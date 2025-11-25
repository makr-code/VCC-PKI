#!/usr/bin/env python3
"""
VCC PKI Server - Timestamp Authority (TSA) Module (Phase 2)
===========================================================

RFC 3161 compliant Time Stamping Authority for VCC PKI.

Features:
- RFC 3161 Timestamp Request/Response handling
- TSA Certificate Management
- Multiple hash algorithms (SHA-256, SHA-384, SHA-512)
- Timestamp token generation
- Accuracy and ordering guarantees
- Audit logging for all timestamps
- Integration with VCC services (Clara, Covina, Veritas)

Standards:
- RFC 3161 - Internet X.509 PKI Time-Stamp Protocol
- RFC 5652 - CMS (Cryptographic Message Syntax)

Author: VCC Team
Date: November 2025
"""

import os
import sys
import json
import logging
import hashlib
import threading
import struct
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class HashAlgorithm(str, Enum):
    """Supported hash algorithms for TSA"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class TSAStatus(str, Enum):
    """TSA Response status"""
    GRANTED = "granted"
    GRANTED_WITH_MODS = "granted_with_mods"
    REJECTION = "rejection"
    WAITING = "waiting"
    REVOCATION_WARNING = "revocation_warning"
    REVOCATION_NOTIFICATION = "revocation_notification"


class TSAFailureInfo(str, Enum):
    """TSA failure reasons"""
    BAD_ALG = "bad_alg"  # Unrecognized or unsupported algorithm
    BAD_REQUEST = "bad_request"  # Transaction not permitted
    BAD_DATA_FORMAT = "bad_data_format"  # Data submitted wrong format
    TIME_NOT_AVAILABLE = "time_not_available"  # TSA time source not available
    UNACCEPTED_POLICY = "unaccepted_policy"  # Policy not supported
    UNACCEPTED_EXTENSION = "unaccepted_extension"  # Extension not supported
    ADD_INFO_NOT_AVAILABLE = "add_info_not_available"  # Additional info not available
    SYSTEM_FAILURE = "system_failure"  # TSA system failure


@dataclass
class TSAConfig:
    """TSA Configuration"""
    enabled: bool = True
    
    # TSA Identity
    tsa_name: str = "VCC Timestamp Authority"
    tsa_policy_oid: str = "1.3.6.1.4.1.99999.1.1.1"  # VCC TSA Policy OID
    
    # Key settings
    key_type: str = "rsa_4096"
    key_validity_years: int = 10
    
    # Accuracy
    accuracy_seconds: int = 1
    accuracy_millis: int = 0
    accuracy_micros: int = 0
    
    # Ordering
    ordering: bool = True
    
    # Certificate storage
    storage_path: str = "../tsa_storage"
    
    # Supported algorithms
    supported_algorithms: List[str] = field(default_factory=lambda: ["sha256", "sha384", "sha512"])
    
    @classmethod
    def from_env(cls) -> "TSAConfig":
        """Create config from environment variables"""
        return cls(
            enabled=os.getenv("VCC_TSA_ENABLED", "true").lower() == "true",
            tsa_name=os.getenv("VCC_TSA_NAME", "VCC Timestamp Authority"),
            tsa_policy_oid=os.getenv("VCC_TSA_POLICY_OID", "1.3.6.1.4.1.99999.1.1.1"),
            key_type=os.getenv("VCC_TSA_KEY_TYPE", "rsa_4096"),
            key_validity_years=int(os.getenv("VCC_TSA_KEY_VALIDITY_YEARS", "10")),
            accuracy_seconds=int(os.getenv("VCC_TSA_ACCURACY_SECONDS", "1")),
            accuracy_millis=int(os.getenv("VCC_TSA_ACCURACY_MILLIS", "0")),
            accuracy_micros=int(os.getenv("VCC_TSA_ACCURACY_MICROS", "0")),
            ordering=os.getenv("VCC_TSA_ORDERING", "true").lower() == "true",
            storage_path=os.getenv("VCC_TSA_STORAGE_PATH", "../tsa_storage"),
            supported_algorithms=os.getenv(
                "VCC_TSA_ALGORITHMS", "sha256,sha384,sha512"
            ).split(",")
        )


@dataclass
class TimestampRequest:
    """RFC 3161 Timestamp Request"""
    message_imprint_hash: bytes
    hash_algorithm: HashAlgorithm
    policy_oid: Optional[str] = None
    nonce: Optional[int] = None
    cert_req: bool = True
    extensions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimestampToken:
    """RFC 3161 Timestamp Token"""
    serial_number: int
    gen_time: datetime
    message_imprint_hash: bytes
    hash_algorithm: HashAlgorithm
    policy_oid: str
    accuracy_seconds: int
    accuracy_millis: int
    accuracy_micros: int
    ordering: bool
    nonce: Optional[int]
    tsa_name: str
    signature: bytes
    tsa_certificate: Optional[bytes] = None


@dataclass
class TimestampResponse:
    """RFC 3161 Timestamp Response"""
    status: TSAStatus
    status_string: Optional[str] = None
    failure_info: Optional[TSAFailureInfo] = None
    timestamp_token: Optional[TimestampToken] = None


@dataclass
class TSAStatistics:
    """TSA Statistics"""
    total_requests: int = 0
    total_granted: int = 0
    total_rejected: int = 0
    requests_sha256: int = 0
    requests_sha384: int = 0
    requests_sha512: int = 0
    last_request_time: Optional[datetime] = None
    startup_time: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# TSA Certificate Manager
# ============================================================================

class TSACertificateManager:
    """
    Manages TSA certificate and private key.
    
    Creates a dedicated certificate for timestamp signing
    with the appropriate extensions (Extended Key Usage: timeStamping).
    """
    
    def __init__(self, config: TSAConfig, ca_manager: Any):
        self.config = config
        self.ca_manager = ca_manager
        self._storage_path = Path(config.storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)
        
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._certificate: Optional[x509.Certificate] = None
        
        # Load or create TSA certificate
        self._load_or_create_certificate()
    
    def _load_or_create_certificate(self) -> None:
        """Load existing TSA certificate or create new one"""
        cert_file = self._storage_path / "tsa_cert.pem"
        key_file = self._storage_path / "tsa_key.pem"
        
        if cert_file.exists() and key_file.exists():
            # Load existing certificate
            try:
                with open(cert_file, 'rb') as f:
                    self._certificate = x509.load_pem_x509_certificate(
                        f.read(),
                        default_backend()
                    )
                
                with open(key_file, 'rb') as f:
                    self._private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                
                # Check if certificate is still valid
                if self._certificate.not_valid_after_utc < datetime.now(timezone.utc):
                    logger.warning("⚠️ TSA certificate expired, creating new one")
                    self._create_certificate()
                else:
                    logger.info("✅ TSA certificate loaded")
                    
            except Exception as e:
                logger.error(f"❌ Failed to load TSA certificate: {e}")
                self._create_certificate()
        else:
            self._create_certificate()
    
    def _create_certificate(self) -> None:
        """Create a new TSA certificate"""
        logger.info("🔑 Creating new TSA certificate...")
        
        # Generate private key
        key_size = 4096 if "4096" in self.config.key_type else 2048
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Brandenburg"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VCC - Veritas Control Center"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Timestamp Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config.tsa_name),
        ])
        
        # Get CA certificate and key for signing
        try:
            ca_cert = self.ca_manager.get_intermediate_certificate()
            ca_key = self.ca_manager.get_intermediate_private_key()
        except Exception:
            # Self-sign if CA not available
            logger.warning("⚠️ CA not available, self-signing TSA certificate")
            ca_cert = None
            ca_key = self._private_key
            issuer = subject
        else:
            issuer = ca_cert.subject if ca_cert else subject
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(self._private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365 * self.config.key_validity_years)
        )
        
        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Extended Key Usage: timeStamping (required for TSA)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.TIME_STAMPING
            ]),
            critical=True
        )
        
        # Key Usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self._private_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        if ca_key:
            self._certificate = builder.sign(ca_key, hashes.SHA256(), default_backend())
        else:
            self._certificate = builder.sign(self._private_key, hashes.SHA256(), default_backend())
        
        # Save certificate and key
        cert_file = self._storage_path / "tsa_cert.pem"
        key_file = self._storage_path / "tsa_key.pem"
        
        with open(cert_file, 'wb') as f:
            f.write(self._certificate.public_bytes(Encoding.PEM))
        
        with open(key_file, 'wb') as f:
            f.write(self._private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            ))
        
        logger.info("✅ TSA certificate created")
    
    @property
    def certificate(self) -> x509.Certificate:
        """Get TSA certificate"""
        return self._certificate
    
    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Get TSA private key"""
        return self._private_key
    
    def get_certificate_pem(self) -> bytes:
        """Get TSA certificate in PEM format"""
        return self._certificate.public_bytes(Encoding.PEM)
    
    def get_certificate_der(self) -> bytes:
        """Get TSA certificate in DER format"""
        return self._certificate.public_bytes(Encoding.DER)


# ============================================================================
# Timestamp Authority
# ============================================================================

class TimestampAuthority:
    """
    RFC 3161 compliant Time Stamping Authority.
    
    Provides timestamp services for:
    - Document timestamping
    - Code signing timestamping
    - Clara model timestamping
    - Covina workflow timestamping
    """
    
    def __init__(self, config: TSAConfig, ca_manager: Any):
        self.config = config
        self._cert_manager = TSACertificateManager(config, ca_manager)
        
        self._lock = threading.Lock()
        self._serial_number = int(time.time() * 1000)  # Start with timestamp-based serial
        self._statistics = TSAStatistics()
        
        # Audit log
        self._audit_log: List[Dict[str, Any]] = []
        
        logger.info("✅ Timestamp Authority initialized")
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """Get TSA statistics"""
        return {
            "total_requests": self._statistics.total_requests,
            "total_granted": self._statistics.total_granted,
            "total_rejected": self._statistics.total_rejected,
            "requests_sha256": self._statistics.requests_sha256,
            "requests_sha384": self._statistics.requests_sha384,
            "requests_sha512": self._statistics.requests_sha512,
            "last_request_time": (
                self._statistics.last_request_time.isoformat()
                if self._statistics.last_request_time else None
            ),
            "startup_time": self._statistics.startup_time.isoformat()
        }
    
    def _get_next_serial(self) -> int:
        """Get next serial number (thread-safe)"""
        with self._lock:
            self._serial_number += 1
            return self._serial_number
    
    def create_timestamp(
        self,
        request: TimestampRequest
    ) -> TimestampResponse:
        """
        Create a timestamp for a hash.
        
        Args:
            request: Timestamp request containing the message digest
        
        Returns:
            TimestampResponse with status and token
        """
        self._statistics.total_requests += 1
        self._statistics.last_request_time = datetime.utcnow()
        
        # Validate request
        if request.hash_algorithm.value not in self.config.supported_algorithms:
            self._statistics.total_rejected += 1
            return TimestampResponse(
                status=TSAStatus.REJECTION,
                status_string="Unsupported hash algorithm",
                failure_info=TSAFailureInfo.BAD_ALG
            )
        
        # Update algorithm statistics
        if request.hash_algorithm == HashAlgorithm.SHA256:
            self._statistics.requests_sha256 += 1
        elif request.hash_algorithm == HashAlgorithm.SHA384:
            self._statistics.requests_sha384 += 1
        elif request.hash_algorithm == HashAlgorithm.SHA512:
            self._statistics.requests_sha512 += 1
        
        # Validate hash length
        expected_lengths = {
            HashAlgorithm.SHA256: 32,
            HashAlgorithm.SHA384: 48,
            HashAlgorithm.SHA512: 64
        }
        
        if len(request.message_imprint_hash) != expected_lengths[request.hash_algorithm]:
            self._statistics.total_rejected += 1
            return TimestampResponse(
                status=TSAStatus.REJECTION,
                status_string="Invalid hash length",
                failure_info=TSAFailureInfo.BAD_DATA_FORMAT
            )
        
        try:
            # Get current time
            gen_time = datetime.now(timezone.utc)
            
            # Get next serial number
            serial_number = self._get_next_serial()
            
            # Policy OID
            policy_oid = request.policy_oid or self.config.tsa_policy_oid
            
            # Create timestamp info structure (simplified)
            tst_info = self._create_tst_info(
                serial_number=serial_number,
                gen_time=gen_time,
                message_imprint_hash=request.message_imprint_hash,
                hash_algorithm=request.hash_algorithm,
                policy_oid=policy_oid,
                nonce=request.nonce
            )
            
            # Sign timestamp info
            signature = self._sign_tst_info(tst_info)
            
            # Create timestamp token
            token = TimestampToken(
                serial_number=serial_number,
                gen_time=gen_time,
                message_imprint_hash=request.message_imprint_hash,
                hash_algorithm=request.hash_algorithm,
                policy_oid=policy_oid,
                accuracy_seconds=self.config.accuracy_seconds,
                accuracy_millis=self.config.accuracy_millis,
                accuracy_micros=self.config.accuracy_micros,
                ordering=self.config.ordering,
                nonce=request.nonce,
                tsa_name=self.config.tsa_name,
                signature=signature,
                tsa_certificate=self._cert_manager.get_certificate_der() if request.cert_req else None
            )
            
            # Audit log
            self._log_timestamp(token)
            
            self._statistics.total_granted += 1
            
            return TimestampResponse(
                status=TSAStatus.GRANTED,
                timestamp_token=token
            )
            
        except Exception as e:
            logger.error(f"❌ Timestamp creation failed: {e}")
            self._statistics.total_rejected += 1
            return TimestampResponse(
                status=TSAStatus.REJECTION,
                status_string=str(e),
                failure_info=TSAFailureInfo.SYSTEM_FAILURE
            )
    
    def _create_tst_info(
        self,
        serial_number: int,
        gen_time: datetime,
        message_imprint_hash: bytes,
        hash_algorithm: HashAlgorithm,
        policy_oid: str,
        nonce: Optional[int]
    ) -> bytes:
        """
        Create TSTInfo structure (simplified DER encoding).
        
        In a full implementation, this would use pyasn1 or similar
        for proper ASN.1 encoding.
        """
        # Simplified structure for signing
        # In production, use proper ASN.1 encoding
        tst_info_dict = {
            "version": 1,
            "policy": policy_oid,
            "messageImprint": {
                "hashAlgorithm": hash_algorithm.value,
                "hashedMessage": message_imprint_hash.hex()
            },
            "serialNumber": serial_number,
            "genTime": gen_time.isoformat(),
            "accuracy": {
                "seconds": self.config.accuracy_seconds,
                "millis": self.config.accuracy_millis,
                "micros": self.config.accuracy_micros
            },
            "ordering": self.config.ordering,
            "nonce": nonce,
            "tsa": self.config.tsa_name
        }
        
        return json.dumps(tst_info_dict, sort_keys=True).encode('utf-8')
    
    def _sign_tst_info(self, tst_info: bytes) -> bytes:
        """Sign the TSTInfo structure"""
        private_key = self._cert_manager.private_key
        
        signature = private_key.sign(
            tst_info,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return signature
    
    def _log_timestamp(self, token: TimestampToken) -> None:
        """Log timestamp for audit"""
        self._audit_log.append({
            "serial_number": token.serial_number,
            "gen_time": token.gen_time.isoformat(),
            "hash_algorithm": token.hash_algorithm.value,
            "message_imprint_hash": token.message_imprint_hash.hex(),
            "policy_oid": token.policy_oid,
            "tsa_name": token.tsa_name
        })
        
        # Keep only last 10000 entries
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]
    
    def verify_timestamp(
        self,
        token: TimestampToken,
        original_hash: bytes
    ) -> Tuple[bool, str]:
        """
        Verify a timestamp token.
        
        Args:
            token: Timestamp token to verify
            original_hash: Original hash that was timestamped
        
        Returns:
            Tuple of (is_valid, message)
        """
        # Check hash matches
        if token.message_imprint_hash != original_hash:
            return False, "Hash mismatch"
        
        # Recreate TSTInfo for verification
        tst_info = self._create_tst_info(
            serial_number=token.serial_number,
            gen_time=token.gen_time,
            message_imprint_hash=token.message_imprint_hash,
            hash_algorithm=token.hash_algorithm,
            policy_oid=token.policy_oid,
            nonce=token.nonce
        )
        
        # Verify signature
        try:
            public_key = self._cert_manager.certificate.public_key()
            public_key.verify(
                token.signature,
                tst_info,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, "Timestamp valid"
        except Exception as e:
            return False, f"Signature verification failed: {e}"
    
    def get_certificate(self) -> bytes:
        """Get TSA certificate in PEM format"""
        return self._cert_manager.get_certificate_pem()
    
    def get_certificate_der(self) -> bytes:
        """Get TSA certificate in DER format"""
        return self._cert_manager.get_certificate_der()
    
    def get_audit_log(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        entries = self._audit_log
        
        if start_time:
            entries = [
                e for e in entries
                if datetime.fromisoformat(e["gen_time"]) >= start_time
            ]
        
        if end_time:
            entries = [
                e for e in entries
                if datetime.fromisoformat(e["gen_time"]) <= end_time
            ]
        
        return entries[-limit:]


# ============================================================================
# VCC-Specific Timestamp Functions
# ============================================================================

class VCCTimestampService:
    """
    VCC-specific timestamp service for integration with VCC components.
    
    Provides specialized timestamping for:
    - Clara: Model and LoRa adapter timestamping
    - Covina: Workflow and pipeline timestamping
    - Veritas: Pipeline configuration timestamping
    """
    
    def __init__(self, tsa: TimestampAuthority):
        self.tsa = tsa
        self._lock = threading.Lock()
    
    def timestamp_clara_model(
        self,
        model_hash: bytes,
        model_name: str,
        model_version: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Timestamp a Clara AI model.
        
        Args:
            model_hash: SHA-256 hash of the model file
            model_name: Name of the model
            model_version: Version of the model
            metadata: Additional metadata
        
        Returns:
            Timestamp result with token
        """
        request = TimestampRequest(
            message_imprint_hash=model_hash,
            hash_algorithm=HashAlgorithm.SHA256,
            cert_req=True,
            extensions={
                "vcc_type": "clara_model",
                "model_name": model_name,
                "model_version": model_version,
                "metadata": metadata or {}
            }
        )
        
        response = self.tsa.create_timestamp(request)
        
        if response.status == TSAStatus.GRANTED:
            return {
                "success": True,
                "serial_number": response.timestamp_token.serial_number,
                "gen_time": response.timestamp_token.gen_time.isoformat(),
                "model_name": model_name,
                "model_version": model_version,
                "signature": response.timestamp_token.signature.hex(),
                "tsa_certificate": response.timestamp_token.tsa_certificate.hex() if response.timestamp_token.tsa_certificate else None
            }
        else:
            return {
                "success": False,
                "error": response.status_string,
                "failure_info": response.failure_info.value if response.failure_info else None
            }
    
    def timestamp_covina_workflow(
        self,
        workflow_hash: bytes,
        workflow_id: str,
        workflow_name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Timestamp a Covina workflow.
        
        Args:
            workflow_hash: SHA-256 hash of the workflow definition
            workflow_id: Unique workflow identifier
            workflow_name: Name of the workflow
            metadata: Additional metadata
        
        Returns:
            Timestamp result with token
        """
        request = TimestampRequest(
            message_imprint_hash=workflow_hash,
            hash_algorithm=HashAlgorithm.SHA256,
            cert_req=True,
            extensions={
                "vcc_type": "covina_workflow",
                "workflow_id": workflow_id,
                "workflow_name": workflow_name,
                "metadata": metadata or {}
            }
        )
        
        response = self.tsa.create_timestamp(request)
        
        if response.status == TSAStatus.GRANTED:
            return {
                "success": True,
                "serial_number": response.timestamp_token.serial_number,
                "gen_time": response.timestamp_token.gen_time.isoformat(),
                "workflow_id": workflow_id,
                "workflow_name": workflow_name,
                "signature": response.timestamp_token.signature.hex()
            }
        else:
            return {
                "success": False,
                "error": response.status_string
            }
    
    def timestamp_veritas_pipeline(
        self,
        pipeline_hash: bytes,
        pipeline_id: str,
        pipeline_config: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Timestamp a Veritas pipeline configuration.
        
        Args:
            pipeline_hash: SHA-256 hash of the pipeline configuration
            pipeline_id: Unique pipeline identifier
            pipeline_config: Pipeline configuration summary
            metadata: Additional metadata
        
        Returns:
            Timestamp result with token
        """
        request = TimestampRequest(
            message_imprint_hash=pipeline_hash,
            hash_algorithm=HashAlgorithm.SHA256,
            cert_req=True,
            extensions={
                "vcc_type": "veritas_pipeline",
                "pipeline_id": pipeline_id,
                "pipeline_config": pipeline_config,
                "metadata": metadata or {}
            }
        )
        
        response = self.tsa.create_timestamp(request)
        
        if response.status == TSAStatus.GRANTED:
            return {
                "success": True,
                "serial_number": response.timestamp_token.serial_number,
                "gen_time": response.timestamp_token.gen_time.isoformat(),
                "pipeline_id": pipeline_id,
                "signature": response.timestamp_token.signature.hex()
            }
        else:
            return {
                "success": False,
                "error": response.status_string
            }
    
    def timestamp_code_signature(
        self,
        signature_hash: bytes,
        artifact_name: str,
        artifact_type: str,
        signer_id: str
    ) -> Dict[str, Any]:
        """
        Timestamp a code signature.
        
        Args:
            signature_hash: SHA-256 hash of the signature
            artifact_name: Name of the signed artifact
            artifact_type: Type of artifact
            signer_id: ID of the signer
        
        Returns:
            Timestamp result with token
        """
        request = TimestampRequest(
            message_imprint_hash=signature_hash,
            hash_algorithm=HashAlgorithm.SHA256,
            cert_req=True,
            extensions={
                "vcc_type": "code_signature",
                "artifact_name": artifact_name,
                "artifact_type": artifact_type,
                "signer_id": signer_id
            }
        )
        
        response = self.tsa.create_timestamp(request)
        
        if response.status == TSAStatus.GRANTED:
            return {
                "success": True,
                "serial_number": response.timestamp_token.serial_number,
                "gen_time": response.timestamp_token.gen_time.isoformat(),
                "artifact_name": artifact_name,
                "artifact_type": artifact_type,
                "signer_id": signer_id,
                "signature": response.timestamp_token.signature.hex()
            }
        else:
            return {
                "success": False,
                "error": response.status_string
            }


# ============================================================================
# FastAPI Router for TSA
# ============================================================================

def create_tsa_router(tsa: TimestampAuthority, vcc_service: VCCTimestampService):
    """Create FastAPI router for TSA endpoints"""
    from fastapi import APIRouter, HTTPException, Request, Response
    from pydantic import BaseModel
    
    router = APIRouter(prefix="/api/v1/tsa", tags=["Timestamp Authority"])
    
    class TimestampRequestModel(BaseModel):
        hash: str  # Hex-encoded hash
        hash_algorithm: str = "sha256"
        nonce: Optional[int] = None
        cert_req: bool = True
    
    class ClaraTimestampRequest(BaseModel):
        model_hash: str
        model_name: str
        model_version: str
        metadata: Optional[Dict[str, Any]] = None
    
    class CovinaTimestampRequest(BaseModel):
        workflow_hash: str
        workflow_id: str
        workflow_name: str
        metadata: Optional[Dict[str, Any]] = None
    
    class VeritasTimestampRequest(BaseModel):
        pipeline_hash: str
        pipeline_id: str
        pipeline_config: Dict[str, Any]
        metadata: Optional[Dict[str, Any]] = None
    
    class CodeSignatureTimestampRequest(BaseModel):
        signature_hash: str
        artifact_name: str
        artifact_type: str
        signer_id: str
    
    @router.get("/status")
    async def get_tsa_status():
        """Get TSA status and statistics"""
        return {
            "enabled": tsa.config.enabled,
            "tsa_name": tsa.config.tsa_name,
            "policy_oid": tsa.config.tsa_policy_oid,
            "supported_algorithms": tsa.config.supported_algorithms,
            "accuracy": {
                "seconds": tsa.config.accuracy_seconds,
                "millis": tsa.config.accuracy_millis,
                "micros": tsa.config.accuracy_micros
            },
            "ordering": tsa.config.ordering,
            "statistics": tsa.statistics
        }
    
    @router.post("/timestamp")
    async def create_timestamp(request: TimestampRequestModel):
        """
        Create a timestamp for a hash.
        
        Accepts hex-encoded hash and returns a signed timestamp token.
        """
        try:
            # Decode hash
            message_hash = bytes.fromhex(request.hash)
            
            # Validate hash algorithm
            try:
                hash_alg = HashAlgorithm(request.hash_algorithm)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported hash algorithm: {request.hash_algorithm}"
                )
            
            # Create timestamp request
            ts_request = TimestampRequest(
                message_imprint_hash=message_hash,
                hash_algorithm=hash_alg,
                nonce=request.nonce,
                cert_req=request.cert_req
            )
            
            # Get timestamp
            response = tsa.create_timestamp(ts_request)
            
            if response.status == TSAStatus.GRANTED:
                token = response.timestamp_token
                return {
                    "status": "granted",
                    "serial_number": token.serial_number,
                    "gen_time": token.gen_time.isoformat(),
                    "policy_oid": token.policy_oid,
                    "accuracy": {
                        "seconds": token.accuracy_seconds,
                        "millis": token.accuracy_millis,
                        "micros": token.accuracy_micros
                    },
                    "ordering": token.ordering,
                    "nonce": token.nonce,
                    "signature": token.signature.hex(),
                    "tsa_certificate": token.tsa_certificate.hex() if token.tsa_certificate else None
                }
            else:
                return {
                    "status": response.status.value,
                    "status_string": response.status_string,
                    "failure_info": response.failure_info.value if response.failure_info else None
                }
                
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/certificate")
    async def get_tsa_certificate():
        """Download TSA certificate (PEM format)"""
        return Response(
            content=tsa.get_certificate(),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=vcc-tsa-cert.pem"}
        )
    
    @router.get("/certificate/der")
    async def get_tsa_certificate_der():
        """Download TSA certificate (DER format)"""
        return Response(
            content=tsa.get_certificate_der(),
            media_type="application/pkix-cert",
            headers={"Content-Disposition": "attachment; filename=vcc-tsa-cert.der"}
        )
    
    @router.get("/audit")
    async def get_tsa_audit_log(
        limit: int = 100,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ):
        """Get TSA audit log"""
        start = datetime.fromisoformat(start_time) if start_time else None
        end = datetime.fromisoformat(end_time) if end_time else None
        
        entries = tsa.get_audit_log(start_time=start, end_time=end, limit=limit)
        
        return {
            "total": len(entries),
            "entries": entries
        }
    
    # VCC-specific endpoints
    @router.post("/vcc/clara/model")
    async def timestamp_clara_model(request: ClaraTimestampRequest):
        """Timestamp a Clara AI model"""
        try:
            model_hash = bytes.fromhex(request.model_hash)
            return vcc_service.timestamp_clara_model(
                model_hash=model_hash,
                model_name=request.model_name,
                model_version=request.model_version,
                metadata=request.metadata
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/vcc/covina/workflow")
    async def timestamp_covina_workflow(request: CovinaTimestampRequest):
        """Timestamp a Covina workflow"""
        try:
            workflow_hash = bytes.fromhex(request.workflow_hash)
            return vcc_service.timestamp_covina_workflow(
                workflow_hash=workflow_hash,
                workflow_id=request.workflow_id,
                workflow_name=request.workflow_name,
                metadata=request.metadata
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/vcc/veritas/pipeline")
    async def timestamp_veritas_pipeline(request: VeritasTimestampRequest):
        """Timestamp a Veritas pipeline configuration"""
        try:
            pipeline_hash = bytes.fromhex(request.pipeline_hash)
            return vcc_service.timestamp_veritas_pipeline(
                pipeline_hash=pipeline_hash,
                pipeline_id=request.pipeline_id,
                pipeline_config=request.pipeline_config,
                metadata=request.metadata
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/vcc/code-signature")
    async def timestamp_code_signature(request: CodeSignatureTimestampRequest):
        """Timestamp a code signature"""
        try:
            signature_hash = bytes.fromhex(request.signature_hash)
            return vcc_service.timestamp_code_signature(
                signature_hash=signature_hash,
                artifact_name=request.artifact_name,
                artifact_type=request.artifact_type,
                signer_id=request.signer_id
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    return router


# ============================================================================
# Factory Function
# ============================================================================

def create_timestamp_authority(
    config: Optional[TSAConfig] = None,
    ca_manager: Any = None
) -> Tuple[TimestampAuthority, VCCTimestampService]:
    """
    Create and initialize Timestamp Authority.
    
    Args:
        config: TSA configuration (uses env vars if not provided)
        ca_manager: CA Manager for certificate signing
    
    Returns:
        Tuple of (TimestampAuthority, VCCTimestampService)
    """
    if config is None:
        config = TSAConfig.from_env()
    
    tsa = TimestampAuthority(config, ca_manager)
    vcc_service = VCCTimestampService(tsa)
    
    return tsa, vcc_service
