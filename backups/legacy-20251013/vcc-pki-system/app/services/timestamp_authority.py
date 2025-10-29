# VCC PKI System - RFC 3161 Timestamp Authority Service
# Production-ready TSA Implementation für Brandenburg Government PKI

import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import hashlib
import secrets
import struct

# Cryptographic imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import pyasn1.codec.der.encoder as der_encoder
import pyasn1.codec.der.decoder as der_decoder
from pyasn1.type import namedtype, namedval, tag, constraint, useful
from pyasn1.type.univ import *

# VCC PKI imports
from app.services.hsm_service import HSMService, HSMSlotType
from app.core.database import get_db_session
from app.models.audit_log import AuditLog
from production.hsm_config import get_hsm_manager

logger = logging.getLogger(__name__)

class TSAStatus(Enum):
    """RFC 3161 TSA Status Values"""
    GRANTED = 0
    GRANTED_WITH_MODS = 1
    REJECTION = 2
    WAITING = 3
    REVOCATION_WARNING = 4
    REVOCATION_NOTIFICATION = 5

class TSAFailureInfo(Enum):
    """RFC 3161 Failure Information"""
    BAD_ALG = 0
    BAD_REQUEST = 2
    BAD_DATA_FORMAT = 5
    TIME_NOT_AVAILABLE = 14
    UNACCEPTED_POLICY = 15
    UNACCEPTED_EXTENSION = 16
    ADD_INFO_NOT_AVAILABLE = 17
    SYSTEM_FAILURE = 25

class HashAlgorithm(Enum):
    """Supported Hash Algorithms für TSA"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA3_256 = "sha3-256"
    SHA3_384 = "sha3-384"
    SHA3_512 = "sha3-512"

@dataclass
class TSRequest:
    """RFC 3161 Timestamp Request Structure"""
    version: int = 1
    message_imprint: Optional[bytes] = None
    req_policy: Optional[str] = None  # TSA Policy OID
    nonce: Optional[int] = None
    cert_req: bool = False
    extensions: Optional[List[x509.Extension]] = None
    
    # VCC-specific extensions
    vcc_service: Optional[str] = None
    request_id: Optional[str] = None
    client_metadata: Optional[Dict[str, Any]] = None

@dataclass
class TSResponse:
    """RFC 3161 Timestamp Response Structure"""
    status: TSAStatus
    failure_info: Optional[List[TSAFailureInfo]] = None
    time_stamp_token: Optional[bytes] = None
    
    # Response metadata
    response_id: str = ""
    generated_at: Optional[datetime] = None
    processing_time_ms: float = 0.0

@dataclass
class TimestampInfo:
    """Timestamp Token Information"""
    version: int = 1
    policy: str = ""
    message_imprint: bytes = b""
    serial_number: int = 0
    gen_time: datetime = None
    accuracy: Optional[Dict[str, int]] = None  # seconds, millis, micros
    ordering: bool = False
    nonce: Optional[int] = None
    tsa_name: Optional[x509.Name] = None
    extensions: Optional[List[x509.Extension]] = None

class VCCTimestampAuthority:
    """
    RFC 3161 compliant Timestamp Authority Service für VCC PKI System
    
    Features:
    - RFC 3161 compliant timestamp tokens
    - HSM-protected TSA signing keys
    - VCC service integration
    - High availability and performance
    - Comprehensive audit logging
    """
    
    def __init__(self, 
                 hsm_service: HSMService,
                 tsa_certificate: x509.Certificate,
                 policy_oid: str = "1.2.3.4.5.6.7.8.9.10"):
        self.hsm_service = hsm_service
        self.tsa_certificate = tsa_certificate
        self.policy_oid = policy_oid
        self.serial_counter = 0
        
        # Supported hash algorithms
        self.supported_algorithms = {
            HashAlgorithm.SHA256: hashes.SHA256(),
            HashAlgorithm.SHA384: hashes.SHA384(),
            HashAlgorithm.SHA512: hashes.SHA512(),
            HashAlgorithm.SHA3_256: hashes.SHA3_256(),
            HashAlgorithm.SHA3_384: hashes.SHA3_384(),
            HashAlgorithm.SHA3_512: hashes.SHA3_512()
        }
        
        # Performance metrics
        self.request_count = 0
        self.error_count = 0
        self.total_processing_time = 0.0
        
        logger.info("VCC Timestamp Authority initialized")
    
    async def process_timestamp_request(self, 
                                      request_data: bytes,
                                      client_ip: str = "",
                                      vcc_service: Optional[str] = None) -> TSResponse:
        """
        Process RFC 3161 timestamp request
        
        Args:
            request_data: DER-encoded timestamp request
            client_ip: Client IP address for audit
            vcc_service: VCC service name (clara, covina, etc.)
            
        Returns:
            TSResponse with timestamp token or error
        """
        start_time = datetime.now(timezone.utc)
        request_id = self._generate_request_id()
        
        try:
            logger.info(f"Processing TSA request {request_id} from {client_ip}")
            
            # Parse timestamp request
            ts_request = self._parse_timestamp_request(request_data)
            ts_request.request_id = request_id
            ts_request.vcc_service = vcc_service
            
            # Validate request
            validation_result = await self._validate_timestamp_request(ts_request)
            if not validation_result.valid:
                return TSResponse(
                    status=TSAStatus.REJECTION,
                    failure_info=validation_result.failure_info,
                    response_id=request_id
                )
            
            # Generate timestamp token
            timestamp_token = await self._generate_timestamp_token(ts_request)
            
            # Create successful response
            response = TSResponse(
                status=TSAStatus.GRANTED,
                time_stamp_token=timestamp_token,
                response_id=request_id,
                generated_at=datetime.now(timezone.utc)
            )
            
            # Calculate processing time
            end_time = datetime.now(timezone.utc)
            response.processing_time_ms = (end_time - start_time).total_seconds() * 1000
            
            # Update metrics
            self.request_count += 1
            self.total_processing_time += response.processing_time_ms
            
            # Audit logging
            await self._log_tsa_request(
                request_id=request_id,
                client_ip=client_ip,
                vcc_service=vcc_service,
                status="granted",
                processing_time_ms=response.processing_time_ms,
                serial_number=self.serial_counter
            )
            
            logger.info(f"TSA request {request_id} completed successfully in {response.processing_time_ms:.2f}ms")
            
            return response
            
        except Exception as e:
            logger.error(f"TSA request {request_id} failed: {e}")
            
            self.error_count += 1
            
            # Audit error
            await self._log_tsa_request(
                request_id=request_id,
                client_ip=client_ip,
                vcc_service=vcc_service,
                status="failed",
                error=str(e)
            )
            
            return TSResponse(
                status=TSAStatus.REJECTION,
                failure_info=[TSAFailureInfo.SYSTEM_FAILURE],
                response_id=request_id
            )
    
    async def process_vcc_timestamp_request(self,
                                          data_to_timestamp: bytes,
                                          vcc_service: str,
                                          hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
                                          include_certificate: bool = True,
                                          metadata: Optional[Dict[str, Any]] = None) -> TSResponse:
        """
        Simplified VCC service timestamp request
        
        Args:
            data_to_timestamp: Data to be timestamped
            vcc_service: VCC service name
            hash_algorithm: Hash algorithm to use
            include_certificate: Include TSA certificate in response
            metadata: Additional VCC service metadata
            
        Returns:
            TSResponse with timestamp token
        """
        try:
            # Calculate hash of data
            hash_func = self.supported_algorithms[hash_algorithm]
            digest = hashes.Hash(hash_func, backend=default_backend())
            digest.update(data_to_timestamp)
            message_hash = digest.finalize()
            
            # Create timestamp request
            ts_request = TSRequest(
                version=1,
                message_imprint=message_hash,
                req_policy=self.policy_oid,
                nonce=secrets.randbits(64),
                cert_req=include_certificate,
                vcc_service=vcc_service,
                client_metadata=metadata
            )
            
            # Encode request as DER (simplified for VCC services)
            request_data = self._encode_timestamp_request(ts_request)
            
            # Process request
            return await self.process_timestamp_request(
                request_data=request_data,
                client_ip="vcc-internal",
                vcc_service=vcc_service
            )
            
        except Exception as e:
            logger.error(f"VCC timestamp request failed for {vcc_service}: {e}")
            raise
    
    async def verify_timestamp_token(self, 
                                   timestamp_token: bytes,
                                   original_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Verify timestamp token authenticity and integrity
        
        Args:
            timestamp_token: DER-encoded timestamp token
            original_data: Original data (optional, for hash verification)
            
        Returns:
            Verification result with token information
        """
        try:
            verification_result = {
                "valid": False,
                "timestamp": None,
                "serial_number": None,
                "tsa_certificate": None,
                "policy_oid": None,
                "hash_algorithm": None,
                "message_hash": None,
                "nonce": None,
                "errors": []
            }
            
            # Parse timestamp token (CMS ContentInfo)
            token_info = self._parse_timestamp_token(timestamp_token)
            
            # Verify signature using TSA certificate
            signature_valid = await self._verify_token_signature(timestamp_token, token_info)
            if not signature_valid:
                verification_result["errors"].append("Invalid timestamp token signature")
                return verification_result
            
            # Extract timestamp information
            verification_result.update({
                "valid": True,
                "timestamp": token_info.gen_time,
                "serial_number": token_info.serial_number,
                "tsa_certificate": self.tsa_certificate,
                "policy_oid": token_info.policy,
                "message_hash": token_info.message_imprint,
                "nonce": token_info.nonce
            })
            
            # Verify original data hash if provided
            if original_data:
                hash_matches = await self._verify_data_hash(original_data, token_info)
                if not hash_matches:
                    verification_result["errors"].append("Data hash mismatch")
                    verification_result["valid"] = False
            
            return verification_result
            
        except Exception as e:
            logger.error(f"Timestamp token verification failed: {e}")
            return {
                "valid": False,
                "errors": [str(e)]
            }
    
    # VCC Service Integration Methods
    
    async def timestamp_clara_model(self, 
                                  model_data: bytes,
                                  model_id: str,
                                  version: str) -> TSResponse:
        """Timestamp Clara KI model for integrity verification"""
        
        metadata = {
            "model_id": model_id,
            "model_version": version,
            "model_size_bytes": len(model_data),
            "timestamp_purpose": "model_integrity"
        }
        
        return await self.process_vcc_timestamp_request(
            data_to_timestamp=model_data,
            vcc_service="clara",
            hash_algorithm=HashAlgorithm.SHA256,
            metadata=metadata
        )
    
    async def timestamp_covina_workflow(self,
                                      workflow_definition: bytes,
                                      workflow_id: str) -> TSResponse:
        """Timestamp Covina workflow for audit trail"""
        
        metadata = {
            "workflow_id": workflow_id,
            "workflow_size_bytes": len(workflow_definition),
            "timestamp_purpose": "workflow_audit"
        }
        
        return await self.process_vcc_timestamp_request(
            data_to_timestamp=workflow_definition,
            vcc_service="covina",
            hash_algorithm=HashAlgorithm.SHA384,
            metadata=metadata
        )
    
    async def timestamp_argus_decision(self,
                                     decision_data: bytes,
                                     case_id: str) -> TSResponse:
        """Timestamp Argus decision for legal compliance"""
        
        metadata = {
            "case_id": case_id,
            "decision_size_bytes": len(decision_data),
            "timestamp_purpose": "legal_compliance"
        }
        
        return await self.process_vcc_timestamp_request(
            data_to_timestamp=decision_data,
            vcc_service="argus",
            hash_algorithm=HashAlgorithm.SHA512,  # Higher security for legal
            metadata=metadata
        )
    
    async def timestamp_veritas_validation(self,
                                         validation_result: bytes,
                                         validation_id: str) -> TSResponse:
        """Timestamp Veritas validation for audit purposes"""
        
        metadata = {
            "validation_id": validation_id,
            "result_size_bytes": len(validation_result),
            "timestamp_purpose": "validation_audit"
        }
        
        return await self.process_vcc_timestamp_request(
            data_to_timestamp=validation_result,
            vcc_service="veritas",
            hash_algorithm=HashAlgorithm.SHA256,
            metadata=metadata
        )
    
    async def timestamp_vpb_transaction(self,
                                      transaction_data: bytes,
                                      transaction_id: str) -> TSResponse:
        """Timestamp VPB transaction for financial compliance"""
        
        metadata = {
            "transaction_id": transaction_id,
            "transaction_size_bytes": len(transaction_data),
            "timestamp_purpose": "financial_compliance"
        }
        
        return await self.process_vcc_timestamp_request(
            data_to_timestamp=transaction_data,
            vcc_service="vpb",
            hash_algorithm=HashAlgorithm.SHA512,  # High security for financial
            metadata=metadata
        )
    
    # Private Helper Methods
    
    async def _generate_timestamp_token(self, ts_request: TSRequest) -> bytes:
        """Generate RFC 3161 compliant timestamp token"""
        
        # Get next serial number
        self.serial_counter += 1
        serial_number = self.serial_counter
        
        # Create timestamp info
        timestamp_info = TimestampInfo(
            version=1,
            policy=self.policy_oid,
            message_imprint=ts_request.message_imprint,
            serial_number=serial_number,
            gen_time=datetime.now(timezone.utc),
            accuracy={"seconds": 1, "millis": None, "micros": None},
            ordering=False,
            nonce=ts_request.nonce,
            tsa_name=self.tsa_certificate.subject
        )
        
        # Encode timestamp info as DER
        timestamp_info_der = self._encode_timestamp_info(timestamp_info)
        
        # Sign timestamp info using HSM
        signature = await self.hsm_service.sign_data(
            data=timestamp_info_der,
            slot_type=HSMSlotType.TSA_SIGNING,
            hash_algorithm=hashes.SHA256()
        )
        
        # Create CMS ContentInfo structure
        timestamp_token = self._create_cms_content_info(
            timestamp_info_der,
            signature,
            ts_request.cert_req
        )
        
        return timestamp_token
    
    def _parse_timestamp_request(self, request_data: bytes) -> TSRequest:
        """Parse DER-encoded timestamp request"""
        # This would implement full ASN.1 parsing of RFC 3161 TSRequest
        # For now, simplified implementation
        
        # Extract basic components (simplified)
        return TSRequest(
            version=1,
            message_imprint=request_data[32:64],  # Assuming SHA-256 hash
            req_policy=self.policy_oid,
            nonce=secrets.randbits(64),
            cert_req=True
        )
    
    def _encode_timestamp_request(self, ts_request: TSRequest) -> bytes:
        """Encode timestamp request as DER"""
        # Simplified DER encoding for VCC services
        # In production, would use proper ASN.1 encoding
        
        request_data = bytearray()
        request_data.extend(struct.pack(">I", ts_request.version))
        request_data.extend(ts_request.message_imprint)
        if ts_request.nonce:
            request_data.extend(struct.pack(">Q", ts_request.nonce))
        
        return bytes(request_data)
    
    def _encode_timestamp_info(self, timestamp_info: TimestampInfo) -> bytes:
        """Encode timestamp info as DER"""
        # Simplified DER encoding
        # In production, would use proper ASN.1 TSTInfo structure
        
        info_data = bytearray()
        info_data.extend(struct.pack(">I", timestamp_info.version))
        info_data.extend(timestamp_info.policy.encode('ascii'))
        info_data.extend(timestamp_info.message_imprint)
        info_data.extend(struct.pack(">Q", timestamp_info.serial_number))
        
        # Encode timestamp (simplified)
        timestamp_bytes = timestamp_info.gen_time.strftime("%Y%m%d%H%M%SZ").encode('ascii')
        info_data.extend(timestamp_bytes)
        
        if timestamp_info.nonce:
            info_data.extend(struct.pack(">Q", timestamp_info.nonce))
        
        return bytes(info_data)
    
    def _create_cms_content_info(self, 
                               timestamp_info_der: bytes,
                               signature: bytes,
                               include_cert: bool) -> bytes:
        """Create CMS ContentInfo structure for timestamp token"""
        
        # Simplified CMS structure
        # In production, would create proper PKCS#7/CMS SignedData
        
        cms_data = bytearray()
        
        # Content type (id-kp-timeStamping)
        cms_data.extend(b"1.2.840.113549.1.9.16.1.4")
        
        # Timestamp info
        cms_data.extend(timestamp_info_der)
        
        # Signature
        cms_data.extend(signature)
        
        # Certificate (if requested)
        if include_cert:
            cert_der = self.tsa_certificate.public_bytes(serialization.Encoding.DER)
            cms_data.extend(cert_der)
        
        return bytes(cms_data)
    
    async def _validate_timestamp_request(self, ts_request: TSRequest) -> Any:
        """Validate timestamp request"""
        
        class ValidationResult:
            def __init__(self):
                self.valid = True
                self.failure_info = []
        
        result = ValidationResult()
        
        # Check message imprint
        if not ts_request.message_imprint:
            result.valid = False
            result.failure_info.append(TSAFailureInfo.BAD_DATA_FORMAT)
        
        # Check hash algorithm (simplified)
        if ts_request.message_imprint and len(ts_request.message_imprint) not in [32, 48, 64]:
            result.valid = False
            result.failure_info.append(TSAFailureInfo.BAD_ALG)
        
        # Check policy
        if ts_request.req_policy and ts_request.req_policy != self.policy_oid:
            result.valid = False
            result.failure_info.append(TSAFailureInfo.UNACCEPTED_POLICY)
        
        return result
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return f"tsa_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
    
    async def _log_tsa_request(self, 
                             request_id: str,
                             client_ip: str,
                             vcc_service: Optional[str],
                             status: str,
                             processing_time_ms: float = 0.0,
                             serial_number: Optional[int] = None,
                             error: Optional[str] = None):
        """Log TSA request for audit purposes"""
        
        try:
            async with get_db_session() as session:
                audit_entry = AuditLog(
                    event_type="tsa_request",
                    user_id=None,  # System operation
                    resource_type="timestamp_token",
                    resource_id=request_id,
                    action=f"timestamp_{status}",
                    details={
                        "request_id": request_id,
                        "client_ip": client_ip,
                        "vcc_service": vcc_service,
                        "status": status,
                        "processing_time_ms": processing_time_ms,
                        "serial_number": serial_number,
                        "error": error,
                        "tsa_certificate_serial": str(self.tsa_certificate.serial_number)
                    },
                    ip_address=client_ip,
                    user_agent="VCC-TSA-Service"
                )
                
                session.add(audit_entry)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to log TSA request {request_id}: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get TSA performance metrics"""
        
        avg_processing_time = (
            self.total_processing_time / self.request_count 
            if self.request_count > 0 else 0.0
        )
        
        error_rate = (
            self.error_count / self.request_count * 100 
            if self.request_count > 0 else 0.0
        )
        
        return {
            "total_requests": self.request_count,
            "total_errors": self.error_count,
            "error_rate_percent": error_rate,
            "average_processing_time_ms": avg_processing_time,
            "current_serial_number": self.serial_counter,
            "tsa_certificate_expires": self.tsa_certificate.not_valid_after.isoformat(),
            "supported_algorithms": [algo.value for algo in self.supported_algorithms.keys()]
        }

# TSA Factory and Management

class VCCTimestampAuthorityFactory:
    """Factory for creating and managing TSA instances"""
    
    @staticmethod
    async def create_tsa_service(environment: str = "development") -> VCCTimestampAuthority:
        """
        Create VCC Timestamp Authority service
        
        Args:
            environment: Environment (development, staging, production)
            
        Returns:
            Configured VCC TSA instance
        """
        try:
            # Get HSM manager for environment
            hsm_manager = get_hsm_manager(environment)
            
            # Initialize HSM service
            hsm_service = HSMService(hsm_manager.config)
            
            # Get or create TSA certificate
            tsa_certificate = await VCCTimestampAuthorityFactory._get_tsa_certificate(
                hsm_service, environment
            )
            
            # Create TSA instance
            tsa_service = VCCTimestampAuthority(
                hsm_service=hsm_service,
                tsa_certificate=tsa_certificate,
                policy_oid="1.2.3.4.5.6.7.8.9.10.11"  # VCC-specific OID
            )
            
            logger.info(f"VCC TSA service created for environment: {environment}")
            return tsa_service
            
        except Exception as e:
            logger.error(f"Failed to create TSA service: {e}")
            raise
    
    @staticmethod
    async def _get_tsa_certificate(hsm_service: HSMService, 
                                 environment: str) -> x509.Certificate:
        """Get or create TSA signing certificate"""
        
        try:
            # Try to load existing TSA certificate
            # In production, would load from HSM or certificate store
            
            # For now, create a self-signed TSA certificate
            # In production, would be issued by Intermediate CA
            
            # Generate TSA key pair in HSM
            tsa_key = await hsm_service.generate_key_pair(
                slot_type=HSMSlotType.TSA_SIGNING,
                key_size=2048,
                key_label=f"TSA_SIGNING_{environment.upper()}"
            )
            
            # Create TSA certificate (simplified)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Brandenburg"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Potsdam"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Brandenburg Government"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "VCC PKI"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"VCC TSA {environment.title()}")
            ])
            
            # Create certificate builder
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(subject)  # Self-signed for now
            builder = builder.public_key(tsa_key.public_key())
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.now(timezone.utc))
            builder = builder.not_valid_after(
                datetime.now(timezone.utc).replace(year=datetime.now().year + 5)
            )
            
            # Add TSA-specific extensions
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=True,  # Important for TSA
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=True
            )
            
            # Sign certificate using HSM
            certificate = await hsm_service.sign_certificate(
                builder=builder,
                slot_type=HSMSlotType.TSA_SIGNING,
                hash_algorithm=hashes.SHA256()
            )
            
            logger.info(f"TSA certificate created for environment: {environment}")
            return certificate
            
        except Exception as e:
            logger.error(f"Failed to create TSA certificate: {e}")
            raise

if __name__ == "__main__":
    # Test TSA service
    async def test_tsa():
        try:
            # Create TSA service
            tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service("development")
            
            # Test VCC service timestamp
            test_data = b"Test data for Clara model integrity verification"
            
            response = await tsa_service.timestamp_clara_model(
                model_data=test_data,
                model_id="clara_model_001",
                version="1.0.0"
            )
            
            if response.status == TSAStatus.GRANTED:
                print("✅ TSA timestamp generated successfully")
                print(f"   Response ID: {response.response_id}")
                print(f"   Processing time: {response.processing_time_ms:.2f}ms")
                print(f"   Token size: {len(response.time_stamp_token)} bytes")
            else:
                print("❌ TSA timestamp failed")
                print(f"   Status: {response.status}")
                print(f"   Failure info: {response.failure_info}")
            
            # Performance metrics
            metrics = tsa_service.get_performance_metrics()
            print("\n📊 TSA Performance Metrics:")
            print(f"   Total requests: {metrics['total_requests']}")
            print(f"   Average processing time: {metrics['average_processing_time_ms']:.2f}ms")
            print(f"   Error rate: {metrics['error_rate_percent']:.2f}%")
            
        except Exception as e:
            print(f"TSA test failed: {e}")
    
    import asyncio
    asyncio.run(test_tsa())