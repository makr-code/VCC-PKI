#!/usr/bin/env python3
"""
VCC PKI Server - OCSP Responder
================================

RFC 6960 compliant Online Certificate Status Protocol (OCSP) responder
implementing Phase 1 of the VCC-PKI development strategy.

Features:
- RFC 6960 OCSP request/response handling
- Response signature generation
- Caching for performance optimization
- Integration with certificate database
- Support for OCSP stapling

This component runs ON-PREMISE and requires no external vendor dependencies.

Author: VCC PKI Team
Date: November 2025
Version: 1.0.0

Standards:
- RFC 6960: X.509 Internet Public Key Infrastructure OCSP
- RFC 5280: X.509 Certificate and CRL Profile
"""

import hashlib
import logging
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from enum import Enum
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from sqlalchemy.orm import Session

from database import get_db, Certificate, CRLEntry

# Configure logging
logger = logging.getLogger(__name__)


class OCSPCertStatus(str, Enum):
    """OCSP Certificate Status (RFC 6960)"""
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class OCSPRevocationReason(int, Enum):
    """OCSP Revocation Reasons (RFC 5280)"""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


@dataclass
class OCSPResponse:
    """OCSP Response data structure"""
    status: OCSPCertStatus
    serial_number: str
    issuer_name_hash: str
    issuer_key_hash: str
    this_update: datetime
    next_update: datetime
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[OCSPRevocationReason] = None
    response_bytes: Optional[bytes] = None


class OCSPCache:
    """Simple in-memory cache for OCSP responses"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[OCSPResponse, datetime]] = {}
    
    def get(self, key: str) -> Optional[OCSPResponse]:
        """Get cached response if not expired"""
        if key not in self._cache:
            return None
        
        response, cached_at = self._cache[key]
        if datetime.now(timezone.utc) - cached_at > timedelta(seconds=self.ttl_seconds):
            del self._cache[key]
            return None
        
        return response
    
    def set(self, key: str, response: OCSPResponse):
        """Cache a response"""
        # Evict oldest entries if cache is full
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), 
                           key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        
        self._cache[key] = (response, datetime.now(timezone.utc))
    
    def clear(self):
        """Clear all cached responses"""
        self._cache.clear()
    
    @property
    def size(self) -> int:
        """Get current cache size"""
        return len(self._cache)


class OCSPResponder:
    """
    RFC 6960 compliant OCSP Responder.
    
    Provides real-time certificate status information for:
    - Certificate validation
    - OCSP stapling support
    - CRL alternative for real-time status
    
    This component is designed for ON-PREMISE deployment with
    no external vendor dependencies.
    """
    
    def __init__(
        self,
        ca_manager,
        cache_ttl_seconds: int = 3600,
        response_validity_hours: int = 24
    ):
        """
        Initialize the OCSP Responder.
        
        Args:
            ca_manager: CAManager instance for signing responses
            cache_ttl_seconds: Cache TTL in seconds (default: 1 hour)
            response_validity_hours: Response validity period in hours (default: 24)
        """
        self.ca_manager = ca_manager
        self.response_validity_hours = response_validity_hours
        self.cache = OCSPCache(ttl_seconds=cache_ttl_seconds)
        
        # Statistics
        self._stats = {
            "requests_total": 0,
            "requests_good": 0,
            "requests_revoked": 0,
            "requests_unknown": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0
        }
        
        logger.info("🔍 OCSP Responder initialized")
        logger.info(f"   Response validity: {response_validity_hours} hours")
        logger.info(f"   Cache TTL: {cache_ttl_seconds} seconds")
    
    # ========================================================================
    # OCSP Request Handling
    # ========================================================================
    
    def check_certificate_status(
        self,
        serial_number: str,
        db: Optional[Session] = None
    ) -> OCSPResponse:
        """
        Check the status of a certificate by serial number.
        
        Args:
            serial_number: Certificate serial number (hex string)
            db: Database session (optional, will create if not provided)
        
        Returns:
            OCSPResponse with certificate status
        """
        self._stats["requests_total"] += 1
        
        # Check cache first
        cache_key = f"ocsp:{serial_number}"
        cached_response = self.cache.get(cache_key)
        if cached_response:
            self._stats["cache_hits"] += 1
            logger.debug(f"OCSP cache hit for serial {serial_number}")
            return cached_response
        
        self._stats["cache_misses"] += 1
        
        # Get database session if not provided
        close_db = False
        if db is None:
            db_gen = get_db()
            db = next(db_gen)
            close_db = True
        
        try:
            # Look up certificate
            cert = db.query(Certificate).filter(
                Certificate.serial_number == serial_number
            ).first()
            
            now = datetime.now(timezone.utc)
            this_update = now
            next_update = now + timedelta(hours=self.response_validity_hours)
            
            if cert is None:
                # Certificate not found - return unknown status
                self._stats["requests_unknown"] += 1
                response = OCSPResponse(
                    status=OCSPCertStatus.UNKNOWN,
                    serial_number=serial_number,
                    issuer_name_hash="",
                    issuer_key_hash="",
                    this_update=this_update,
                    next_update=next_update
                )
            
            elif cert.status == "revoked":
                # Certificate is revoked
                self._stats["requests_revoked"] += 1
                
                # Get revocation details from CRL entry
                crl_entry = db.query(CRLEntry).filter(
                    CRLEntry.certificate_id == cert.certificate_id
                ).first()
                
                revocation_time = crl_entry.revoked_at if crl_entry else now
                revocation_reason = self._map_revocation_reason(
                    crl_entry.revocation_reason if crl_entry else "unspecified"
                )
                
                response = OCSPResponse(
                    status=OCSPCertStatus.REVOKED,
                    serial_number=serial_number,
                    issuer_name_hash=self._compute_issuer_name_hash(cert.issuer_dn),
                    issuer_key_hash="",
                    this_update=this_update,
                    next_update=next_update,
                    revocation_time=revocation_time,
                    revocation_reason=revocation_reason
                )
            
            elif cert.status == "expired" or (cert.not_after and cert.not_after < now):
                # Certificate is expired - treat as revoked with cessation
                self._stats["requests_revoked"] += 1
                response = OCSPResponse(
                    status=OCSPCertStatus.REVOKED,
                    serial_number=serial_number,
                    issuer_name_hash=self._compute_issuer_name_hash(cert.issuer_dn),
                    issuer_key_hash="",
                    this_update=this_update,
                    next_update=next_update,
                    revocation_time=cert.not_after,
                    revocation_reason=OCSPRevocationReason.CESSATION_OF_OPERATION
                )
            
            else:
                # Certificate is valid
                self._stats["requests_good"] += 1
                response = OCSPResponse(
                    status=OCSPCertStatus.GOOD,
                    serial_number=serial_number,
                    issuer_name_hash=self._compute_issuer_name_hash(cert.issuer_dn),
                    issuer_key_hash="",
                    this_update=this_update,
                    next_update=next_update
                )
            
            # Cache the response
            self.cache.set(cache_key, response)
            
            return response
        
        except Exception as e:
            self._stats["errors"] += 1
            logger.error(f"OCSP status check failed: {e}")
            raise
        
        finally:
            if close_db:
                try:
                    next(db_gen)
                except StopIteration:
                    pass
    
    def handle_ocsp_request(self, request_bytes: bytes) -> bytes:
        """
        Handle an OCSP request and return a signed response.
        
        Args:
            request_bytes: DER-encoded OCSP request
        
        Returns:
            DER-encoded OCSP response
        """
        try:
            # Parse OCSP request
            ocsp_request = ocsp.load_der_ocsp_request(request_bytes)
            serial_number = format(ocsp_request.serial_number, 'x')
            
            logger.debug(f"Received OCSP request for serial: {serial_number}")
            
            # Check certificate status
            status = self.check_certificate_status(serial_number)
            
            # Build OCSP response
            response_bytes = self._build_ocsp_response(ocsp_request, status)
            
            return response_bytes
        
        except Exception as e:
            logger.error(f"Failed to handle OCSP request: {e}")
            # Return unauthorized error response
            return self._build_error_response(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
    
    # ========================================================================
    # Response Building
    # ========================================================================
    
    def _build_ocsp_response(
        self,
        request: ocsp.OCSPRequest,
        status: OCSPResponse
    ) -> bytes:
        """Build and sign an OCSP response"""
        try:
            # Get CA certificate and private key for signing
            ca_cert = self.ca_manager.get_intermediate_certificate()
            ca_key = self.ca_manager.get_intermediate_private_key()
            
            if ca_cert is None or ca_key is None:
                logger.error("CA certificate or key not available for OCSP signing")
                return self._build_error_response(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
            
            # Build response based on status
            builder = ocsp.OCSPResponseBuilder()
            
            if status.status == OCSPCertStatus.GOOD:
                builder = builder.add_response(
                    cert=self._get_certificate_for_response(status.serial_number),
                    issuer=ca_cert,
                    algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.GOOD,
                    this_update=status.this_update,
                    next_update=status.next_update,
                    revocation_time=None,
                    revocation_reason=None
                )
            elif status.status == OCSPCertStatus.REVOKED:
                # Map revocation reason
                crypto_reason = None
                if status.revocation_reason:
                    crypto_reason = self._map_to_crypto_reason(status.revocation_reason)
                
                builder = builder.add_response(
                    cert=self._get_certificate_for_response(status.serial_number),
                    issuer=ca_cert,
                    algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.REVOKED,
                    this_update=status.this_update,
                    next_update=status.next_update,
                    revocation_time=status.revocation_time,
                    revocation_reason=crypto_reason
                )
            else:
                # Unknown status
                return self._build_error_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)
            
            # Set responder ID
            builder = builder.responder_id(
                ocsp.OCSPResponderEncoding.HASH, ca_cert
            )
            
            # Sign the response
            response = builder.sign(ca_key, hashes.SHA256())
            
            return response.public_bytes(serialization.Encoding.DER)
        
        except Exception as e:
            logger.error(f"Failed to build OCSP response: {e}")
            return self._build_error_response(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
    
    def _build_error_response(self, status: ocsp.OCSPResponseStatus) -> bytes:
        """Build an OCSP error response"""
        try:
            builder = ocsp.OCSPResponseBuilder()
            response = builder.build_unsuccessful(status)
            return response.public_bytes(serialization.Encoding.DER)
        except Exception as e:
            logger.error(f"Failed to build error response: {e}")
            # Return minimal error bytes if all else fails
            return b''
    
    def _get_certificate_for_response(self, serial_number: str):
        """Get the certificate object for OCSP response building"""
        # This would need to load the actual certificate
        # For now, we'll need the certificate from the database
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            cert_record = db.query(Certificate).filter(
                Certificate.serial_number == serial_number
            ).first()
            
            if cert_record and cert_record.cert_file_path:
                from pathlib import Path
                cert_path = Path(cert_record.cert_file_path)
                if cert_path.exists():
                    with open(cert_path, 'rb') as f:
                        return x509.load_pem_x509_certificate(f.read())
            
            return None
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _compute_issuer_name_hash(self, issuer_dn: str) -> str:
        """Compute SHA-256 hash of issuer distinguished name"""
        return hashlib.sha256(issuer_dn.encode()).hexdigest()
    
    def _map_revocation_reason(self, reason: str) -> OCSPRevocationReason:
        """Map string revocation reason to OCSP enum"""
        reason_map = {
            "unspecified": OCSPRevocationReason.UNSPECIFIED,
            "key_compromise": OCSPRevocationReason.KEY_COMPROMISE,
            "ca_compromise": OCSPRevocationReason.CA_COMPROMISE,
            "affiliation_changed": OCSPRevocationReason.AFFILIATION_CHANGED,
            "superseded": OCSPRevocationReason.SUPERSEDED,
            "cessation_of_operation": OCSPRevocationReason.CESSATION_OF_OPERATION,
            "certificate_hold": OCSPRevocationReason.CERTIFICATE_HOLD,
            "remove_from_crl": OCSPRevocationReason.REMOVE_FROM_CRL,
            "privilege_withdrawn": OCSPRevocationReason.PRIVILEGE_WITHDRAWN,
            "aa_compromise": OCSPRevocationReason.AA_COMPROMISE
        }
        return reason_map.get(reason.lower(), OCSPRevocationReason.UNSPECIFIED)
    
    def _map_to_crypto_reason(self, reason: OCSPRevocationReason):
        """Map OCSPRevocationReason to cryptography ReasonFlags"""
        from cryptography.x509.oid import ReasonFlags
        
        reason_map = {
            OCSPRevocationReason.KEY_COMPROMISE: ReasonFlags.key_compromise,
            OCSPRevocationReason.CA_COMPROMISE: ReasonFlags.ca_compromise,
            OCSPRevocationReason.AFFILIATION_CHANGED: ReasonFlags.affiliation_changed,
            OCSPRevocationReason.SUPERSEDED: ReasonFlags.superseded,
            OCSPRevocationReason.CESSATION_OF_OPERATION: ReasonFlags.cessation_of_operation,
            OCSPRevocationReason.CERTIFICATE_HOLD: ReasonFlags.certificate_hold,
            OCSPRevocationReason.PRIVILEGE_WITHDRAWN: ReasonFlags.privilege_withdrawn,
            OCSPRevocationReason.AA_COMPROMISE: ReasonFlags.aa_compromise
        }
        return reason_map.get(reason)
    
    # ========================================================================
    # Statistics & Management
    # ========================================================================
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """Get OCSP responder statistics"""
        return {
            **self._stats,
            "cache_size": self.cache.size,
            "cache_ttl_seconds": self.cache.ttl_seconds
        }
    
    def clear_cache(self):
        """Clear the OCSP response cache"""
        self.cache.clear()
        logger.info("🗑️ OCSP cache cleared")
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of certificate statuses"""
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            total = db.query(Certificate).count()
            active = db.query(Certificate).filter(Certificate.status == "active").count()
            revoked = db.query(Certificate).filter(Certificate.status == "revoked").count()
            expired = db.query(Certificate).filter(Certificate.status == "expired").count()
            
            return {
                "total_certificates": total,
                "active": active,
                "revoked": revoked,
                "expired": expired
            }
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass


# ============================================================================
# Factory Function
# ============================================================================

def create_ocsp_responder(
    ca_manager,
    cache_ttl_seconds: int = 3600,
    response_validity_hours: int = 24
) -> OCSPResponder:
    """
    Factory function to create an OCSP responder instance.
    
    Args:
        ca_manager: CAManager instance for signing responses
        cache_ttl_seconds: Cache TTL in seconds (default: 1 hour)
        response_validity_hours: Response validity period (default: 24 hours)
    
    Returns:
        Configured OCSPResponder instance
    """
    return OCSPResponder(
        ca_manager=ca_manager,
        cache_ttl_seconds=cache_ttl_seconds,
        response_validity_hours=response_validity_hours
    )


# ============================================================================
# Example Usage / Testing
# ============================================================================

if __name__ == "__main__":
    """Example usage of the OCSP responder"""
    
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("VCC PKI OCSP Responder - Test Mode")
    print("=" * 60)
    
    # Initialize database
    from database import init_database
    init_database()
    
    print("\n✅ OCSP Responder module loaded successfully")
    print("   Use create_ocsp_responder(ca_manager) to create an instance")
    print("\nSupported operations:")
    print("   - check_certificate_status(serial_number)")
    print("   - handle_ocsp_request(request_bytes)")
    print("   - get_status_summary()")
    print("   - clear_cache()")
