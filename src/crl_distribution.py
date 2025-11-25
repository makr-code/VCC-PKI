#!/usr/bin/env python3
"""
VCC PKI Server - CRL Distribution Points
==========================================

HTTP-based Certificate Revocation List (CRL) distribution implementing
Phase 1 of the VCC-PKI development strategy.

Features:
- HTTP-based CRL distribution endpoint
- Automatic CRL generation (configurable interval)
- Delta-CRL support for efficiency
- X.509 CRL format (RFC 5280 compliant)
- Caching for performance

This component runs ON-PREMISE and requires no external vendor dependencies.

Author: VCC PKI Team
Date: November 2025
Version: 1.0.0

Standards:
- RFC 5280: X.509 Certificate and CRL Profile
"""

import logging
import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from pathlib import Path
from enum import Enum

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from sqlalchemy.orm import Session

from database import get_db, Certificate, CRLEntry

# Configure logging
logger = logging.getLogger(__name__)


class CRLFormat(str, Enum):
    """CRL output formats"""
    DER = "der"
    PEM = "pem"


@dataclass
class CRLConfig:
    """Configuration for CRL distribution"""
    # CRL generation settings
    crl_validity_hours: int = 24  # CRL valid for 24 hours
    crl_update_interval_seconds: int = 3600  # Regenerate every hour
    
    # Delta CRL settings
    enable_delta_crl: bool = True
    delta_crl_interval_seconds: int = 300  # 5 minutes
    
    # Storage settings
    crl_storage_path: str = "crl"
    
    # Performance settings
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300  # 5 minute cache


class CRLGenerator:
    """
    X.509 CRL Generator.
    
    Generates RFC 5280 compliant Certificate Revocation Lists.
    """
    
    def __init__(self, ca_manager):
        """
        Initialize CRL Generator.
        
        Args:
            ca_manager: CAManager instance for signing CRLs
        """
        self.ca_manager = ca_manager
        self._crl_number = 1
    
    def generate_full_crl(
        self,
        revoked_certificates: List[Dict[str, Any]],
        validity_hours: int = 24
    ) -> bytes:
        """
        Generate a full CRL containing all revoked certificates.
        
        Args:
            revoked_certificates: List of revoked certificate info
            validity_hours: CRL validity period in hours
        
        Returns:
            DER-encoded CRL bytes
        """
        try:
            # Get CA certificate and key
            ca_cert = self.ca_manager.get_intermediate_certificate()
            ca_key = self.ca_manager.get_intermediate_private_key()
            
            if ca_cert is None or ca_key is None:
                raise ValueError("CA certificate or key not available")
            
            # Build CRL
            now = datetime.now(timezone.utc)
            next_update = now + timedelta(hours=validity_hours)
            
            builder = x509.CertificateRevocationListBuilder()
            builder = builder.issuer_name(ca_cert.subject)
            builder = builder.last_update(now)
            builder = builder.next_update(next_update)
            
            # Add revoked certificates
            for cert_info in revoked_certificates:
                serial_number = int(cert_info["serial_number"], 16)
                revocation_date = cert_info.get("revoked_at", now)
                
                if isinstance(revocation_date, str):
                    revocation_date = datetime.fromisoformat(revocation_date.replace('Z', '+00:00'))
                
                revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                    serial_number
                ).revocation_date(
                    revocation_date
                )
                
                # Add revocation reason if available
                reason = cert_info.get("revocation_reason")
                if reason:
                    reason_flag = self._map_revocation_reason(reason)
                    if reason_flag:
                        revoked_cert = revoked_cert.add_extension(
                            x509.CRLReason(reason_flag),
                            critical=False
                        )
                
                builder = builder.add_revoked_certificate(revoked_cert.build())
            
            # Add CRL number extension
            builder = builder.add_extension(
                x509.CRLNumber(self._crl_number),
                critical=False
            )
            self._crl_number += 1
            
            # Sign CRL
            crl = builder.sign(
                private_key=ca_key,
                algorithm=hashes.SHA256()
            )
            
            return crl.public_bytes(serialization.Encoding.DER)
        
        except Exception as e:
            logger.error(f"Failed to generate CRL: {e}")
            raise
    
    def generate_delta_crl(
        self,
        revoked_since: datetime,
        base_crl_number: int,
        validity_hours: int = 1
    ) -> bytes:
        """
        Generate a delta CRL containing only recent revocations.
        
        Args:
            revoked_since: Include revocations since this time
            base_crl_number: The CRL number this delta is based on
            validity_hours: Delta CRL validity period
        
        Returns:
            DER-encoded delta CRL bytes
        """
        # Get recent revocations from database
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            recent_revocations = db.query(CRLEntry).filter(
                CRLEntry.revoked_at >= revoked_since
            ).all()
            
            revoked_list = []
            for entry in recent_revocations:
                revoked_list.append({
                    "serial_number": entry.serial_number,
                    "revoked_at": entry.revoked_at,
                    "revocation_reason": entry.revocation_reason
                })
            
            # Generate delta CRL
            return self.generate_full_crl(revoked_list, validity_hours)
        
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    
    def _map_revocation_reason(self, reason: str):
        """Map string reason to x509 ReasonFlags"""
        reason_map = {
            "key_compromise": x509.ReasonFlags.key_compromise,
            "ca_compromise": x509.ReasonFlags.ca_compromise,
            "affiliation_changed": x509.ReasonFlags.affiliation_changed,
            "superseded": x509.ReasonFlags.superseded,
            "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
            "certificate_hold": x509.ReasonFlags.certificate_hold,
            "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
            "aa_compromise": x509.ReasonFlags.aa_compromise,
            "remove_from_crl": x509.ReasonFlags.remove_from_crl
        }
        return reason_map.get(reason.lower())


class CRLDistributionPoint:
    """
    HTTP-based CRL Distribution Point.
    
    Provides:
    - Full CRL endpoint
    - Delta CRL endpoint (optional)
    - Automatic CRL regeneration
    - Caching for performance
    
    This component is designed for ON-PREMISE deployment with
    no external vendor dependencies.
    """
    
    def __init__(
        self,
        ca_manager,
        config: Optional[CRLConfig] = None
    ):
        """
        Initialize CRL Distribution Point.
        
        Args:
            ca_manager: CAManager instance for signing CRLs
            config: CRL configuration (uses defaults if not provided)
        """
        self.ca_manager = ca_manager
        self.config = config or CRLConfig()
        self.generator = CRLGenerator(ca_manager)
        
        # Storage
        self.storage_path = Path(self.config.crl_storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Cache
        self._crl_cache: Optional[bytes] = None
        self._crl_cache_time: Optional[datetime] = None
        self._delta_crl_cache: Optional[bytes] = None
        self._delta_crl_cache_time: Optional[datetime] = None
        self._last_full_crl_time: Optional[datetime] = None
        
        # Background worker
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        
        # Statistics
        self._stats = {
            "crls_generated": 0,
            "delta_crls_generated": 0,
            "crl_requests": 0,
            "cache_hits": 0,
            "last_generation": None
        }
        
        logger.info("📋 CRL Distribution Point initialized")
        logger.info(f"   CRL validity: {self.config.crl_validity_hours} hours")
        logger.info(f"   Update interval: {self.config.crl_update_interval_seconds} seconds")
    
    # ========================================================================
    # Lifecycle Management
    # ========================================================================
    
    def start(self):
        """Start the CRL distribution service"""
        if self._running:
            logger.warning("CRL Distribution Point is already running")
            return
        
        self._running = True
        
        # Generate initial CRL
        self._generate_and_cache_crl()
        
        # Start background worker
        self._worker_thread = threading.Thread(
            target=self._run_worker,
            daemon=True,
            name="CRLDistributionWorker"
        )
        self._worker_thread.start()
        
        logger.info("🚀 CRL Distribution Point started")
    
    def stop(self):
        """Stop the CRL distribution service"""
        if not self._running:
            return
        
        self._running = False
        
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=10)
        
        logger.info("🛑 CRL Distribution Point stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if the service is running"""
        return self._running
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        return self._stats.copy()
    
    # ========================================================================
    # CRL Retrieval
    # ========================================================================
    
    def get_crl(self, format: CRLFormat = CRLFormat.DER) -> bytes:
        """
        Get the current CRL.
        
        Args:
            format: Output format (DER or PEM)
        
        Returns:
            CRL bytes in requested format
        """
        self._stats["crl_requests"] += 1
        
        # Check cache
        if self.config.cache_enabled and self._is_cache_valid():
            self._stats["cache_hits"] += 1
            crl_bytes = self._crl_cache
        else:
            # Generate new CRL if cache invalid
            self._generate_and_cache_crl()
            crl_bytes = self._crl_cache
        
        if crl_bytes is None:
            raise ValueError("CRL not available")
        
        # Convert format if needed
        if format == CRLFormat.PEM:
            crl = x509.load_der_x509_crl(crl_bytes)
            return crl.public_bytes(serialization.Encoding.PEM)
        
        return crl_bytes
    
    def get_delta_crl(self, format: CRLFormat = CRLFormat.DER) -> Optional[bytes]:
        """
        Get the current delta CRL.
        
        Args:
            format: Output format (DER or PEM)
        
        Returns:
            Delta CRL bytes or None if not available
        """
        if not self.config.enable_delta_crl:
            return None
        
        if self._delta_crl_cache is None:
            return None
        
        if format == CRLFormat.PEM:
            crl = x509.load_der_x509_crl(self._delta_crl_cache)
            return crl.public_bytes(serialization.Encoding.PEM)
        
        return self._delta_crl_cache
    
    def get_crl_info(self) -> Dict[str, Any]:
        """Get information about the current CRL"""
        if self._crl_cache is None:
            return {"available": False}
        
        try:
            crl = x509.load_der_x509_crl(self._crl_cache)
            
            return {
                "available": True,
                "issuer": crl.issuer.rfc4514_string(),
                "last_update": crl.last_update_utc.isoformat() if hasattr(crl, 'last_update_utc') else str(crl.last_update),
                "next_update": crl.next_update_utc.isoformat() if hasattr(crl, 'next_update_utc') else str(crl.next_update),
                "revoked_count": len(list(crl)),
                "crl_number": self._get_crl_number(crl),
                "signature_algorithm": crl.signature_algorithm_oid.dotted_string,
                "cache_time": self._crl_cache_time.isoformat() if self._crl_cache_time else None,
                "delta_crl_available": self._delta_crl_cache is not None
            }
        except Exception as e:
            logger.error(f"Failed to get CRL info: {e}")
            return {"available": False, "error": str(e)}
    
    def _get_crl_number(self, crl) -> Optional[int]:
        """Extract CRL number from CRL"""
        try:
            for ext in crl.extensions:
                if ext.oid == ExtensionOID.CRL_NUMBER:
                    return ext.value.crl_number
        except Exception:
            pass
        return None
    
    # ========================================================================
    # Background Worker
    # ========================================================================
    
    def _run_worker(self):
        """Background worker for CRL regeneration"""
        logger.info("🔄 CRL Distribution Worker started")
        
        while self._running:
            try:
                # Sleep for update interval
                for _ in range(self.config.crl_update_interval_seconds):
                    if not self._running:
                        break
                    time.sleep(1)
                
                if not self._running:
                    break
                
                # Regenerate CRL
                self._generate_and_cache_crl()
                
                # Generate delta CRL if enabled
                if self.config.enable_delta_crl and self._last_full_crl_time:
                    self._generate_delta_crl()
                
            except Exception as e:
                logger.error(f"CRL worker error: {e}")
        
        logger.info("🔄 CRL Distribution Worker stopped")
    
    def _generate_and_cache_crl(self):
        """Generate and cache a new CRL"""
        try:
            # Get revoked certificates from database
            revoked_certs = self._get_revoked_certificates()
            
            # Generate CRL
            crl_bytes = self.generator.generate_full_crl(
                revoked_certs,
                self.config.crl_validity_hours
            )
            
            # Cache
            self._crl_cache = crl_bytes
            self._crl_cache_time = datetime.now(timezone.utc)
            self._last_full_crl_time = self._crl_cache_time
            
            # Save to file
            crl_file = self.storage_path / "crl.der"
            crl_file.write_bytes(crl_bytes)
            
            # Also save PEM version
            crl = x509.load_der_x509_crl(crl_bytes)
            pem_file = self.storage_path / "crl.pem"
            pem_file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
            
            self._stats["crls_generated"] += 1
            self._stats["last_generation"] = self._crl_cache_time.isoformat()
            
            logger.info(f"✅ CRL generated with {len(revoked_certs)} revoked certificates")
            
        except Exception as e:
            logger.error(f"Failed to generate CRL: {e}")
    
    def _generate_delta_crl(self):
        """Generate a delta CRL"""
        if not self._last_full_crl_time:
            return
        
        try:
            delta_crl_bytes = self.generator.generate_delta_crl(
                self._last_full_crl_time,
                self._stats["crls_generated"],
                validity_hours=1
            )
            
            self._delta_crl_cache = delta_crl_bytes
            self._delta_crl_cache_time = datetime.now(timezone.utc)
            
            # Save to file
            delta_file = self.storage_path / "delta-crl.der"
            delta_file.write_bytes(delta_crl_bytes)
            
            self._stats["delta_crls_generated"] += 1
            
            logger.debug("Delta CRL generated")
            
        except Exception as e:
            logger.error(f"Failed to generate delta CRL: {e}")
    
    def _get_revoked_certificates(self) -> List[Dict[str, Any]]:
        """Get all revoked certificates from database"""
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            entries = db.query(CRLEntry).all()
            
            return [
                {
                    "serial_number": entry.serial_number,
                    "revoked_at": entry.revoked_at,
                    "revocation_reason": entry.revocation_reason
                }
                for entry in entries
            ]
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    
    def _is_cache_valid(self) -> bool:
        """Check if CRL cache is still valid"""
        if self._crl_cache is None or self._crl_cache_time is None:
            return False
        
        age = (datetime.now(timezone.utc) - self._crl_cache_time).total_seconds()
        return age < self.config.cache_ttl_seconds
    
    # ========================================================================
    # Manual Operations
    # ========================================================================
    
    def force_regenerate(self):
        """Force immediate CRL regeneration"""
        logger.info("⚡ Forcing CRL regeneration")
        self._generate_and_cache_crl()
        
        if self.config.enable_delta_crl:
            self._generate_delta_crl()
    
    def clear_cache(self):
        """Clear the CRL cache"""
        self._crl_cache = None
        self._crl_cache_time = None
        self._delta_crl_cache = None
        self._delta_crl_cache_time = None
        logger.info("🗑️ CRL cache cleared")


# ============================================================================
# Factory Function
# ============================================================================

def create_crl_distribution_point(
    ca_manager,
    config: Optional[CRLConfig] = None
) -> CRLDistributionPoint:
    """
    Factory function to create a CRL Distribution Point instance.
    
    Args:
        ca_manager: CAManager instance for signing CRLs
        config: CRL configuration (uses defaults if not provided)
    
    Returns:
        Configured CRLDistributionPoint instance
    """
    return CRLDistributionPoint(ca_manager, config)


# ============================================================================
# Example Usage / Testing
# ============================================================================

if __name__ == "__main__":
    """Example usage of the CRL distribution point"""
    
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("VCC PKI CRL Distribution Point - Test Mode")
    print("=" * 60)
    
    # Initialize database
    from database import init_database
    init_database()
    
    config = CRLConfig(
        crl_validity_hours=24,
        crl_update_interval_seconds=3600,
        enable_delta_crl=True
    )
    
    print(f"\nConfiguration:")
    print(f"  - CRL validity: {config.crl_validity_hours} hours")
    print(f"  - Update interval: {config.crl_update_interval_seconds} seconds")
    print(f"  - Delta CRL enabled: {config.enable_delta_crl}")
    
    print("\n✅ CRL Distribution Point module loaded successfully")
    print("   Use create_crl_distribution_point(ca_manager) to create an instance")
    print("\nEndpoints:")
    print("   - GET /api/v1/crl/full - Get full CRL (DER)")
    print("   - GET /api/v1/crl/full/pem - Get full CRL (PEM)")
    print("   - GET /api/v1/crl/delta - Get delta CRL")
    print("   - GET /api/v1/crl/info - Get CRL information")
