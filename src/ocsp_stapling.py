# ============================================================================
# VCC PROTECTED SOURCE CODE
# ============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: ocsp_stapling
# Description: OCSP Stapling Support for VCC PKI Server
# File Path: ocsp_stapling.py
#
# Version: 1.0.0
# Author: VCC Security Team
#
# ============================================================================

"""
VCC PKI OCSP Stapling Support
=============================

Provides OCSP Stapling (TLS Certificate Status Request) functionality.

OCSP Stapling improves TLS handshake performance by:
- Pre-fetching OCSP responses on the server side
- Including the response in the TLS handshake
- Reducing client-side OCSP lookups
- Improving privacy (no direct client-CA communication)

RFC References:
- RFC 6066: Transport Layer Security (TLS) Extensions
- RFC 6960: Online Certificate Status Protocol (OCSP)
- RFC 6961: TLS Multiple Certificate Status Request Extension

Author: VCC Team
Date: 2025-11-25
Version: 1.0.0
"""

import os
import json
import logging
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp as crypto_ocsp

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Data Classes
# ============================================================================

class OCSPStapleStatus(str, Enum):
    """OCSP staple status"""
    VALID = "valid"
    EXPIRED = "expired"
    UNKNOWN = "unknown"
    ERROR = "error"
    PENDING = "pending"


@dataclass
class OCSPStaplingConfig:
    """Configuration for OCSP Stapling"""
    enabled: bool = True
    update_interval_seconds: int = 3600  # 1 hour
    response_validity_hours: int = 24
    max_cache_size: int = 1000
    retry_interval_seconds: int = 300  # 5 minutes
    max_retry_attempts: int = 3
    cache_path: str = "../ocsp_staples"
    enable_persistence: bool = True
    
    @classmethod
    def from_env(cls) -> "OCSPStaplingConfig":
        """Create configuration from environment variables"""
        return cls(
            enabled=os.getenv("VCC_OCSP_STAPLING_ENABLED", "true").lower() == "true",
            update_interval_seconds=int(os.getenv("VCC_OCSP_STAPLE_INTERVAL", "3600")),
            response_validity_hours=int(os.getenv("VCC_OCSP_STAPLE_VALIDITY", "24")),
            max_cache_size=int(os.getenv("VCC_OCSP_STAPLE_CACHE_SIZE", "1000")),
            retry_interval_seconds=int(os.getenv("VCC_OCSP_STAPLE_RETRY_INTERVAL", "300")),
            max_retry_attempts=int(os.getenv("VCC_OCSP_STAPLE_MAX_RETRIES", "3")),
            cache_path=os.getenv("VCC_OCSP_STAPLE_CACHE_PATH", "../ocsp_staples"),
            enable_persistence=os.getenv("VCC_OCSP_STAPLE_PERSIST", "true").lower() == "true"
        )


@dataclass
class OCSPStaple:
    """OCSP staple data"""
    serial_number: str
    certificate_fingerprint: str
    ocsp_response: bytes
    created_at: datetime
    valid_until: datetime
    status: OCSPStapleStatus = OCSPStapleStatus.VALID
    retry_count: int = 0
    last_error: Optional[str] = None
    
    def is_valid(self) -> bool:
        """Check if staple is still valid"""
        return (
            self.status == OCSPStapleStatus.VALID and
            datetime.now(timezone.utc) < self.valid_until
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "serial_number": self.serial_number,
            "certificate_fingerprint": self.certificate_fingerprint,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "status": self.status.value,
            "retry_count": self.retry_count,
            "last_error": self.last_error,
            "is_valid": self.is_valid()
        }


@dataclass
class StaplingStatistics:
    """OCSP stapling statistics"""
    total_staples: int = 0
    valid_staples: int = 0
    expired_staples: int = 0
    error_staples: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    updates_performed: int = 0
    update_failures: int = 0
    last_update_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        if self.last_update_time:
            result["last_update_time"] = self.last_update_time.isoformat()
        return result


# ============================================================================
# OCSP Stapling Manager
# ============================================================================

class OCSPStaplingManager:
    """
    OCSP Stapling Manager.
    
    Manages OCSP staples for TLS server certificates.
    Provides background updates and caching.
    """
    
    def __init__(
        self,
        ocsp_responder,
        config: Optional[OCSPStaplingConfig] = None
    ):
        """
        Initialize the OCSP Stapling Manager.
        
        Args:
            ocsp_responder: OCSPResponder instance for generating responses
            config: Stapling configuration
        """
        self._ocsp_responder = ocsp_responder
        self.config = config or OCSPStaplingConfig.from_env()
        
        # Staple cache
        self._staples: Dict[str, OCSPStaple] = {}
        self._lock = threading.RLock()
        
        # Statistics
        self.statistics = StaplingStatistics()
        
        # Background worker
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        
        # Persistence
        self._cache_path = Path(self.config.cache_path)
        if self.config.enable_persistence:
            self._cache_path.mkdir(parents=True, exist_ok=True)
            self._load_cached_staples()
        
        logger.info("📌 OCSP Stapling Manager initialized")
    
    # ========================================================================
    # Lifecycle Management
    # ========================================================================
    
    def start(self):
        """Start the background worker"""
        if self._running:
            logger.warning("OCSP Stapling Manager already running")
            return
        
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="OCSPStaplingWorker",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("✅ OCSP Stapling Manager started")
    
    def stop(self):
        """Stop the background worker"""
        if not self._running:
            return
        
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
        
        # Save staples before stopping
        if self.config.enable_persistence:
            self._save_cached_staples()
        
        logger.info("🛑 OCSP Stapling Manager stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if the manager is running"""
        return self._running
    
    # ========================================================================
    # Staple Management
    # ========================================================================
    
    def get_staple(self, certificate: x509.Certificate) -> Optional[bytes]:
        """
        Get OCSP staple for a certificate.
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            OCSP response bytes or None if not available
        """
        fingerprint = self._get_certificate_fingerprint(certificate)
        
        with self._lock:
            staple = self._staples.get(fingerprint)
            
            if staple and staple.is_valid():
                self.statistics.cache_hits += 1
                return staple.ocsp_response
            
            self.statistics.cache_misses += 1
            
            # Try to generate new staple
            if staple is None or not staple.is_valid():
                new_staple = self._generate_staple(certificate)
                if new_staple and new_staple.is_valid():
                    self._staples[fingerprint] = new_staple
                    return new_staple.ocsp_response
            
            return None
    
    def get_staple_by_serial(self, serial_number: str) -> Optional[bytes]:
        """
        Get OCSP staple by certificate serial number.
        
        Args:
            serial_number: Certificate serial number (hex string)
            
        Returns:
            OCSP response bytes or None if not available
        """
        with self._lock:
            for staple in self._staples.values():
                if staple.serial_number == serial_number and staple.is_valid():
                    self.statistics.cache_hits += 1
                    return staple.ocsp_response
            
            self.statistics.cache_misses += 1
            return None
    
    def add_certificate(self, certificate: x509.Certificate) -> bool:
        """
        Add a certificate to stapling management.
        
        Args:
            certificate: X.509 certificate to manage
            
        Returns:
            True if staple was generated successfully
        """
        fingerprint = self._get_certificate_fingerprint(certificate)
        
        with self._lock:
            if fingerprint in self._staples and self._staples[fingerprint].is_valid():
                logger.debug(f"Certificate {fingerprint[:16]}... already has valid staple")
                return True
            
            staple = self._generate_staple(certificate)
            if staple:
                self._staples[fingerprint] = staple
                logger.info(f"📌 Added staple for certificate {fingerprint[:16]}...")
                return True
            
            logger.warning(f"❌ Failed to generate staple for {fingerprint[:16]}...")
            return False
    
    def remove_certificate(self, certificate: x509.Certificate):
        """
        Remove a certificate from stapling management.
        
        Args:
            certificate: X.509 certificate to remove
        """
        fingerprint = self._get_certificate_fingerprint(certificate)
        
        with self._lock:
            if fingerprint in self._staples:
                del self._staples[fingerprint]
                logger.info(f"🗑️ Removed staple for certificate {fingerprint[:16]}...")
    
    def get_status(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Get stapling status for a certificate.
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            Dictionary with staple status information
        """
        fingerprint = self._get_certificate_fingerprint(certificate)
        
        with self._lock:
            staple = self._staples.get(fingerprint)
            
            if staple:
                return staple.to_dict()
            
            return {
                "certificate_fingerprint": fingerprint,
                "status": OCSPStapleStatus.UNKNOWN.value,
                "is_valid": False,
                "message": "No staple available for this certificate"
            }
    
    def get_all_staples_status(self) -> List[Dict[str, Any]]:
        """
        Get status of all managed staples.
        
        Returns:
            List of staple status dictionaries
        """
        with self._lock:
            return [staple.to_dict() for staple in self._staples.values()]
    
    # ========================================================================
    # Staple Generation
    # ========================================================================
    
    def _generate_staple(self, certificate: x509.Certificate) -> Optional[OCSPStaple]:
        """
        Generate OCSP staple for a certificate.
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            OCSPStaple or None if generation failed
        """
        try:
            serial_hex = format(certificate.serial_number, 'x')
            fingerprint = self._get_certificate_fingerprint(certificate)
            
            # Get OCSP response from responder
            response = self._ocsp_responder.check_certificate_status(serial_hex)
            
            if response.status.value != "good":
                logger.warning(f"Certificate {serial_hex} status is {response.status.value}")
            
            # Build OCSP response bytes (simplified - in production use full OCSP response)
            ocsp_response_bytes = self._build_ocsp_response_bytes(response)
            
            staple = OCSPStaple(
                serial_number=serial_hex,
                certificate_fingerprint=fingerprint,
                ocsp_response=ocsp_response_bytes,
                created_at=datetime.now(timezone.utc),
                valid_until=response.next_update,
                status=OCSPStapleStatus.VALID
            )
            
            self.statistics.total_staples += 1
            self.statistics.valid_staples += 1
            self.statistics.updates_performed += 1
            self.statistics.last_update_time = datetime.now(timezone.utc)
            
            return staple
            
        except Exception as e:
            logger.error(f"❌ Failed to generate staple: {e}")
            self.statistics.update_failures += 1
            return None
    
    def _build_ocsp_response_bytes(self, response) -> bytes:
        """
        Build OCSP response bytes from response object.
        
        Args:
            response: OCSPResponse object
            
        Returns:
            Encoded OCSP response bytes
        """
        # In a full implementation, this would build a proper DER-encoded OCSP response
        # For now, we create a simplified representation
        response_data = {
            "serial_number": response.serial_number,
            "status": response.status.value,
            "this_update": response.this_update.isoformat(),
            "next_update": response.next_update.isoformat()
        }
        
        if response.revocation_time:
            response_data["revocation_time"] = response.revocation_time.isoformat()
        if response.revocation_reason:
            response_data["revocation_reason"] = response.revocation_reason.name
        
        return json.dumps(response_data).encode('utf-8')
    
    # ========================================================================
    # Background Worker
    # ========================================================================
    
    def _worker_loop(self):
        """Background worker loop for staple updates"""
        logger.info("📌 OCSP Stapling worker started")
        
        while self._running:
            try:
                self._update_expiring_staples()
                
                # Sleep with early exit support
                for _ in range(self.config.update_interval_seconds):
                    if not self._running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"❌ Stapling worker error: {e}")
                time.sleep(self.config.retry_interval_seconds)
        
        logger.info("🛑 OCSP Stapling worker stopped")
    
    def _update_expiring_staples(self):
        """Update staples that are expiring soon"""
        now = datetime.now(timezone.utc)
        update_threshold = now + timedelta(hours=self.config.response_validity_hours // 2)
        
        with self._lock:
            staples_to_update = [
                (fp, staple) for fp, staple in self._staples.items()
                if staple.valid_until < update_threshold
            ]
        
        for fingerprint, staple in staples_to_update:
            try:
                # Re-fetch OCSP response
                response = self._ocsp_responder.check_certificate_status(staple.serial_number)
                
                with self._lock:
                    staple.ocsp_response = self._build_ocsp_response_bytes(response)
                    staple.created_at = now
                    staple.valid_until = response.next_update
                    staple.status = OCSPStapleStatus.VALID
                    staple.retry_count = 0
                    staple.last_error = None
                
                self.statistics.updates_performed += 1
                self.statistics.last_update_time = now
                
                logger.debug(f"📌 Updated staple for {fingerprint[:16]}...")
                
            except Exception as e:
                with self._lock:
                    staple.retry_count += 1
                    staple.last_error = str(e)
                    
                    if staple.retry_count >= self.config.max_retry_attempts:
                        staple.status = OCSPStapleStatus.ERROR
                        self.statistics.error_staples += 1
                
                self.statistics.update_failures += 1
                logger.warning(f"❌ Failed to update staple {fingerprint[:16]}...: {e}")
    
    # ========================================================================
    # Persistence
    # ========================================================================
    
    def _load_cached_staples(self):
        """Load cached staples from disk"""
        cache_file = self._cache_path / "staples_cache.json"
        
        if not cache_file.exists():
            return
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            now = datetime.now(timezone.utc)
            
            for item in data.get("staples", []):
                valid_until = datetime.fromisoformat(item["valid_until"])
                
                if valid_until > now:
                    staple = OCSPStaple(
                        serial_number=item["serial_number"],
                        certificate_fingerprint=item["certificate_fingerprint"],
                        ocsp_response=base64.b64decode(item["ocsp_response"]),
                        created_at=datetime.fromisoformat(item["created_at"]),
                        valid_until=valid_until,
                        status=OCSPStapleStatus(item["status"])
                    )
                    self._staples[item["certificate_fingerprint"]] = staple
            
            logger.info(f"📂 Loaded {len(self._staples)} cached staples")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to load cached staples: {e}")
    
    def _save_cached_staples(self):
        """Save staples to disk cache"""
        cache_file = self._cache_path / "staples_cache.json"
        
        try:
            data = {
                "version": "1.0",
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "staples": []
            }
            
            with self._lock:
                for staple in self._staples.values():
                    if staple.is_valid():
                        data["staples"].append({
                            "serial_number": staple.serial_number,
                            "certificate_fingerprint": staple.certificate_fingerprint,
                            "ocsp_response": base64.b64encode(staple.ocsp_response).decode('ascii'),
                            "created_at": staple.created_at.isoformat(),
                            "valid_until": staple.valid_until.isoformat(),
                            "status": staple.status.value
                        })
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"💾 Saved {len(data['staples'])} staples to cache")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to save staples cache: {e}")
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _get_certificate_fingerprint(self, certificate: x509.Certificate) -> str:
        """Get SHA-256 fingerprint of certificate"""
        cert_bytes = certificate.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_bytes).hexdigest()
    
    def force_update_all(self):
        """Force update of all staples"""
        logger.info("⚡ Forcing update of all staples")
        
        with self._lock:
            fingerprints = list(self._staples.keys())
        
        for fingerprint in fingerprints:
            with self._lock:
                staple = self._staples.get(fingerprint)
                if staple:
                    try:
                        response = self._ocsp_responder.check_certificate_status(staple.serial_number)
                        staple.ocsp_response = self._build_ocsp_response_bytes(response)
                        staple.created_at = datetime.now(timezone.utc)
                        staple.valid_until = response.next_update
                        staple.status = OCSPStapleStatus.VALID
                        staple.retry_count = 0
                        self.statistics.updates_performed += 1
                    except Exception as e:
                        staple.last_error = str(e)
                        self.statistics.update_failures += 1
        
        self.statistics.last_update_time = datetime.now(timezone.utc)
    
    def clear_cache(self):
        """Clear all cached staples"""
        with self._lock:
            self._staples.clear()
            self.statistics.total_staples = 0
            self.statistics.valid_staples = 0
            self.statistics.expired_staples = 0
            self.statistics.error_staples = 0
        
        logger.info("🗑️ OCSP staple cache cleared")


# ============================================================================
# API Router Factory
# ============================================================================

def create_stapling_router(stapling_manager: OCSPStaplingManager) -> "APIRouter":
    """
    Create FastAPI router for OCSP stapling endpoints.
    
    Args:
        stapling_manager: OCSPStaplingManager instance
        
    Returns:
        FastAPI router
    """
    from fastapi import APIRouter, HTTPException, Response
    
    router = APIRouter(prefix="/api/v1/ocsp-stapling", tags=["OCSP Stapling"])
    
    @router.get("/status")
    async def get_stapling_status():
        """Get OCSP stapling status and statistics"""
        return {
            "enabled": stapling_manager.config.enabled,
            "running": stapling_manager.is_running,
            "statistics": stapling_manager.statistics.to_dict(),
            "config": {
                "update_interval_seconds": stapling_manager.config.update_interval_seconds,
                "response_validity_hours": stapling_manager.config.response_validity_hours,
                "max_cache_size": stapling_manager.config.max_cache_size
            }
        }
    
    @router.get("/staples")
    async def get_all_staples():
        """Get status of all managed staples"""
        staples = stapling_manager.get_all_staples_status()
        return {
            "total": len(staples),
            "staples": staples
        }
    
    @router.get("/staples/{serial_number}")
    async def get_staple(serial_number: str):
        """Get OCSP staple for a specific certificate"""
        staple_bytes = stapling_manager.get_staple_by_serial(serial_number)
        
        if staple_bytes is None:
            raise HTTPException(
                status_code=404,
                detail=f"No valid staple found for serial number: {serial_number}"
            )
        
        return Response(
            content=staple_bytes,
            media_type="application/ocsp-response"
        )
    
    @router.post("/force-update")
    async def force_update():
        """Force update of all staples"""
        stapling_manager.force_update_all()
        return {
            "success": True,
            "message": "Forced update of all staples",
            "statistics": stapling_manager.statistics.to_dict()
        }
    
    @router.post("/clear-cache")
    async def clear_cache():
        """Clear all cached staples"""
        stapling_manager.clear_cache()
        return {
            "success": True,
            "message": "OCSP staple cache cleared"
        }
    
    @router.post("/start")
    async def start_stapling():
        """Start the OCSP stapling background worker"""
        if stapling_manager.is_running:
            return {
                "success": True,
                "message": "OCSP stapling already running"
            }
        
        stapling_manager.start()
        return {
            "success": True,
            "message": "OCSP stapling started"
        }
    
    @router.post("/stop")
    async def stop_stapling():
        """Stop the OCSP stapling background worker"""
        if not stapling_manager.is_running:
            return {
                "success": True,
                "message": "OCSP stapling already stopped"
            }
        
        stapling_manager.stop()
        return {
            "success": True,
            "message": "OCSP stapling stopped"
        }
    
    return router


# ============================================================================
# Factory Function
# ============================================================================

def create_ocsp_stapling_manager(
    ocsp_responder,
    config: Optional[OCSPStaplingConfig] = None
) -> OCSPStaplingManager:
    """
    Create a new OCSPStaplingManager instance.
    
    Args:
        ocsp_responder: OCSPResponder instance
        config: Stapling configuration
        
    Returns:
        OCSPStaplingManager instance
    """
    return OCSPStaplingManager(ocsp_responder, config)
