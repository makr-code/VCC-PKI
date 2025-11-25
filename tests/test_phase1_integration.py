#!/usr/bin/env python3
"""
VCC PKI Server - Integration Tests for Phase 1 Components
==========================================================

Tests for:
- Auto-Renewal Engine
- OCSP Responder
- CRL Distribution Point

Run with: pytest tests/test_phase1_integration.py -v
"""

import pytest
import sys
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database import init_database, get_db, Certificate, CRLEntry, RotationSchedule


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def db_session():
    """Create a test database session"""
    # Use in-memory SQLite for tests
    engine = init_database(":memory:")
    
    # Create tables
    from database import Base
    Base.metadata.create_all(bind=engine)
    
    # Get session
    db_gen = get_db()
    db = next(db_gen)
    
    yield db
    
    # Cleanup
    try:
        next(db_gen)
    except StopIteration:
        pass


@pytest.fixture
def mock_ca_manager():
    """Create a mock CA manager"""
    manager = Mock()
    manager.get_intermediate_certificate.return_value = None
    manager.get_intermediate_private_key.return_value = None
    return manager


@pytest.fixture
def mock_cert_manager():
    """Create a mock certificate manager"""
    manager = Mock()
    manager.renew_service_certificate.return_value = {
        "serial_number": "abc123",
        "common_name": "test-service.vcc.local"
    }
    return manager


# ============================================================================
# Auto-Renewal Engine Tests
# ============================================================================

class TestAutoRenewalEngine:
    """Tests for the Auto-Renewal Engine"""
    
    def test_import(self):
        """Test that auto_renewal_engine can be imported"""
        from auto_renewal_engine import AutoRenewalEngine, RenewalConfig
        assert AutoRenewalEngine is not None
        assert RenewalConfig is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from auto_renewal_engine import RenewalConfig
        
        config = RenewalConfig()
        
        assert config.renewal_threshold_days == 30
        assert config.warning_threshold_days == 14
        assert config.critical_threshold_days == 7
        assert config.check_interval_seconds == 3600
        assert config.max_retry_attempts == 3
    
    def test_config_custom(self):
        """Test custom configuration values"""
        from auto_renewal_engine import RenewalConfig
        
        config = RenewalConfig(
            renewal_threshold_days=45,
            warning_threshold_days=21,
            critical_threshold_days=10
        )
        
        assert config.renewal_threshold_days == 45
        assert config.warning_threshold_days == 21
        assert config.critical_threshold_days == 10
    
    def test_engine_initialization(self, mock_cert_manager):
        """Test engine initialization"""
        from auto_renewal_engine import AutoRenewalEngine, RenewalConfig
        
        config = RenewalConfig(check_interval_seconds=60)
        engine = AutoRenewalEngine(mock_cert_manager, config)
        
        assert engine.cert_manager == mock_cert_manager
        assert engine.config.check_interval_seconds == 60
        assert not engine.is_running
    
    def test_engine_statistics(self, mock_cert_manager):
        """Test engine statistics tracking"""
        from auto_renewal_engine import AutoRenewalEngine, RenewalConfig
        
        config = RenewalConfig()
        engine = AutoRenewalEngine(mock_cert_manager, config)
        
        stats = engine.statistics
        
        assert "total_renewals" in stats
        assert "successful_renewals" in stats
        assert "failed_renewals" in stats
        assert stats["total_renewals"] == 0
    
    def test_renewal_status_enum(self):
        """Test RenewalStatus enum values"""
        from auto_renewal_engine import RenewalStatus
        
        assert RenewalStatus.PENDING.value == "pending"
        assert RenewalStatus.IN_PROGRESS.value == "in_progress"
        assert RenewalStatus.COMPLETED.value == "completed"
        assert RenewalStatus.FAILED.value == "failed"


# ============================================================================
# OCSP Responder Tests
# ============================================================================

class TestOCSPResponder:
    """Tests for the OCSP Responder"""
    
    def test_import(self):
        """Test that ocsp_responder can be imported"""
        from ocsp_responder import OCSPResponder, OCSPCertStatus
        assert OCSPResponder is not None
        assert OCSPCertStatus is not None
    
    def test_cert_status_enum(self):
        """Test OCSPCertStatus enum values"""
        from ocsp_responder import OCSPCertStatus
        
        assert OCSPCertStatus.GOOD.value == "good"
        assert OCSPCertStatus.REVOKED.value == "revoked"
        assert OCSPCertStatus.UNKNOWN.value == "unknown"
    
    def test_revocation_reason_enum(self):
        """Test OCSPRevocationReason enum values"""
        from ocsp_responder import OCSPRevocationReason
        
        assert OCSPRevocationReason.UNSPECIFIED.value == 0
        assert OCSPRevocationReason.KEY_COMPROMISE.value == 1
        assert OCSPRevocationReason.CA_COMPROMISE.value == 2
    
    def test_cache_initialization(self):
        """Test OCSP cache initialization"""
        from ocsp_responder import OCSPCache
        
        cache = OCSPCache(max_size=100, ttl_seconds=60)
        
        assert cache.max_size == 100
        assert cache.ttl_seconds == 60
        assert cache.size == 0
    
    def test_cache_get_set(self):
        """Test OCSP cache get/set operations"""
        from ocsp_responder import OCSPCache, OCSPResponse, OCSPCertStatus
        
        cache = OCSPCache(max_size=100, ttl_seconds=3600)
        
        response = OCSPResponse(
            status=OCSPCertStatus.GOOD,
            serial_number="abc123",
            issuer_name_hash="hash",
            issuer_key_hash="keyhash",
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        
        cache.set("test_key", response)
        
        assert cache.size == 1
        assert cache.get("test_key") == response
    
    def test_cache_expiry(self):
        """Test OCSP cache TTL expiry"""
        from ocsp_responder import OCSPCache, OCSPResponse, OCSPCertStatus
        import time
        
        # Very short TTL
        cache = OCSPCache(max_size=100, ttl_seconds=1)
        
        response = OCSPResponse(
            status=OCSPCertStatus.GOOD,
            serial_number="abc123",
            issuer_name_hash="hash",
            issuer_key_hash="keyhash",
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        
        cache.set("test_key", response)
        assert cache.get("test_key") is not None
        
        # Wait for expiry
        time.sleep(1.5)
        assert cache.get("test_key") is None
    
    def test_responder_initialization(self, mock_ca_manager):
        """Test OCSP responder initialization"""
        from ocsp_responder import OCSPResponder
        
        responder = OCSPResponder(
            ca_manager=mock_ca_manager,
            cache_ttl_seconds=1800,
            response_validity_hours=12
        )
        
        assert responder.ca_manager == mock_ca_manager
        assert responder.response_validity_hours == 12
        assert responder.cache.ttl_seconds == 1800
    
    def test_responder_statistics(self, mock_ca_manager):
        """Test OCSP responder statistics"""
        from ocsp_responder import OCSPResponder
        
        responder = OCSPResponder(mock_ca_manager)
        
        stats = responder.statistics
        
        assert "requests_total" in stats
        assert "requests_good" in stats
        assert "requests_revoked" in stats
        assert "requests_unknown" in stats
        assert "cache_hits" in stats
        assert stats["requests_total"] == 0


# ============================================================================
# CRL Distribution Tests
# ============================================================================

class TestCRLDistribution:
    """Tests for the CRL Distribution Point"""
    
    def test_import(self):
        """Test that crl_distribution can be imported"""
        from crl_distribution import CRLDistributionPoint, CRLConfig
        assert CRLDistributionPoint is not None
        assert CRLConfig is not None
    
    def test_config_defaults(self):
        """Test default CRL configuration values"""
        from crl_distribution import CRLConfig
        
        config = CRLConfig()
        
        assert config.crl_validity_hours == 24
        assert config.crl_update_interval_seconds == 3600
        assert config.enable_delta_crl == True
        assert config.cache_enabled == True
    
    def test_crl_format_enum(self):
        """Test CRLFormat enum values"""
        from crl_distribution import CRLFormat
        
        assert CRLFormat.DER.value == "der"
        assert CRLFormat.PEM.value == "pem"
    
    def test_distribution_point_initialization(self, mock_ca_manager):
        """Test CRL distribution point initialization"""
        from crl_distribution import CRLDistributionPoint, CRLConfig
        
        config = CRLConfig(crl_validity_hours=48)
        cdp = CRLDistributionPoint(mock_ca_manager, config)
        
        assert cdp.ca_manager == mock_ca_manager
        assert cdp.config.crl_validity_hours == 48
        assert not cdp.is_running
    
    def test_distribution_point_statistics(self, mock_ca_manager):
        """Test CRL distribution point statistics"""
        from crl_distribution import CRLDistributionPoint, CRLConfig
        
        config = CRLConfig()
        cdp = CRLDistributionPoint(mock_ca_manager, config)
        
        stats = cdp.statistics
        
        assert "crls_generated" in stats
        assert "delta_crls_generated" in stats
        assert "crl_requests" in stats
        assert "cache_hits" in stats
        assert stats["crls_generated"] == 0
    
    def test_crl_generator_initialization(self, mock_ca_manager):
        """Test CRL generator initialization"""
        from crl_distribution import CRLGenerator
        
        generator = CRLGenerator(mock_ca_manager)
        
        assert generator.ca_manager == mock_ca_manager


# ============================================================================
# Database Model Tests
# ============================================================================

class TestDatabaseModels:
    """Tests for database models used by Phase 1 components"""
    
    def test_certificate_needs_renewal(self):
        """Test Certificate.needs_renewal property"""
        cert = Certificate(
            certificate_id="test-cert",
            service_id="test-service",
            common_name="test.vcc.local",
            serial_number="abc123",
            fingerprint="fp123",
            subject_dn="CN=test",
            issuer_dn="CN=CA",
            not_before=datetime.now(timezone.utc) - timedelta(days=300),
            not_after=datetime.now(timezone.utc) + timedelta(days=20)  # 20 days until expiry
        )
        
        assert cert.needs_renewal == True
    
    def test_certificate_does_not_need_renewal(self):
        """Test Certificate that doesn't need renewal"""
        cert = Certificate(
            certificate_id="test-cert",
            service_id="test-service",
            common_name="test.vcc.local",
            serial_number="abc123",
            fingerprint="fp123",
            subject_dn="CN=test",
            issuer_dn="CN=CA",
            not_before=datetime.now(timezone.utc) - timedelta(days=100),
            not_after=datetime.now(timezone.utc) + timedelta(days=200)  # 200 days until expiry
        )
        
        assert cert.needs_renewal == False
    
    def test_certificate_days_until_expiry(self):
        """Test Certificate.days_until_expiry property"""
        cert = Certificate(
            certificate_id="test-cert",
            service_id="test-service",
            common_name="test.vcc.local",
            serial_number="abc123",
            fingerprint="fp123",
            subject_dn="CN=test",
            issuer_dn="CN=CA",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=100)
        )
        
        # Should be approximately 100 days
        assert 99 <= cert.days_until_expiry <= 100


# ============================================================================
# Integration Tests
# ============================================================================

class TestPhase1Integration:
    """Integration tests for Phase 1 components working together"""
    
    def test_all_components_import(self):
        """Test that all Phase 1 components can be imported together"""
        from auto_renewal_engine import AutoRenewalEngine, RenewalConfig
        from ocsp_responder import OCSPResponder, OCSPCertStatus
        from crl_distribution import CRLDistributionPoint, CRLConfig
        
        # All imports successful
        assert True
    
    def test_components_share_database(self, mock_ca_manager, mock_cert_manager):
        """Test that components can share database connection"""
        from auto_renewal_engine import AutoRenewalEngine, RenewalConfig
        from ocsp_responder import OCSPResponder
        from crl_distribution import CRLDistributionPoint, CRLConfig
        
        # Create all components
        renewal_engine = AutoRenewalEngine(mock_cert_manager, RenewalConfig())
        ocsp = OCSPResponder(mock_ca_manager)
        cdp = CRLDistributionPoint(mock_ca_manager, CRLConfig())
        
        # All should be able to access database
        # (database is initialized when any component tries to access it)
        assert renewal_engine is not None
        assert ocsp is not None
        assert cdp is not None


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
