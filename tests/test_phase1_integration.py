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
# VCC Service Integration Tests
# ============================================================================

class TestVCCServiceIntegration:
    """Tests for VCC Service Integration module"""
    
    def test_import(self):
        """Test module imports correctly"""
        from vcc_service_integration import (
            VCCServiceIntegration,
            VCCIntegrationConfig,
            VCCServiceType,
            ServiceStatus,
            AuthMethod,
            TrustLevel,
            VCCService,
            VCCServiceRegistry
        )
        
        assert VCCServiceIntegration is not None
        assert VCCIntegrationConfig is not None
    
    def test_config_defaults(self):
        """Test VCCIntegrationConfig default values"""
        from vcc_service_integration import VCCIntegrationConfig
        
        config = VCCIntegrationConfig()
        
        assert config.discovery_enabled == True
        assert config.health_check_enabled == True
        assert config.auto_certificate_provisioning == True
        assert config.mtls_enabled == True
        assert config.zero_trust_enabled == True
        assert config.certificate_validity_days == 365
    
    def test_service_type_enum(self):
        """Test VCCServiceType enumeration"""
        from vcc_service_integration import VCCServiceType
        
        assert VCCServiceType.COVINA_BACKEND.value == "covina-backend"
        assert VCCServiceType.VERITAS_BACKEND.value == "veritas-backend"
        assert VCCServiceType.CLARA_BACKEND.value == "clara-backend"
        assert VCCServiceType.PKI_SERVER.value == "pki-server"
    
    def test_service_status_enum(self):
        """Test ServiceStatus enumeration"""
        from vcc_service_integration import ServiceStatus
        
        assert ServiceStatus.PENDING.value == "pending"
        assert ServiceStatus.ACTIVE.value == "active"
        assert ServiceStatus.UNHEALTHY.value == "unhealthy"
    
    def test_trust_level_enum(self):
        """Test TrustLevel enumeration"""
        from vcc_service_integration import TrustLevel
        
        assert TrustLevel.HIGH.value == "high"
        assert TrustLevel.MEDIUM.value == "medium"
        assert TrustLevel.LOW.value == "low"
        assert TrustLevel.UNTRUSTED.value == "untrusted"
    
    def test_vcc_service_creation(self):
        """Test VCCService creation"""
        from vcc_service_integration import VCCService, VCCServiceType, ServiceStatus
        
        service = VCCService(
            service_id="test-service",
            service_type=VCCServiceType.GENERIC,
            display_name="Test Service",
            description="A test service",
            endpoints=["https://test.vcc.local:443"]
        )
        
        assert service.service_id == "test-service"
        assert service.service_type == VCCServiceType.GENERIC
        assert service.status == ServiceStatus.PENDING
    
    def test_vcc_service_to_dict(self):
        """Test VCCService.to_dict()"""
        from vcc_service_integration import VCCService, VCCServiceType
        
        service = VCCService(
            service_id="test-service",
            service_type=VCCServiceType.COVINA_BACKEND,
            display_name="Test Service",
            description="A test service",
            endpoints=["https://test.vcc.local:443"]
        )
        
        data = service.to_dict()
        
        assert data["service_id"] == "test-service"
        assert data["service_type"] == "covina-backend"
        assert "endpoints" in data
        assert "created_at" in data
    
    def test_service_registry(self):
        """Test VCCServiceRegistry"""
        from vcc_service_integration import VCCServiceRegistry, VCCService, VCCServiceType
        
        registry = VCCServiceRegistry()
        
        service = VCCService(
            service_id="test-service",
            service_type=VCCServiceType.COVINA_BACKEND,
            display_name="Test Service",
            description="A test service",
            endpoints=["https://test.vcc.local:443"]
        )
        
        # Register
        result = registry.register(service)
        assert result == True
        
        # Get
        retrieved = registry.get("test-service")
        assert retrieved is not None
        assert retrieved.service_id == "test-service"
        
        # Get all
        all_services = registry.get_all()
        assert len(all_services) == 1
        
        # Unregister
        result = registry.unregister("test-service")
        assert result == True
        
        # Verify unregistered
        retrieved = registry.get("test-service")
        assert retrieved is None
    
    def test_integration_initialization(self):
        """Test VCCServiceIntegration initialization"""
        from vcc_service_integration import VCCServiceIntegration, VCCIntegrationConfig
        
        config = VCCIntegrationConfig()
        integration = VCCServiceIntegration(config=config)
        
        assert integration.registry is not None
        assert integration.provisioner is not None
        assert integration.health_checker is not None


# ============================================================================
# Database Migration Tests
# ============================================================================

class TestDatabaseMigration:
    """Tests for Database Migration module"""
    
    def test_import(self):
        """Test module imports correctly"""
        from database_migration import (
            DatabaseMigration,
            DatabaseConfig,
            DatabaseType,
            MigrationStatus,
            IsolationLevel
        )
        
        assert DatabaseMigration is not None
        assert DatabaseConfig is not None
    
    def test_database_type_enum(self):
        """Test DatabaseType enumeration"""
        from database_migration import DatabaseType
        
        assert DatabaseType.SQLITE.value == "sqlite"
        assert DatabaseType.POSTGRESQL.value == "postgresql"
    
    def test_isolation_level_enum(self):
        """Test IsolationLevel enumeration"""
        from database_migration import IsolationLevel
        
        assert IsolationLevel.STRICT.value == "strict"
        assert IsolationLevel.COLLABORATIVE.value == "collaborative"
        assert IsolationLevel.FEDERATED.value == "federated"
    
    def test_config_defaults(self):
        """Test DatabaseConfig default values"""
        from database_migration import DatabaseConfig, DatabaseType
        
        config = DatabaseConfig()
        
        assert config.database_type == DatabaseType.SQLITE
        assert config.pool_size == 5
        assert config.max_overflow == 10
        assert config.multi_tenant_enabled == False
        assert config.audit_chain_enabled == True
    
    def test_migration_schema_versions(self):
        """Test migration schema versions are defined"""
        from database_migration import DatabaseMigration
        
        migration = DatabaseMigration()
        
        assert len(migration.SCHEMA_VERSIONS) > 0
        
        # Check first version
        version, description, func_name = migration.SCHEMA_VERSIONS[0]
        assert version == "1.0.0"
        assert "initial" in description.lower() or "Initial" in description
    
    def test_organization_model(self):
        """Test Organization model"""
        from database_migration import Organization
        
        org = Organization(
            org_name="test-org",
            display_name="Test Organization",
            description="A test organization"
        )
        
        assert org.org_name == "test-org"
        # Note: Column defaults are only applied when persisted to DB
        # Test that the model can be created
        assert org.display_name == "Test Organization"
    
    def test_certificate_template_model(self):
        """Test CertificateTemplate model"""
        from database_migration import CertificateTemplate
        
        template = CertificateTemplate(
            template_name="vcc-service",
            description="VCC Service Certificate Template",
            validity_days=365,
            auto_renewal=True  # Explicitly set
        )
        
        assert template.template_name == "vcc-service"
        assert template.validity_days == 365
        assert template.auto_renewal == True
    
    def test_enhanced_audit_log_hash(self):
        """Test EnhancedAuditLog hash calculation"""
        from database_migration import EnhancedAuditLog
        from datetime import datetime, timezone
        
        log = EnhancedAuditLog(
            action="CERTIFICATE_ISSUED",
            resource_type="certificate",
            resource_id="test-cert-123",
            user_id="admin",
            details='{"common_name": "test.vcc.local"}'
        )
        log.timestamp = datetime.now(timezone.utc)
        
        # Calculate hash
        hash1 = log.calculate_hash("")
        hash2 = log.calculate_hash("")
        
        assert hash1 == hash2  # Same input should produce same hash
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
    
    def test_migration_manager_initialization(self):
        """Test DatabaseMigration initialization"""
        from database_migration import DatabaseMigration, DatabaseConfig, DatabaseType
        
        config = DatabaseConfig(
            database_type=DatabaseType.SQLITE,
            sqlite_path="/tmp/test_pki.db"
        )
        
        migration = DatabaseMigration(config)
        
        assert migration.config == config
        assert migration.config.database_type == DatabaseType.SQLITE


# ============================================================================
# Monitoring Dashboard Tests
# ============================================================================

class TestMonitoringDashboard:
    """Tests for the Monitoring Dashboard"""
    
    def test_import(self):
        """Test that monitoring_dashboard can be imported"""
        from monitoring_dashboard import MonitoringDashboard, DashboardConfig
        assert MonitoringDashboard is not None
        assert DashboardConfig is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from monitoring_dashboard import DashboardConfig
        
        config = DashboardConfig()
        
        assert config.warning_threshold_days == 30
        assert config.critical_threshold_days == 14
        assert config.max_alerts == 100
        assert config.enable_notifications == True
    
    def test_dashboard_initialization(self):
        """Test dashboard initialization"""
        from monitoring_dashboard import MonitoringDashboard, DashboardConfig
        
        config = DashboardConfig(
            warning_threshold_days=45,
            critical_threshold_days=21
        )
        
        dashboard = MonitoringDashboard(config)
        
        assert dashboard.config.warning_threshold_days == 45
        assert dashboard.config.critical_threshold_days == 21
    
    def test_certificate_metrics_dataclass(self):
        """Test CertificateMetrics dataclass"""
        from monitoring_dashboard import CertificateMetrics
        
        metrics = CertificateMetrics(
            total_certificates=10,
            active_certificates=8,
            expired_certificates=1,
            revoked_certificates=1
        )
        
        assert metrics.total_certificates == 10
        assert metrics.active_certificates == 8
        
        # Test to_dict
        result = metrics.to_dict()
        assert result["total_certificates"] == 10
    
    def test_alert_creation(self):
        """Test alert creation"""
        from monitoring_dashboard import MonitoringDashboard, AlertSeverity
        
        dashboard = MonitoringDashboard()
        
        alert = dashboard.create_alert(
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="This is a test alert",
            source="test"
        )
        
        assert alert.severity == AlertSeverity.WARNING
        assert alert.title == "Test Alert"
        assert alert.acknowledged == False
    
    def test_alert_acknowledgement(self):
        """Test alert acknowledgement"""
        from monitoring_dashboard import MonitoringDashboard, AlertSeverity
        
        dashboard = MonitoringDashboard()
        
        alert = dashboard.create_alert(
            severity=AlertSeverity.CRITICAL,
            title="Critical Alert",
            message="Critical issue",
            source="system"
        )
        
        # Acknowledge the alert
        result = dashboard.acknowledge_alert(alert.alert_id, "admin")
        
        assert result == True
        
        # Get alerts and verify
        alerts = dashboard.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].acknowledged == True
        assert alerts[0].acknowledged_by == "admin"
    
    def test_alert_summary(self):
        """Test alert summary"""
        from monitoring_dashboard import MonitoringDashboard, AlertSeverity
        
        dashboard = MonitoringDashboard()
        
        # Create various alerts
        dashboard.create_alert(AlertSeverity.INFO, "Info", "Info message", "test")
        dashboard.create_alert(AlertSeverity.WARNING, "Warning", "Warning message", "test")
        dashboard.create_alert(AlertSeverity.CRITICAL, "Critical", "Critical message", "test")
        
        summary = dashboard.get_alert_summary()
        
        assert summary["info"] == 1
        assert summary["warning"] == 1
        assert summary["critical"] == 1
        assert summary["total"] == 3
        assert summary["unacknowledged"] == 3
    
    def test_system_metrics(self):
        """Test system metrics collection"""
        from monitoring_dashboard import MonitoringDashboard
        
        dashboard = MonitoringDashboard()
        
        # Record some requests
        dashboard.record_request(50.0)
        dashboard.record_request(100.0)
        dashboard.record_request(75.0)
        
        metrics = dashboard.get_system_metrics()
        
        assert metrics.total_requests == 3
        assert metrics.avg_response_time_ms == 75.0


# ============================================================================
# OCSP Stapling Tests
# ============================================================================

class TestOCSPStapling:
    """Tests for OCSP Stapling"""
    
    def test_import(self):
        """Test that ocsp_stapling can be imported"""
        from ocsp_stapling import OCSPStaplingManager, OCSPStaplingConfig
        assert OCSPStaplingManager is not None
        assert OCSPStaplingConfig is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from ocsp_stapling import OCSPStaplingConfig
        
        config = OCSPStaplingConfig()
        
        assert config.enabled == True
        assert config.update_interval_seconds == 3600
        assert config.response_validity_hours == 24
        assert config.max_cache_size == 1000
    
    def test_config_custom(self):
        """Test custom configuration values"""
        from ocsp_stapling import OCSPStaplingConfig
        
        config = OCSPStaplingConfig(
            enabled=False,
            update_interval_seconds=1800,
            max_cache_size=500
        )
        
        assert config.enabled == False
        assert config.update_interval_seconds == 1800
        assert config.max_cache_size == 500
    
    def test_staple_status_enum(self):
        """Test OCSPStapleStatus enum"""
        from ocsp_stapling import OCSPStapleStatus
        
        assert OCSPStapleStatus.VALID.value == "valid"
        assert OCSPStapleStatus.EXPIRED.value == "expired"
        assert OCSPStapleStatus.UNKNOWN.value == "unknown"
        assert OCSPStapleStatus.ERROR.value == "error"
    
    def test_staple_dataclass(self):
        """Test OCSPStaple dataclass"""
        from ocsp_stapling import OCSPStaple, OCSPStapleStatus
        from datetime import datetime, timedelta, timezone
        
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(hours=24)
        
        staple = OCSPStaple(
            serial_number="abc123",
            certificate_fingerprint="fingerprint123",
            ocsp_response=b"response_bytes",
            created_at=now,
            valid_until=valid_until,
            status=OCSPStapleStatus.VALID
        )
        
        assert staple.serial_number == "abc123"
        assert staple.is_valid() == True
        
        # Test expired staple
        expired_staple = OCSPStaple(
            serial_number="xyz789",
            certificate_fingerprint="fingerprint456",
            ocsp_response=b"response_bytes",
            created_at=now - timedelta(hours=48),
            valid_until=now - timedelta(hours=24),
            status=OCSPStapleStatus.VALID
        )
        
        assert expired_staple.is_valid() == False
    
    def test_stapling_statistics(self):
        """Test StaplingStatistics dataclass"""
        from ocsp_stapling import StaplingStatistics
        
        stats = StaplingStatistics(
            total_staples=10,
            valid_staples=8,
            cache_hits=50,
            cache_misses=5
        )
        
        assert stats.total_staples == 10
        assert stats.valid_staples == 8
        
        # Test to_dict
        result = stats.to_dict()
        assert result["cache_hits"] == 50
        assert result["cache_misses"] == 5


# ============================================================================
# Phase 2 Tests - HSM Integration
# ============================================================================

class TestHSMIntegration:
    """Tests for the HSM Integration Module (Phase 2)"""
    
    def test_import(self):
        """Test that hsm_integration can be imported"""
        from hsm_integration import HSMManager, HSMConfig, KeyType, KeyPurpose
        assert HSMManager is not None
        assert HSMConfig is not None
        assert KeyType is not None
        assert KeyPurpose is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from hsm_integration import HSMConfig, HSMType, KeyType
        
        config = HSMConfig()
        
        assert config.hsm_type == HSMType.SOFTHSM
        assert config.slot_id == 0
        assert config.token_label == "VCC-PKI"
        assert config.default_key_type == KeyType.RSA_4096
        assert config.require_dual_auth == False
    
    def test_key_type_enum(self):
        """Test KeyType enum values"""
        from hsm_integration import KeyType
        
        assert KeyType.RSA_2048.value == "rsa_2048"
        assert KeyType.RSA_4096.value == "rsa_4096"
        assert KeyType.ECC_P256.value == "ecc_p256"
        assert KeyType.ECC_P384.value == "ecc_p384"
        assert KeyType.ECC_P521.value == "ecc_p521"
    
    def test_key_purpose_enum(self):
        """Test KeyPurpose enum values"""
        from hsm_integration import KeyPurpose
        
        assert KeyPurpose.ROOT_CA.value == "root_ca"
        assert KeyPurpose.INTERMEDIATE_CA.value == "intermediate_ca"
        assert KeyPurpose.SERVICE_SIGNING.value == "service_signing"
        assert KeyPurpose.CODE_SIGNING.value == "code_signing"
        assert KeyPurpose.TSA_SIGNING.value == "tsa_signing"
    
    def test_hsm_key_info_dataclass(self):
        """Test HSMKeyInfo dataclass"""
        from hsm_integration import HSMKeyInfo, KeyType, KeyPurpose
        from datetime import datetime
        
        key_info = HSMKeyInfo(
            key_id="test-key-123",
            key_label="test-key",
            key_type=KeyType.RSA_4096,
            purpose=KeyPurpose.SERVICE_SIGNING,
            created_at=datetime.utcnow()
        )
        
        assert key_info.key_id == "test-key-123"
        assert key_info.key_type == KeyType.RSA_4096
        assert key_info.is_extractable == False
        assert key_info.is_persistent == True
    
    def test_auth_session_dataclass(self):
        """Test AuthSession dataclass"""
        from hsm_integration import AuthSession
        from datetime import datetime, timedelta
        
        session = AuthSession(
            session_id="session-123",
            required_persons=2,
            authenticated_persons=["admin1"],
            operation="generate_ca_key",
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        
        assert session.session_id == "session-123"
        assert session.required_persons == 2
        assert len(session.authenticated_persons) == 1
        assert session.is_valid == True
    
    def test_softhsm_backend(self):
        """Test SoftHSM backend initialization"""
        from hsm_integration import SoftHSMBackend, HSMConfig
        
        config = HSMConfig()
        backend = SoftHSMBackend(config)
        
        assert backend.is_connected() == False
        
        # Connect
        result = backend.connect()
        assert result == True
        assert backend.is_connected() == True
        
        # Disconnect
        backend.disconnect()
        assert backend.is_connected() == False
    
    def test_hsm_manager_status(self):
        """Test HSM Manager status"""
        from hsm_integration import HSMManager, HSMConfig, HSMStatus
        
        config = HSMConfig()
        manager = HSMManager(config)
        
        # Before connecting
        assert manager.status == HSMStatus.DISCONNECTED
        
        # After connecting
        manager.connect()
        assert manager.status == HSMStatus.CONNECTED
        
        manager.disconnect()


# ============================================================================
# Phase 2 Tests - Timestamp Authority
# ============================================================================

class TestTimestampAuthority:
    """Tests for the Timestamp Authority Module (Phase 2)"""
    
    def test_import(self):
        """Test that timestamp_authority can be imported"""
        from timestamp_authority import TimestampAuthority, TSAConfig, HashAlgorithm
        assert TimestampAuthority is not None
        assert TSAConfig is not None
        assert HashAlgorithm is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from timestamp_authority import TSAConfig
        
        config = TSAConfig()
        
        assert config.enabled == True
        assert config.tsa_name == "VCC Timestamp Authority"
        assert config.accuracy_seconds == 1
        assert config.ordering == True
        assert "sha256" in config.supported_algorithms
    
    def test_hash_algorithm_enum(self):
        """Test HashAlgorithm enum values"""
        from timestamp_authority import HashAlgorithm
        
        assert HashAlgorithm.SHA256.value == "sha256"
        assert HashAlgorithm.SHA384.value == "sha384"
        assert HashAlgorithm.SHA512.value == "sha512"
    
    def test_tsa_status_enum(self):
        """Test TSAStatus enum values"""
        from timestamp_authority import TSAStatus
        
        assert TSAStatus.GRANTED.value == "granted"
        assert TSAStatus.REJECTION.value == "rejection"
        assert TSAStatus.WAITING.value == "waiting"
    
    def test_timestamp_request_dataclass(self):
        """Test TimestampRequest dataclass"""
        from timestamp_authority import TimestampRequest, HashAlgorithm
        
        request = TimestampRequest(
            message_imprint_hash=b'x' * 32,
            hash_algorithm=HashAlgorithm.SHA256,
            nonce=12345,
            cert_req=True
        )
        
        assert len(request.message_imprint_hash) == 32
        assert request.hash_algorithm == HashAlgorithm.SHA256
        assert request.nonce == 12345
    
    def test_timestamp_token_dataclass(self):
        """Test TimestampToken dataclass"""
        from timestamp_authority import TimestampToken, HashAlgorithm
        from datetime import datetime, timezone
        
        token = TimestampToken(
            serial_number=123456,
            gen_time=datetime.now(timezone.utc),
            message_imprint_hash=b'x' * 32,
            hash_algorithm=HashAlgorithm.SHA256,
            policy_oid="1.2.3.4.5",
            accuracy_seconds=1,
            accuracy_millis=0,
            accuracy_micros=0,
            ordering=True,
            nonce=12345,
            tsa_name="Test TSA",
            signature=b'signature'
        )
        
        assert token.serial_number == 123456
        assert token.accuracy_seconds == 1
        assert token.ordering == True
    
    def test_tsa_statistics_dataclass(self):
        """Test TSAStatistics dataclass"""
        from timestamp_authority import TSAStatistics
        
        stats = TSAStatistics(
            total_requests=100,
            total_granted=95,
            total_rejected=5,
            requests_sha256=80
        )
        
        assert stats.total_requests == 100
        assert stats.total_granted == 95
        assert stats.requests_sha256 == 80


# ============================================================================
# Phase 2 Tests - Certificate Templates
# ============================================================================

class TestCertificateTemplates:
    """Tests for the Certificate Templates Module (Phase 2)"""
    
    def test_import(self):
        """Test that certificate_templates can be imported"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        assert CertificateTemplateManager is not None
        assert TemplateConfig is not None
    
    def test_config_defaults(self):
        """Test default configuration values"""
        from certificate_templates import TemplateConfig
        
        config = TemplateConfig()
        
        assert config.templates_path == "../templates"
        assert config.auto_load == True
        assert config.strict_validation == True
    
    def test_template_type_enum(self):
        """Test TemplateType enum values"""
        from certificate_templates import TemplateType
        
        assert TemplateType.SERVICE.value == "service"
        assert TemplateType.CODE_SIGNING.value == "code_signing"
        assert TemplateType.TLS_SERVER.value == "tls_server"
        assert TemplateType.ADMIN.value == "admin"
        assert TemplateType.TSA.value == "tsa"
    
    def test_key_usage_flags_enum(self):
        """Test KeyUsageFlags enum"""
        from certificate_templates import KeyUsageFlags
        
        assert KeyUsageFlags.DIGITAL_SIGNATURE.value == "digital_signature"
        assert KeyUsageFlags.KEY_ENCIPHERMENT.value == "key_encipherment"
        assert KeyUsageFlags.KEY_CERT_SIGN.value == "key_cert_sign"
    
    def test_extended_key_usage_enum(self):
        """Test ExtendedKeyUsage enum"""
        from certificate_templates import ExtendedKeyUsage
        
        assert ExtendedKeyUsage.SERVER_AUTH.value == "server_auth"
        assert ExtendedKeyUsage.CLIENT_AUTH.value == "client_auth"
        assert ExtendedKeyUsage.CODE_SIGNING.value == "code_signing"
        assert ExtendedKeyUsage.TIME_STAMPING.value == "time_stamping"
    
    def test_subject_config_dataclass(self):
        """Test SubjectConfig dataclass"""
        from certificate_templates import SubjectConfig
        
        subject = SubjectConfig(
            country="DE",
            state="Brandenburg",
            organization="VCC",
            common_name="test.vcc.local"
        )
        
        assert subject.country == "DE"
        assert subject.organization == "VCC"
    
    def test_validity_config_dataclass(self):
        """Test ValidityConfig dataclass"""
        from certificate_templates import ValidityConfig
        
        validity = ValidityConfig(
            days=365,
            max_days=730,
            renewable=True
        )
        
        assert validity.days == 365
        assert validity.max_days == 730
        assert validity.renewable == True
    
    def test_certificate_template_dataclass(self):
        """Test CertificateTemplate dataclass"""
        from certificate_templates import CertificateTemplate, TemplateType
        
        template = CertificateTemplate(
            template_id="test-template",
            template_name="Test Template",
            template_type=TemplateType.SERVICE,
            description="A test template"
        )
        
        assert template.template_id == "test-template"
        assert template.template_type == TemplateType.SERVICE
        assert template.key_size == 4096  # Default
    
    def test_template_manager_predefined_templates(self):
        """Test that predefined templates are loaded"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        
        config = TemplateConfig(auto_load=False)
        manager = CertificateTemplateManager(config)
        
        # Check predefined templates exist
        templates = manager.list_templates()
        template_ids = [t["template_id"] for t in templates]
        
        assert "vcc-service" in template_ids
        assert "vcc-code-signing" in template_ids
        assert "vcc-clara-model" in template_ids
        assert "vcc-tls-server" in template_ids
        assert "vcc-admin" in template_ids
        assert "vcc-tsa" in template_ids
    
    def test_get_template(self):
        """Test getting a specific template"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        
        config = TemplateConfig(auto_load=False)
        manager = CertificateTemplateManager(config)
        
        template = manager.get_template("vcc-service")
        
        assert template is not None
        assert template.template_id == "vcc-service"
        assert template.key_size == 4096
    
    def test_variable_substitution(self):
        """Test variable substitution in templates"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        
        config = TemplateConfig(auto_load=False)
        manager = CertificateTemplateManager(config)
        
        resolved = manager.get_resolved_template(
            "vcc-service",
            {"service_name": "my-service"}
        )
        
        assert resolved is not None
        assert "my-service" in resolved.subject.common_name
    
    def test_validate_request_valid(self):
        """Test request validation - valid request"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        
        config = TemplateConfig(auto_load=False)
        manager = CertificateTemplateManager(config)
        
        is_valid, errors = manager.validate_request(
            "vcc-service",
            {"service_name": "my-service"},
            365
        )
        
        assert is_valid == True
        assert len(errors) == 0
    
    def test_validate_request_invalid_validity(self):
        """Test request validation - invalid validity period"""
        from certificate_templates import CertificateTemplateManager, TemplateConfig
        
        config = TemplateConfig(auto_load=False)
        manager = CertificateTemplateManager(config)
        
        # Request validity exceeds max
        is_valid, errors = manager.validate_request(
            "vcc-service",
            {"service_name": "my-service"},
            1000  # Exceeds max_days of 730
        )
        
        assert is_valid == False
        assert len(errors) > 0


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
