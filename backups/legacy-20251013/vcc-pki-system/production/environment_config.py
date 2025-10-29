# VCC PKI System - Multi-Environment Production Configuration
# Comprehensive Configuration Management für Development, Staging, Production

import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import yaml
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class Environment(Enum):
    """VCC PKI System Environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging" 
    PRODUCTION = "production"
    DR_SITE = "disaster_recovery"  # Disaster Recovery Site

class SecurityLevel(Enum):
    """Security Classification Levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

@dataclass
class DatabaseConfig:
    """Database Configuration per Environment"""
    host: str
    port: int = 5432
    database: str = "vcc_pki"
    username: str = "vcc_pki_user"
    password: str = "${DB_PASSWORD}"  # Environment variable
    
    # Connection Pool Settings
    min_connections: int = 5
    max_connections: int = 20
    connection_timeout: int = 30
    
    # SSL Configuration
    ssl_mode: str = "require"
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    ssl_ca_path: Optional[str] = None
    
    # Backup Configuration
    backup_enabled: bool = True
    backup_retention_days: int = 30
    backup_schedule: str = "0 2 * * *"  # Daily at 2 AM
    
    # Monitoring
    slow_query_threshold: float = 1.0  # seconds
    connection_monitoring: bool = True

@dataclass
class RedisConfig:
    """Redis Configuration für Caching & Sessions"""
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    database: int = 0
    
    # SSL Configuration
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    
    # Connection Pool
    max_connections: int = 50
    connection_timeout: int = 10
    
    # Clustering
    cluster_enabled: bool = False
    cluster_nodes: List[str] = field(default_factory=list)

@dataclass
class SecurityConfig:
    """Security Configuration per Environment"""
    
    # JWT Configuration
    jwt_secret_key: str = "${JWT_SECRET}"
    jwt_algorithm: str = "RS256"
    jwt_expiration_hours: int = 24
    jwt_refresh_expiration_days: int = 7
    
    # Password Policy
    min_password_length: int = 12
    require_special_chars: bool = True
    require_numbers: bool = True
    require_uppercase: bool = True
    password_expiry_days: int = 90
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour
    
    # Session Management
    session_timeout_minutes: int = 30
    max_concurrent_sessions: int = 5
    
    # HTTPS Configuration
    force_https: bool = True
    hsts_max_age: int = 31536000  # 1 year
    
    # API Security
    api_key_expiry_days: int = 365
    cors_origins: List[str] = field(default_factory=list)
    
    # Audit & Logging
    audit_all_requests: bool = True
    log_sensitive_data: bool = False
    retention_period_days: int = 2555  # 7 years for compliance

@dataclass
class MonitoringConfig:
    """Monitoring & Alerting Configuration"""
    
    # Prometheus Configuration
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    
    # Grafana Configuration  
    grafana_enabled: bool = True
    grafana_port: int = 3000
    
    # Health Checks
    health_check_interval: int = 30  # seconds
    health_check_timeout: int = 5
    
    # Alerting
    alert_manager_url: Optional[str] = None
    smtp_server: Optional[str] = None
    alert_email_recipients: List[str] = field(default_factory=list)
    
    # Log Aggregation
    log_level: str = "INFO"
    log_format: str = "json"
    log_rotation_size: str = "100MB"
    log_retention_days: int = 90
    
    # Performance Monitoring
    apm_enabled: bool = False
    apm_service_name: str = "vcc-pki-system"

@dataclass
class NetworkConfig:
    """Network Configuration per Environment"""
    
    # Application Binding
    bind_host: str = "0.0.0.0"
    bind_port: int = 8000
    
    # Load Balancer Configuration
    load_balancer_enabled: bool = False
    upstream_servers: List[str] = field(default_factory=list)
    
    # Proxy Configuration
    reverse_proxy_enabled: bool = False
    proxy_headers: Dict[str, str] = field(default_factory=dict)
    
    # Firewall Rules
    allowed_ips: List[str] = field(default_factory=list)
    blocked_ips: List[str] = field(default_factory=list)
    
    # VPN Configuration
    vpn_required: bool = False
    vpn_networks: List[str] = field(default_factory=list)

@dataclass
class VCCEnvironmentConfig:
    """Complete VCC PKI Environment Configuration"""
    
    environment: Environment
    security_level: SecurityLevel
    
    # Service Configuration
    database: DatabaseConfig
    redis: RedisConfig
    security: SecurityConfig
    monitoring: MonitoringConfig
    network: NetworkConfig
    
    # HSM Configuration Reference
    hsm_environment: str
    
    # VCC Service Integration
    vcc_services: Dict[str, str] = field(default_factory=dict)
    service_discovery_enabled: bool = False
    
    # Backup & Disaster Recovery
    backup_enabled: bool = True
    dr_enabled: bool = False
    dr_site_url: Optional[str] = None
    
    # Compliance
    gdpr_compliance: bool = True
    ai_act_compliance: bool = True
    bsi_tr_compliance: bool = True
    audit_retention_years: int = 7

# Production Environment Configurations
ENVIRONMENT_CONFIGS = {
    Environment.DEVELOPMENT: VCCEnvironmentConfig(
        environment=Environment.DEVELOPMENT,
        security_level=SecurityLevel.INTERNAL,
        
        database=DatabaseConfig(
            host="localhost",
            port=5432,
            password="dev_password_123",
            min_connections=2,
            max_connections=10,
            ssl_mode="prefer",
            backup_enabled=False
        ),
        
        redis=RedisConfig(
            host="localhost",
            port=6379,
            password=None,
            ssl_enabled=False,
            max_connections=10
        ),
        
        security=SecurityConfig(
            jwt_secret_key="dev_secret_key_not_for_production",
            jwt_expiration_hours=72,  # Longer for development
            min_password_length=8,
            require_special_chars=False,
            rate_limit_requests=1000,  # More lenient
            force_https=False,
            audit_all_requests=False,
            log_sensitive_data=True,  # For debugging
            cors_origins=["http://localhost:3000", "http://127.0.0.1:3000"]
        ),
        
        monitoring=MonitoringConfig(
            prometheus_enabled=False,
            grafana_enabled=False,
            log_level="DEBUG",
            log_format="human",
            alert_email_recipients=[],
            apm_enabled=False
        ),
        
        network=NetworkConfig(
            bind_host="127.0.0.1",
            bind_port=8000,
            allowed_ips=["127.0.0.1", "::1"],
            vpn_required=False
        ),
        
        hsm_environment="development",
        
        vcc_services={
            "clara": "http://localhost:8001",
            "covina": "http://localhost:8002", 
            "argus": "http://localhost:8003",
            "veritas": "http://localhost:8004",
            "vpb": "http://localhost:8005"
        },
        
        backup_enabled=False,
        dr_enabled=False,
        gdpr_compliance=False,  # Relaxed for development
        ai_act_compliance=False,
        bsi_tr_compliance=False
    ),
    
    Environment.TESTING: VCCEnvironmentConfig(
        environment=Environment.TESTING,
        security_level=SecurityLevel.INTERNAL,
        
        database=DatabaseConfig(
            host="test-db.vcc.internal",
            port=5432,
            password="${TEST_DB_PASSWORD}",
            min_connections=5,
            max_connections=15,
            ssl_mode="require",
            ssl_ca_path="/etc/ssl/certs/vcc-ca.crt",
            backup_enabled=True,
            backup_retention_days=7
        ),
        
        redis=RedisConfig(
            host="test-redis.vcc.internal",
            port=6379,
            password="${TEST_REDIS_PASSWORD}",
            ssl_enabled=True,
            max_connections=25
        ),
        
        security=SecurityConfig(
            jwt_secret_key="${TEST_JWT_SECRET}",
            jwt_expiration_hours=24,
            min_password_length=10,
            rate_limit_requests=200,
            force_https=True,
            audit_all_requests=True,
            log_sensitive_data=False,
            cors_origins=["https://test-pki.vcc.internal"]
        ),
        
        monitoring=MonitoringConfig(
            prometheus_enabled=True,
            grafana_enabled=True,
            log_level="INFO",
            log_format="json",
            alert_email_recipients=["test-alerts@vcc.brandenburg.de"],
            apm_enabled=True
        ),
        
        network=NetworkConfig(
            bind_host="0.0.0.0",
            bind_port=8000,
            load_balancer_enabled=False,
            allowed_ips=["10.0.0.0/8"],  # Internal network only
            vpn_required=True,
            vpn_networks=["10.0.0.0/8"]
        ),
        
        hsm_environment="development",  # Still using mock HSM for testing
        
        vcc_services={
            "clara": "https://test-clara.vcc.internal",
            "covina": "https://test-covina.vcc.internal",
            "argus": "https://test-argus.vcc.internal", 
            "veritas": "https://test-veritas.vcc.internal",
            "vpb": "https://test-vpb.vcc.internal"
        },
        service_discovery_enabled=True,
        
        backup_enabled=True,
        dr_enabled=False,
        gdpr_compliance=True,
        ai_act_compliance=True,
        bsi_tr_compliance=True
    ),
    
    Environment.STAGING: VCCEnvironmentConfig(
        environment=Environment.STAGING,
        security_level=SecurityLevel.CONFIDENTIAL,
        
        database=DatabaseConfig(
            host="staging-db.vcc.internal",
            port=5432,
            password="${STAGING_DB_PASSWORD}",
            min_connections=10,
            max_connections=30,
            ssl_mode="require",
            ssl_cert_path="/etc/ssl/certs/pki-staging.crt",
            ssl_key_path="/etc/ssl/private/pki-staging.key",
            ssl_ca_path="/etc/ssl/certs/vcc-ca.crt",
            backup_enabled=True,
            backup_retention_days=30
        ),
        
        redis=RedisConfig(
            host="staging-redis.vcc.internal",
            port=6379,
            password="${STAGING_REDIS_PASSWORD}",
            ssl_enabled=True,
            ssl_cert_path="/etc/ssl/certs/redis-staging.crt",
            max_connections=50,
            cluster_enabled=True,
            cluster_nodes=[
                "staging-redis-1.vcc.internal:6379",
                "staging-redis-2.vcc.internal:6379"
            ]
        ),
        
        security=SecurityConfig(
            jwt_secret_key="${STAGING_JWT_SECRET}",
            jwt_algorithm="RS256",
            jwt_expiration_hours=12,
            min_password_length=12,
            password_expiry_days=60,
            rate_limit_requests=150,
            session_timeout_minutes=15,
            force_https=True,
            hsts_max_age=31536000,
            audit_all_requests=True,
            log_sensitive_data=False,
            retention_period_days=2555,
            cors_origins=["https://staging-pki.vcc.internal"]
        ),
        
        monitoring=MonitoringConfig(
            prometheus_enabled=True,
            prometheus_port=9090,
            grafana_enabled=True,
            grafana_port=3000,
            health_check_interval=15,
            alert_manager_url="https://alertmanager.vcc.internal",
            smtp_server="mail.vcc.internal",
            alert_email_recipients=[
                "pki-staging-alerts@vcc.brandenburg.de",
                "devops-team@vcc.brandenburg.de"
            ],
            log_level="INFO",
            log_format="json",
            apm_enabled=True,
            apm_service_name="vcc-pki-staging"
        ),
        
        network=NetworkConfig(
            bind_host="0.0.0.0",
            bind_port=8000,
            load_balancer_enabled=True,
            upstream_servers=[
                "staging-pki-1.vcc.internal:8000",
                "staging-pki-2.vcc.internal:8000"
            ],
            reverse_proxy_enabled=True,
            proxy_headers={"X-Forwarded-Proto": "https"},
            allowed_ips=["10.0.0.0/8", "172.16.0.0/12"],
            vpn_required=True,
            vpn_networks=["10.0.0.0/8", "172.16.0.0/12"]
        ),
        
        hsm_environment="thales_primary",  # Production-like HSM
        
        vcc_services={
            "clara": "https://staging-clara.vcc.internal",
            "covina": "https://staging-covina.vcc.internal",
            "argus": "https://staging-argus.vcc.internal",
            "veritas": "https://staging-veritas.vcc.internal", 
            "vpb": "https://staging-vpb.vcc.internal"
        },
        service_discovery_enabled=True,
        
        backup_enabled=True,
        dr_enabled=True,
        dr_site_url="https://dr-pki.vcc.internal",
        gdpr_compliance=True,
        ai_act_compliance=True,
        bsi_tr_compliance=True,
        audit_retention_years=7
    ),
    
    Environment.PRODUCTION: VCCEnvironmentConfig(
        environment=Environment.PRODUCTION,
        security_level=SecurityLevel.SECRET,
        
        database=DatabaseConfig(
            host="prod-db-cluster.vcc.internal",
            port=5432,
            password="${PROD_DB_PASSWORD}",
            min_connections=20,
            max_connections=100,
            connection_timeout=10,
            ssl_mode="require",
            ssl_cert_path="/etc/ssl/certs/pki-production.crt",
            ssl_key_path="/etc/ssl/private/pki-production.key", 
            ssl_ca_path="/etc/ssl/certs/vcc-root-ca.crt",
            backup_enabled=True,
            backup_retention_days=2555,  # 7 years
            backup_schedule="0 1,13 * * *",  # Twice daily
            slow_query_threshold=0.5,
            connection_monitoring=True
        ),
        
        redis=RedisConfig(
            host="prod-redis-cluster.vcc.internal",
            port=6379,
            password="${PROD_REDIS_PASSWORD}",
            ssl_enabled=True,
            ssl_cert_path="/etc/ssl/certs/redis-production.crt",
            max_connections=200,
            cluster_enabled=True,
            cluster_nodes=[
                "prod-redis-1.vcc.internal:6379",
                "prod-redis-2.vcc.internal:6379",
                "prod-redis-3.vcc.internal:6379",
                "prod-redis-4.vcc.internal:6379"
            ]
        ),
        
        security=SecurityConfig(
            jwt_secret_key="${PROD_JWT_SECRET}",
            jwt_algorithm="RS256",
            jwt_expiration_hours=8,  # Shorter for production
            jwt_refresh_expiration_days=1,
            min_password_length=16,
            require_special_chars=True,
            require_numbers=True,
            require_uppercase=True,
            password_expiry_days=30,  # Strict password rotation
            rate_limit_requests=50,   # Strict rate limiting
            rate_limit_window=3600,
            session_timeout_minutes=10,  # Short session timeout
            max_concurrent_sessions=2,
            force_https=True,
            hsts_max_age=63072000,  # 2 years
            api_key_expiry_days=90,
            audit_all_requests=True,
            log_sensitive_data=False,
            retention_period_days=2555,
            cors_origins=["https://pki.vcc.brandenburg.de"]
        ),
        
        monitoring=MonitoringConfig(
            prometheus_enabled=True,
            prometheus_port=9090,
            grafana_enabled=True,
            grafana_port=3000,
            health_check_interval=10,  # Frequent health checks
            health_check_timeout=3,
            alert_manager_url="https://alertmanager.vcc.brandenburg.de",
            smtp_server="secure-mail.vcc.internal",
            alert_email_recipients=[
                "pki-production-alerts@vcc.brandenburg.de",
                "security-operations@vcc.brandenburg.de",
                "infrastructure-team@vcc.brandenburg.de"
            ],
            log_level="WARN",  # Less verbose in production
            log_format="json",
            log_rotation_size="50MB",
            log_retention_days=2555,
            apm_enabled=True,
            apm_service_name="vcc-pki-production"
        ),
        
        network=NetworkConfig(
            bind_host="0.0.0.0",
            bind_port=8000,
            load_balancer_enabled=True,
            upstream_servers=[
                "prod-pki-1.vcc.internal:8000",
                "prod-pki-2.vcc.internal:8000",
                "prod-pki-3.vcc.internal:8000",
                "prod-pki-4.vcc.internal:8000"
            ],
            reverse_proxy_enabled=True,
            proxy_headers={
                "X-Forwarded-Proto": "https",
                "X-Real-IP": "$remote_addr",
                "X-Forwarded-For": "$proxy_add_x_forwarded_for"
            },
            allowed_ips=[
                "10.0.0.0/8",      # Internal VCC network
                "172.16.0.0/12",   # Management network
                "192.168.100.0/24" # Admin network
            ],
            vpn_required=True,
            vpn_networks=[
                "10.0.0.0/8",
                "172.16.0.0/12" 
            ]
        ),
        
        hsm_environment="thales_primary",
        
        vcc_services={
            "clara": "https://clara.vcc.brandenburg.de",
            "covina": "https://covina.vcc.brandenburg.de",
            "argus": "https://argus.vcc.brandenburg.de",
            "veritas": "https://veritas.vcc.brandenburg.de",
            "vpb": "https://vpb.vcc.brandenburg.de"
        },
        service_discovery_enabled=True,
        
        backup_enabled=True,
        dr_enabled=True,
        dr_site_url="https://dr-pki.vcc-backup.brandenburg.de",
        gdpr_compliance=True,
        ai_act_compliance=True,
        bsi_tr_compliance=True,
        audit_retention_years=10  # Extended retention for production
    ),
    
    Environment.DR_SITE: VCCEnvironmentConfig(
        environment=Environment.DR_SITE,
        security_level=SecurityLevel.SECRET,
        
        # Similar to production but with DR-specific configuration
        database=DatabaseConfig(
            host="dr-db-cluster.vcc-backup.internal",
            port=5432,
            password="${DR_DB_PASSWORD}",
            min_connections=10,
            max_connections=50,  # Lower capacity for DR
            ssl_mode="require",
            ssl_cert_path="/etc/ssl/certs/pki-dr.crt",
            ssl_key_path="/etc/ssl/private/pki-dr.key",
            ssl_ca_path="/etc/ssl/certs/vcc-root-ca.crt",
            backup_enabled=True,
            backup_retention_days=90
        ),
        
        redis=RedisConfig(
            host="dr-redis-cluster.vcc-backup.internal",
            port=6379,
            password="${DR_REDIS_PASSWORD}",
            ssl_enabled=True,
            max_connections=100,
            cluster_enabled=True,
            cluster_nodes=[
                "dr-redis-1.vcc-backup.internal:6379",
                "dr-redis-2.vcc-backup.internal:6379"
            ]
        ),
        
        security=SecurityConfig(
            jwt_secret_key="${DR_JWT_SECRET}",
            jwt_algorithm="RS256",
            jwt_expiration_hours=8,
            min_password_length=16,
            rate_limit_requests=50,
            session_timeout_minutes=10,
            force_https=True,
            audit_all_requests=True,
            log_sensitive_data=False,
            cors_origins=["https://dr-pki.vcc-backup.brandenburg.de"]
        ),
        
        monitoring=MonitoringConfig(
            prometheus_enabled=True,
            grafana_enabled=True,
            health_check_interval=15,
            alert_email_recipients=[
                "pki-dr-alerts@vcc.brandenburg.de",
                "disaster-recovery@vcc.brandenburg.de"
            ],
            log_level="INFO",
            apm_enabled=True,
            apm_service_name="vcc-pki-dr"
        ),
        
        network=NetworkConfig(
            bind_host="0.0.0.0", 
            bind_port=8000,
            load_balancer_enabled=True,
            upstream_servers=[
                "dr-pki-1.vcc-backup.internal:8000",
                "dr-pki-2.vcc-backup.internal:8000"
            ],
            allowed_ips=["10.1.0.0/8", "172.17.0.0/12"],  # DR network ranges
            vpn_required=True
        ),
        
        hsm_environment="utimaco_backup",  # Backup HSM
        
        vcc_services={
            "clara": "https://dr-clara.vcc-backup.internal",
            "covina": "https://dr-covina.vcc-backup.internal",
            "argus": "https://dr-argus.vcc-backup.internal",
            "veritas": "https://dr-veritas.vcc-backup.internal",
            "vpb": "https://dr-vpb.vcc-backup.internal"
        },
        
        backup_enabled=False,  # DR site doesn't backup to itself
        dr_enabled=False,      # DR site is the DR
        gdpr_compliance=True,
        ai_act_compliance=True,
        bsi_tr_compliance=True
    )
}

class VCCEnvironmentManager:
    """VCC PKI Environment Configuration Manager"""
    
    def __init__(self, environment: Optional[str] = None):
        self.environment = self._detect_environment(environment)
        self.config = self._load_configuration()
        self._validate_configuration()
        
    def _detect_environment(self, env_override: Optional[str] = None) -> Environment:
        """Detect current environment"""
        
        if env_override:
            try:
                return Environment(env_override.lower())
            except ValueError:
                logger.warning(f"Invalid environment override: {env_override}")
        
        # Check environment variable
        env_var = os.getenv("VCC_PKI_ENVIRONMENT", "development").lower()
        
        try:
            return Environment(env_var)
        except ValueError:
            logger.warning(f"Invalid environment in VCC_PKI_ENVIRONMENT: {env_var}")
            return Environment.DEVELOPMENT
    
    def _load_configuration(self) -> VCCEnvironmentConfig:
        """Load configuration for current environment"""
        
        config = ENVIRONMENT_CONFIGS.get(self.environment)
        if not config:
            raise ValueError(f"No configuration found for environment: {self.environment}")
        
        # Substitute environment variables
        self._substitute_environment_variables(config)
        
        return config
    
    def _substitute_environment_variables(self, config: VCCEnvironmentConfig):
        """Replace environment variable placeholders with actual values"""
        
        # Database password
        if config.database.password.startswith("${"):
            env_var = config.database.password[2:-1]
            config.database.password = os.getenv(env_var, "default_password")
        
        # Redis password
        if config.redis.password and config.redis.password.startswith("${"):
            env_var = config.redis.password[2:-1]
            config.redis.password = os.getenv(env_var)
        
        # JWT secret
        if config.security.jwt_secret_key.startswith("${"):
            env_var = config.security.jwt_secret_key[2:-1]
            config.security.jwt_secret_key = os.getenv(env_var, "default_jwt_secret")
    
    def _validate_configuration(self):
        """Validate environment configuration"""
        
        errors = []
        
        # Production security validation
        if self.environment == Environment.PRODUCTION:
            if "default" in self.config.database.password.lower():
                errors.append("Production database password cannot be default")
            
            if "default" in self.config.security.jwt_secret_key.lower():
                errors.append("Production JWT secret cannot be default")
            
            if not self.config.security.force_https:
                errors.append("HTTPS must be forced in production")
            
            if self.config.security.log_sensitive_data:
                errors.append("Sensitive data logging must be disabled in production")
        
        # Network validation
        if self.config.network.vpn_required and not self.config.network.vpn_networks:
            errors.append("VPN networks must be specified when VPN is required")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def get_database_url(self) -> str:
        """Get database connection URL"""
        db = self.config.database
        return f"postgresql://{db.username}:{db.password}@{db.host}:{db.port}/{db.database}"
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL"""
        redis = self.config.redis
        
        if redis.ssl_enabled:
            scheme = "rediss"
        else:
            scheme = "redis"
        
        if redis.password:
            return f"{scheme}://:{redis.password}@{redis.host}:{redis.port}/{redis.database}"
        else:
            return f"{scheme}://{redis.host}:{redis.port}/{redis.database}"
    
    def get_vcc_service_url(self, service_name: str) -> Optional[str]:
        """Get VCC service URL"""
        return self.config.vcc_services.get(service_name.lower())
    
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment == Environment.PRODUCTION
    
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment == Environment.DEVELOPMENT
    
    def export_config(self, format_type: str = "yaml") -> str:
        """Export configuration in specified format"""
        
        config_dict = {
            "environment": self.environment.value,
            "security_level": self.config.security_level.value,
            "database": {
                "host": self.config.database.host,
                "port": self.config.database.port,
                "database": self.config.database.database,
                "ssl_mode": self.config.database.ssl_mode,
                "backup_enabled": self.config.database.backup_enabled
            },
            "security": {
                "jwt_algorithm": self.config.security.jwt_algorithm,
                "min_password_length": self.config.security.min_password_length,
                "force_https": self.config.security.force_https,
                "audit_enabled": self.config.security.audit_all_requests
            },
            "hsm_environment": self.config.hsm_environment,
            "vcc_services": self.config.vcc_services,
            "compliance": {
                "gdpr": self.config.gdpr_compliance,
                "ai_act": self.config.ai_act_compliance,
                "bsi_tr": self.config.bsi_tr_compliance
            }
        }
        
        if format_type.lower() == "yaml":
            return yaml.dump(config_dict, default_flow_style=False)
        elif format_type.lower() == "json":
            return json.dumps(config_dict, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

# Global Environment Manager
_env_manager = None

def get_environment_manager(environment: Optional[str] = None) -> VCCEnvironmentManager:
    """Get global environment manager instance"""
    global _env_manager
    
    if _env_manager is None or environment:
        _env_manager = VCCEnvironmentManager(environment)
        logger.info(f"Environment Manager initialized: {_env_manager.environment.value}")
    
    return _env_manager

def get_current_environment() -> Environment:
    """Get current environment"""
    return get_environment_manager().environment

def get_database_url() -> str:
    """Get database URL for current environment"""
    return get_environment_manager().get_database_url()

def get_redis_url() -> str:
    """Get Redis URL for current environment"""
    return get_environment_manager().get_redis_url()

def is_production() -> bool:
    """Check if running in production"""
    return get_environment_manager().is_production()

if __name__ == "__main__":
    # Test environment configuration
    try:
        env_manager = get_environment_manager("development")
        
        print("VCC PKI Environment Configuration")
        print("=" * 50)
        print(f"Environment: {env_manager.environment.value}")
        print(f"Security Level: {env_manager.config.security_level.value}")
        print(f"HSM Environment: {env_manager.config.hsm_environment}")
        print(f"Database URL: {env_manager.get_database_url()}")
        print(f"Redis URL: {env_manager.get_redis_url()}")
        print()
        print("VCC Services:")
        for service, url in env_manager.config.vcc_services.items():
            print(f"  {service}: {url}")
        
        print("\nConfiguration Export (YAML):")
        print(env_manager.export_config("yaml"))
        
    except Exception as e:
        print(f"Environment Configuration Error: {e}")