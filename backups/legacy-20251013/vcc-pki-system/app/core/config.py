# VCC PKI System - Configuration Management
# Centralized configuration for all PKI operations

import os
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import json

class VCCPKIConfig(BaseSettings):
    """Production-ready configuration for VCC PKI System"""
    
    # Database Configuration
    database_path: str = Field(default="data/vcc_pki.db", description="SQLite database path")
    database_encryption_key: Optional[str] = Field(default=None, description="Database encryption key")
    
    # PKI Configuration
    organization_name: str = Field(default="Brandenburg Government", description="Default organization")
    organization_id: str = Field(default="brandenburg-gov", description="Default organization ID")
    country_code: str = Field(default="DE", description="Country code for certificates")
    state_name: str = Field(default="Brandenburg", description="State/Province name")
    
    # Root CA Configuration
    root_ca_key_size: int = Field(default=4096, description="Root CA key size in bits")
    root_ca_validity_years: int = Field(default=20, description="Root CA validity in years")
    root_ca_algorithm: str = Field(default="RSA", description="Root CA key algorithm")
    
    # Issuing CA Configuration
    issuing_ca_key_size: int = Field(default=2048, description="Issuing CA key size in bits")
    issuing_ca_validity_years: int = Field(default=10, description="Issuing CA validity in years")
    
    # Service Certificate Configuration
    service_cert_validity_days: int = Field(default=365, description="Service certificate validity in days")
    code_signing_cert_validity_days: int = Field(default=1095, description="Code signing certificate validity in days") # 3 years
    admin_cert_validity_days: int = Field(default=730, description="Admin certificate validity in days") # 2 years
    
    # Auto-renewal Configuration
    auto_renewal_enabled: bool = Field(default=True, description="Enable automatic certificate renewal")
    renewal_threshold_days: int = Field(default=30, description="Days before expiry to trigger renewal")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API host address")
    api_port: int = Field(default=12091, description="API port")
    api_workers: int = Field(default=4, description="Number of API workers")
    
    # Security Configuration
    require_mtls: bool = Field(default=True, description="Require mTLS for service communication")
    hsm_enabled: bool = Field(default=False, description="Use Hardware Security Module")
    hsm_pkcs11_lib: Optional[str] = Field(default=None, description="PKCS#11 library path for HSM")
    
    # VCC Service Discovery
    service_discovery_enabled: bool = Field(default=True, description="Enable automatic service discovery")
    service_discovery_interval: int = Field(default=60, description="Service discovery interval in seconds")
    vcc_service_networks: list = Field(default=["172.20.0.0/16", "10.0.0.0/8"], description="Networks to scan for VCC services")
    
    # Logging and Monitoring
    log_level: str = Field(default="INFO", description="Logging level")
    audit_enabled: bool = Field(default=True, description="Enable audit logging")
    compliance_mode: bool = Field(default=True, description="Enable GDPR/AI Act compliance features")
    
    # File Paths
    certificates_path: str = Field(default="certificates", description="Directory for certificate storage")
    private_keys_path: str = Field(default="private_keys", description="Directory for private key storage")
    crl_path: str = Field(default="crl", description="Directory for CRL storage")
    backups_path: str = Field(default="backups", description="Directory for backups")
    
    # Security Configuration
    jwt_secret_key: str = Field(default="vcc-pki-development-secret-change-in-production", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30, description="Access token expiration in minutes")
    refresh_token_expire_days: int = Field(default=7, description="Refresh token expiration in days")
    
    # Keycloak Configuration (Production)
    keycloak_url: Optional[str] = Field(default=None, description="Keycloak server URL")
    keycloak_realm: str = Field(default="vcc", description="Keycloak realm")
    keycloak_client_id: str = Field(default="vcc-pki", description="Keycloak client ID")
    keycloak_client_secret: Optional[str] = Field(default=None, description="Keycloak client secret")
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, description="Enable API rate limiting")
    rate_limit_requests_per_minute: int = Field(default=60, description="Rate limit: requests per minute")
    
    # Mock/Development Configuration
    mock_mode: bool = Field(default=True, description="Enable mock mode for development")
    mock_vcc_services: bool = Field(default=True, description="Create mock VCC services")
    mock_hsm: bool = Field(default=True, description="Use mock HSM for development")
    
    class Config:
        env_prefix = "VCC_PKI_"
        env_file = ".env"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure all required directories exist"""
        directories = [
            self.certificates_path,
            self.private_keys_path, 
            self.crl_path,
            self.backups_path,
            Path(self.database_path).parent
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get_ca_subject(self, ca_type: str, ca_name: str) -> Dict[str, str]:
        """Generate CA subject DN"""
        return {
            "country_name": self.country_code,
            "state_or_province_name": self.state_name,
            "organization_name": self.organization_name,
            "organizational_unit_name": f"VCC PKI - {ca_type.title()} CA",
            "common_name": ca_name
        }
    
    def get_service_subject(self, service_name: str, service_type: str) -> Dict[str, str]:
        """Generate service certificate subject DN"""
        return {
            "country_name": self.country_code,
            "state_or_province_name": self.state_name, 
            "organization_name": self.organization_name,
            "organizational_unit_name": f"VCC Services - {service_type.title()}",
            "common_name": f"{service_name}.vcc.{self.organization_id}"
        }
    
    def get_vcc_service_config(self) -> Dict[str, Any]:
        """Get VCC service-specific configuration"""
        return {
            "argus": {
                "service_type": "api",
                "default_port": 12091,
                "health_endpoint": "/health",
                "requires_high_security": False,
                "public_facing": True,
                "mtls_required": True
            },
            "covina": {
                "service_type": "orchestrator", 
                "default_port": 8001,
                "health_endpoint": "/api/health",
                "requires_high_security": True,
                "public_facing": False,
                "mtls_required": True,
                "worker_signing_required": True
            },
            "clara": {
                "service_type": "processor",
                "default_port": 8002,
                "health_endpoint": "/status",
                "requires_high_security": True,
                "public_facing": False,
                "mtls_required": True,
                "model_signing_required": True
            },
            "veritas": {
                "service_type": "orchestrator",
                "default_port": 8003,
                "health_endpoint": "/health", 
                "requires_high_security": True,
                "public_facing": False,
                "mtls_required": True,
                "pipeline_signing_required": True
            },
            "vpb": {
                "service_type": "ui",
                "default_port": 8004,
                "health_endpoint": "/api/status",
                "requires_high_security": False,
                "public_facing": True,
                "mtls_required": True,
                "asset_signing_enabled": True
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            field_name: getattr(self, field_name)
            for field_name in self.__fields__.keys()
        }
    
    def save_config(self, file_path: str = "config/vcc_pki_config.json"):
        """Save configuration to file"""
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    @classmethod
    def load_config(cls, file_path: str = "config/vcc_pki_config.json") -> 'VCCPKIConfig':
        """Load configuration from file"""
        if Path(file_path).exists():
            with open(file_path, 'r') as f:
                config_data = json.load(f)
            return cls(**config_data)
        else:
            # Return default configuration
            return cls()

# Global configuration instance
config = VCCPKIConfig()

# Environment-specific configurations
def get_production_config() -> VCCPKIConfig:
    """Get production configuration"""
    return VCCPKIConfig(
        mock_mode=False,
        mock_vcc_services=False,
        mock_hsm=False,
        hsm_enabled=True,
        log_level="WARNING",
        api_host="0.0.0.0",
        database_path="/secure/vcc_pki/database/vcc_pki.db",
        certificates_path="/secure/vcc_pki/certificates",
        private_keys_path="/secure/vcc_pki/private_keys",
        backups_path="/secure/vcc_pki/backups"
    )

def get_development_config() -> VCCPKIConfig:
    """Get development configuration"""  
    return VCCPKIConfig(
        mock_mode=True,
        mock_vcc_services=True,
        mock_hsm=True,
        hsm_enabled=False,
        log_level="DEBUG",
        api_host="127.0.0.1",
        database_path="data/vcc_pki_dev.db"
    )

def get_test_config() -> VCCPKIConfig:
    """Get test configuration"""
    return VCCPKIConfig(
        mock_mode=True,
        mock_vcc_services=True, 
        mock_hsm=True,
        hsm_enabled=False,
        log_level="DEBUG",
        database_path=":memory:",  # In-memory database for tests
        auto_renewal_enabled=False  # Disable for predictable tests
    )

# Configuration factory
def create_config(environment: str = None) -> VCCPKIConfig:
    """Create configuration based on environment"""
    environment = environment or os.getenv("VCC_PKI_ENVIRONMENT", "development")
    
    if environment == "production":
        return get_production_config()
    elif environment == "test":
        return get_test_config()
    else:
        return get_development_config()

if __name__ == "__main__":
    # Test configuration
    print("🔧 VCC PKI Configuration Test")
    print("=" * 40)
    
    # Test different environments
    for env in ["development", "test", "production"]:
        print(f"\n{env.title()} Configuration:")
        cfg = create_config(env)
        print(f"   Mock Mode: {cfg.mock_mode}")
        print(f"   Database: {cfg.database_path}")
        print(f"   API Port: {cfg.api_port}")
        print(f"   HSM Enabled: {cfg.hsm_enabled}")
    
    # Test VCC service configuration
    print(f"\nVCC Services Configuration:")
    cfg = create_config("development")
    services = cfg.get_vcc_service_config()
    for service_name, service_config in services.items():
        print(f"   {service_name}: Port {service_config['default_port']}, Security: {service_config['requires_high_security']}")
    
    # Save configuration example
    cfg.save_config("config_example.json")
    print(f"\n✅ Configuration saved to config_example.json")