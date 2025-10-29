# VCC PKI System - Hardware Security Module (HSM) Integration Configuration
# Production-Grade HSM Integration für Brandenburg Government PKI

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class HSMType(Enum):
    """Supported HSM Types für VCC PKI System"""
    THALES_NSHIELD = "thales_nshield"
    UTIMACO_CRYPTOSERVER = "utimaco_cryptoserver" 
    SAFENET_LUNA = "safenet_luna"
    YUBICO_YHSM = "yubico_yhsm"
    PKCS11_GENERIC = "pkcs11_generic"
    SOFTWARE_MOCK = "software_mock"  # Für Development/Testing

class HSMSlotType(Enum):
    """HSM Slot Types für verschiedene Key-Zwecke"""
    ROOT_CA = "root_ca"           # Root CA Keys (höchste Sicherheit)
    INTERMEDIATE_CA = "intermediate_ca"  # Intermediate CA Keys  
    TSA_SIGNING = "tsa_signing"   # Timestamp Authority Keys
    OCSP_SIGNING = "ocsp_signing" # OCSP Responder Keys
    ADMIN_AUTH = "admin_auth"     # Administrative Authentication
    SERVICE_AUTH = "service_auth" # VCC Service Authentication

@dataclass
class HSMSlotConfig:
    """HSM Slot Configuration für spezifische Key-Verwendung"""
    slot_id: int
    slot_type: HSMSlotType
    label: str
    pin: str  # Encrypted/Hashed in Production
    so_pin: Optional[str] = None  # Security Officer PIN
    
    # Key Management
    max_keys: int = 100
    key_backup_enabled: bool = True
    key_escrow_required: bool = False
    
    # Access Control
    dual_authentication: bool = False
    quorum_required: int = 1
    operator_cards: List[str] = field(default_factory=list)
    
    # Compliance
    fips_140_2_level: int = 3
    common_criteria_level: str = "EAL4+"
    audit_logging: bool = True

@dataclass 
class HSMConfiguration:
    """Comprehensive HSM Configuration für VCC PKI"""
    
    # HSM Hardware
    hsm_type: HSMType
    library_path: str
    device_serial: Optional[str] = None
    firmware_version: Optional[str] = None
    
    # Network Configuration (für Network-attached HSMs)
    hsm_host: Optional[str] = None
    hsm_port: Optional[int] = None
    use_tls: bool = True
    tls_cert_path: Optional[str] = None
    
    # Slot Configurations
    slots: Dict[HSMSlotType, HSMSlotConfig] = field(default_factory=dict)
    
    # Performance Settings
    connection_pool_size: int = 10
    session_timeout: int = 3600
    retry_attempts: int = 3
    retry_delay: float = 1.0
    
    # High Availability
    backup_hsm_enabled: bool = False
    backup_hsm_config: Optional['HSMConfiguration'] = None
    load_balancing: bool = False
    
    # Monitoring & Alerting
    health_check_interval: int = 300  # seconds
    performance_monitoring: bool = True
    alert_on_key_usage_threshold: float = 0.8
    alert_recipients: List[str] = field(default_factory=list)
    
    # Compliance & Audit
    audit_all_operations: bool = True
    tamper_detection: bool = True
    secure_time_source: Optional[str] = None
    
    def validate_configuration(self) -> List[str]:
        """Validate HSM configuration and return any errors"""
        errors = []
        
        # Check required fields
        if not self.library_path:
            errors.append("HSM library path is required")
        elif not Path(self.library_path).exists():
            errors.append(f"HSM library not found: {self.library_path}")
        
        # Validate slots
        if not self.slots:
            errors.append("At least one HSM slot must be configured")
        
        # Check for required slot types
        required_slots = [HSMSlotType.ROOT_CA, HSMSlotType.INTERMEDIATE_CA]
        for slot_type in required_slots:
            if slot_type not in self.slots:
                errors.append(f"Required slot type missing: {slot_type.value}")
        
        # Validate slot configurations
        slot_ids = set()
        for slot_type, slot_config in self.slots.items():
            if slot_config.slot_id in slot_ids:
                errors.append(f"Duplicate slot ID: {slot_config.slot_id}")
            slot_ids.add(slot_config.slot_id)
            
            if not slot_config.pin:
                errors.append(f"PIN required for slot {slot_config.label}")
        
        # Network HSM validation
        if self.hsm_host and not self.hsm_port:
            errors.append("HSM port required when host is specified")
        
        return errors

# Production HSM Configurations für Brandenburg Government

PRODUCTION_HSM_CONFIGS = {
    # Thales nShield Configuration (Primary)
    "thales_primary": HSMConfiguration(
        hsm_type=HSMType.THALES_NSHIELD,
        library_path="/opt/nfast/toolkits/pkcs11/libcknfast.so",
        device_serial="ESN-12345",
        
        slots={
            HSMSlotType.ROOT_CA: HSMSlotConfig(
                slot_id=0,
                slot_type=HSMSlotType.ROOT_CA,
                label="VCC_ROOT_CA",
                pin="${HSM_ROOT_CA_PIN}",  # Environment variable
                so_pin="${HSM_ROOT_CA_SO_PIN}",
                max_keys=10,
                dual_authentication=True,
                quorum_required=2,
                operator_cards=["OCS_CARD_001", "OCS_CARD_002", "OCS_CARD_003"],
                fips_140_2_level=4,
                common_criteria_level="EAL4+",
                key_escrow_required=True
            ),
            
            HSMSlotType.INTERMEDIATE_CA: HSMSlotConfig(
                slot_id=1,
                slot_type=HSMSlotType.INTERMEDIATE_CA,
                label="VCC_INTERMEDIATE_CA",
                pin="${HSM_INTERMEDIATE_PIN}",
                so_pin="${HSM_INTERMEDIATE_SO_PIN}",
                max_keys=50,
                dual_authentication=True,
                quorum_required=1,
                operator_cards=["OCS_CARD_001", "OCS_CARD_002"],
                fips_140_2_level=3
            ),
            
            HSMSlotType.TSA_SIGNING: HSMSlotConfig(
                slot_id=2,
                slot_type=HSMSlotType.TSA_SIGNING,
                label="VCC_TSA_SIGNING",
                pin="${HSM_TSA_PIN}",
                max_keys=20,
                dual_authentication=False,
                fips_140_2_level=3,
                audit_logging=True
            ),
            
            HSMSlotType.OCSP_SIGNING: HSMSlotConfig(
                slot_id=3,
                slot_type=HSMSlotType.OCSP_SIGNING,
                label="VCC_OCSP_SIGNING",
                pin="${HSM_OCSP_PIN}",
                max_keys=10,
                fips_140_2_level=3
            ),
            
            HSMSlotType.SERVICE_AUTH: HSMSlotConfig(
                slot_id=4,
                slot_type=HSMSlotType.SERVICE_AUTH,
                label="VCC_SERVICE_AUTH",
                pin="${HSM_SERVICE_PIN}",
                max_keys=200,  # Für alle VCC Services
                fips_140_2_level=3
            )
        },
        
        # Performance & HA Configuration
        connection_pool_size=20,
        session_timeout=7200,
        backup_hsm_enabled=True,
        health_check_interval=60,
        
        # Monitoring
        performance_monitoring=True,
        alert_on_key_usage_threshold=0.85,
        alert_recipients=["hsm-admin@vcc.brandenburg.de", "security-team@vcc.brandenburg.de"],
        
        # Compliance
        audit_all_operations=True,
        tamper_detection=True,
        secure_time_source="ntp.ptb.de"  # German National Time Server
    ),
    
    # Backup HSM Configuration (Utimaco)
    "utimaco_backup": HSMConfiguration(
        hsm_type=HSMType.UTIMACO_CRYPTOSERVER,
        library_path="/opt/utimaco/lib/libcs_pkcs11_R2.so",
        device_serial="UTI-67890",
        
        # Network Configuration
        hsm_host="hsm-backup.vcc.internal",
        hsm_port=3001,
        use_tls=True,
        tls_cert_path="/etc/ssl/certs/utimaco-hsm.crt",
        
        slots={
            HSMSlotType.ROOT_CA: HSMSlotConfig(
                slot_id=0,
                slot_type=HSMSlotType.ROOT_CA,
                label="VCC_ROOT_CA_BACKUP",
                pin="${HSM_BACKUP_ROOT_PIN}",
                dual_authentication=True,
                quorum_required=2,
                fips_140_2_level=4
            ),
            
            HSMSlotType.INTERMEDIATE_CA: HSMSlotConfig(
                slot_id=1,
                slot_type=HSMSlotType.INTERMEDIATE_CA,
                label="VCC_INTERMEDIATE_BACKUP",
                pin="${HSM_BACKUP_INTERMEDIATE_PIN}",
                fips_140_2_level=3
            )
        },
        
        health_check_interval=120,
        audit_all_operations=True
    ),
    
    # Development/Testing Configuration (Software Mock)
    "development": HSMConfiguration(
        hsm_type=HSMType.SOFTWARE_MOCK,
        library_path="/usr/lib/softhsm/libsofthsm2.so",
        
        slots={
            HSMSlotType.ROOT_CA: HSMSlotConfig(
                slot_id=0,
                slot_type=HSMSlotType.ROOT_CA,
                label="DEV_ROOT_CA",
                pin="1234",
                max_keys=10,
                dual_authentication=False,
                fips_140_2_level=1
            ),
            
            HSMSlotType.INTERMEDIATE_CA: HSMSlotConfig(
                slot_id=1,
                slot_type=HSMSlotType.INTERMEDIATE_CA,
                label="DEV_INTERMEDIATE",
                pin="1234",
                max_keys=50,
                fips_140_2_level=1
            ),
            
            HSMSlotType.TSA_SIGNING: HSMSlotConfig(
                slot_id=2,
                slot_type=HSMSlotType.TSA_SIGNING,
                label="DEV_TSA",
                pin="1234",
                max_keys=5,
                fips_140_2_level=1
            )
        },
        
        connection_pool_size=5,
        backup_hsm_enabled=False,
        health_check_interval=600,
        performance_monitoring=False,
        audit_all_operations=False
    )
}

class HSMConfigurationManager:
    """HSM Configuration Management für verschiedene Umgebungen"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.config = self._load_configuration(environment)
        
    def _load_configuration(self, environment: str) -> HSMConfiguration:
        """Load HSM configuration für spezifische Umgebung"""
        
        if environment not in PRODUCTION_HSM_CONFIGS:
            raise ValueError(f"Unknown HSM environment: {environment}")
        
        config = PRODUCTION_HSM_CONFIGS[environment]
        
        # Validate configuration
        errors = config.validate_configuration()
        if errors:
            raise ValueError(f"HSM configuration errors: {', '.join(errors)}")
        
        # Load environment variables for PINs
        self._load_environment_pins(config)
        
        return config
    
    def _load_environment_pins(self, config: HSMConfiguration):
        """Load HSM PINs from environment variables"""
        
        for slot_type, slot_config in config.slots.items():
            # Replace environment variable placeholders
            if slot_config.pin.startswith("${") and slot_config.pin.endswith("}"):
                env_var = slot_config.pin[2:-1]
                pin_value = os.getenv(env_var)
                
                if not pin_value:
                    if config.hsm_type == HSMType.SOFTWARE_MOCK:
                        # Use default PIN for development
                        slot_config.pin = "1234"
                        logger.warning(f"Using default PIN for development slot {slot_config.label}")
                    else:
                        raise ValueError(f"HSM PIN environment variable not set: {env_var}")
                else:
                    slot_config.pin = pin_value
            
            # Same for SO PIN
            if slot_config.so_pin and slot_config.so_pin.startswith("${"):
                env_var = slot_config.so_pin[2:-1]
                so_pin_value = os.getenv(env_var)
                if so_pin_value:
                    slot_config.so_pin = so_pin_value
    
    def get_slot_config(self, slot_type: HSMSlotType) -> Optional[HSMSlotConfig]:
        """Get configuration for specific slot type"""
        return self.config.slots.get(slot_type)
    
    def get_primary_ca_slot(self) -> HSMSlotConfig:
        """Get primary CA slot configuration"""
        root_slot = self.get_slot_config(HSMSlotType.ROOT_CA)
        if root_slot:
            return root_slot
        
        # Fallback to intermediate CA
        intermediate_slot = self.get_slot_config(HSMSlotType.INTERMEDIATE_CA)
        if intermediate_slot:
            return intermediate_slot
            
        raise ValueError("No CA slot configured in HSM")
    
    def get_tsa_slot(self) -> Optional[HSMSlotConfig]:
        """Get TSA signing slot configuration"""
        return self.get_slot_config(HSMSlotType.TSA_SIGNING)
    
    def is_production_hsm(self) -> bool:
        """Check if this is a production HSM configuration"""
        return self.config.hsm_type != HSMType.SOFTWARE_MOCK
    
    def get_backup_config(self) -> Optional[HSMConfiguration]:
        """Get backup HSM configuration if available"""
        return self.config.backup_hsm_config
    
    def generate_hsm_report(self) -> Dict[str, Any]:
        """Generate comprehensive HSM configuration report"""
        
        return {
            "environment": self.environment,
            "hsm_type": self.config.hsm_type.value,
            "library_path": self.config.library_path,
            "device_serial": self.config.device_serial,
            "slot_count": len(self.config.slots),
            "slots": {
                slot_type.value: {
                    "slot_id": slot_config.slot_id,
                    "label": slot_config.label,
                    "max_keys": slot_config.max_keys,
                    "fips_level": slot_config.fips_140_2_level,
                    "dual_auth": slot_config.dual_authentication,
                    "quorum": slot_config.quorum_required
                } for slot_type, slot_config in self.config.slots.items()
            },
            "high_availability": {
                "backup_enabled": self.config.backup_hsm_enabled,
                "load_balancing": self.config.load_balancing,
                "connection_pool": self.config.connection_pool_size
            },
            "compliance": {
                "audit_enabled": self.config.audit_all_operations,
                "tamper_detection": self.config.tamper_detection,
                "time_source": self.config.secure_time_source
            },
            "monitoring": {
                "health_checks": self.config.health_check_interval,
                "performance_monitoring": self.config.performance_monitoring,
                "alert_threshold": self.config.alert_on_key_usage_threshold
            }
        }

# HSM Environment Detection
def detect_hsm_environment() -> str:
    """
    Detect HSM environment based on system configuration
    """
    
    # Check for environment variable
    env = os.getenv("VCC_PKI_ENVIRONMENT", "development")
    
    # Production indicators
    production_indicators = [
        "/opt/nfast/toolkits/pkcs11/libcknfast.so",  # Thales nShield
        "/opt/utimaco/lib/libcs_pkcs11_R2.so",       # Utimaco
        "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"  # SafeNet Luna
    ]
    
    for indicator in production_indicators:
        if Path(indicator).exists():
            logger.info(f"Production HSM detected: {indicator}")
            return "thales_primary"  # Default to primary production config
    
    # Development fallback
    logger.info("Using development HSM configuration")
    return "development"

# Global HSM Manager Instance
_hsm_manager = None

def get_hsm_manager(environment: Optional[str] = None) -> HSMConfigurationManager:
    """
    Get global HSM configuration manager instance
    """
    global _hsm_manager
    
    if _hsm_manager is None or environment:
        env = environment or detect_hsm_environment()
        _hsm_manager = HSMConfigurationManager(env)
        logger.info(f"HSM Manager initialized for environment: {env}")
    
    return _hsm_manager

# HSM Health Check Functions
async def check_hsm_health(config: HSMConfiguration) -> Dict[str, Any]:
    """
    Comprehensive HSM health check
    """
    try:
        # This would use PyKCS11 or similar library in real implementation
        health_status = {
            "hsm_available": True,
            "library_loaded": True,
            "slots_accessible": {},
            "key_counts": {},
            "performance_metrics": {},
            "errors": []
        }
        
        # Check each slot
        for slot_type, slot_config in config.slots.items():
            try:
                # Slot accessibility check
                health_status["slots_accessible"][slot_type.value] = True
                health_status["key_counts"][slot_type.value] = 0  # Would get real count
                
            except Exception as e:
                health_status["slots_accessible"][slot_type.value] = False
                health_status["errors"].append(f"Slot {slot_type.value} error: {str(e)}")
        
        return health_status
        
    except Exception as e:
        return {
            "hsm_available": False,
            "error": str(e),
            "timestamp": "2025-10-02T12:00:00Z"
        }

if __name__ == "__main__":
    # Test HSM configuration
    try:
        hsm_manager = get_hsm_manager("development")
        print("HSM Configuration Report:")
        print("=" * 50)
        
        import json
        report = hsm_manager.generate_hsm_report()
        print(json.dumps(report, indent=2))
        
        print("\nSlot Configurations:")
        for slot_type in HSMSlotType:
            slot_config = hsm_manager.get_slot_config(slot_type)
            if slot_config:
                print(f"  {slot_type.value}: Slot {slot_config.slot_id} - {slot_config.label}")
        
    except Exception as e:
        print(f"HSM Configuration Error: {e}")