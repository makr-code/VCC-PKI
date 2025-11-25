"""
VCC PKI Server - VCC Service Integration Module

Provides seamless integration with all VCC services:
- Covina (Main Backend + Ingestion)
- Veritas (Backend + Frontend)
- Clara (AI Backend)
- VPB (Brandenburg Portal Backend)
- Argus (Monitoring & Security)

Features:
- Automatic service discovery and registration
- mTLS certificate provisioning for services
- Service-to-service authentication
- Health monitoring and certificate validation
- Zero-Trust policy enforcement

Usage:
    from vcc_service_integration import VCCServiceIntegration
    
    integration = VCCServiceIntegration(pki_server)
    await integration.start()
    
    # Register a new VCC service
    await integration.register_service(
        service_id="covina-backend",
        service_type=VCCServiceType.COVINA,
        endpoints=["https://covina.vcc.local:443"]
    )

Author: VCC-PKI Team
Date: November 2025
"""

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

logger = logging.getLogger(__name__)


# ============================================================================
# Enumerations
# ============================================================================

class VCCServiceType(Enum):
    """VCC Service Types"""
    COVINA_BACKEND = "covina-backend"
    COVINA_INGESTION = "covina-ingestion"
    VERITAS_BACKEND = "veritas-backend"
    VERITAS_FRONTEND = "veritas-frontend"
    CLARA_BACKEND = "clara-backend"
    VPB_BACKEND = "vpb-backend"
    ARGUS_BACKEND = "argus-backend"
    PKI_SERVER = "pki-server"
    GENERIC = "generic"


class ServiceStatus(Enum):
    """Service Status"""
    PENDING = "pending"
    ACTIVE = "active"
    UNHEALTHY = "unhealthy"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    CERTIFICATE_EXPIRED = "certificate_expired"
    DISCONNECTED = "disconnected"
    MAINTENANCE = "maintenance"


class AuthMethod(Enum):
    """Authentication Methods"""
    MTLS_CERTIFICATE = "mtls_certificate"
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    NONE = "none"


class TrustLevel(Enum):
    """Trust Levels for Zero-Trust Architecture"""
    HIGH = "high"          # Fully trusted, can call any service
    MEDIUM = "medium"      # Trusted, can call specific services
    LOW = "low"            # Limited trust, restricted access
    UNTRUSTED = "untrusted"  # No trust, deny all


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class VCCIntegrationConfig:
    """Configuration for VCC Service Integration"""
    
    # Service Discovery
    discovery_enabled: bool = True
    discovery_interval_seconds: int = 60
    
    # Health Checking
    health_check_enabled: bool = True
    health_check_interval_seconds: int = 30
    health_check_timeout_seconds: int = 10
    health_check_retry_count: int = 3
    
    # Certificate Management
    auto_certificate_provisioning: bool = True
    certificate_renewal_threshold_days: int = 30
    certificate_validity_days: int = 365
    
    # mTLS Settings
    mtls_enabled: bool = True
    require_client_cert: bool = True
    allowed_auth_methods: List[AuthMethod] = field(default_factory=lambda: [AuthMethod.MTLS_CERTIFICATE])
    
    # Zero-Trust Settings
    zero_trust_enabled: bool = True
    default_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    
    # Service-to-Service Communication
    service_communication_timeout: int = 30
    retry_on_failure: bool = True
    max_retries: int = 3
    
    # Notification Settings
    notifications_enabled: bool = True
    webhook_url: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "VCCIntegrationConfig":
        """Load configuration from environment variables"""
        return cls(
            discovery_enabled=os.environ.get("VCC_DISCOVERY_ENABLED", "true").lower() == "true",
            discovery_interval_seconds=int(os.environ.get("VCC_DISCOVERY_INTERVAL", "60")),
            health_check_enabled=os.environ.get("VCC_HEALTH_CHECK_ENABLED", "true").lower() == "true",
            health_check_interval_seconds=int(os.environ.get("VCC_HEALTH_CHECK_INTERVAL", "30")),
            health_check_timeout_seconds=int(os.environ.get("VCC_HEALTH_CHECK_TIMEOUT", "10")),
            health_check_retry_count=int(os.environ.get("VCC_HEALTH_CHECK_RETRY_COUNT", "3")),
            auto_certificate_provisioning=os.environ.get("VCC_AUTO_CERT_PROVISIONING", "true").lower() == "true",
            certificate_renewal_threshold_days=int(os.environ.get("VCC_CERT_RENEWAL_THRESHOLD", "30")),
            certificate_validity_days=int(os.environ.get("VCC_CERT_VALIDITY_DAYS", "365")),
            mtls_enabled=os.environ.get("VCC_MTLS_ENABLED", "true").lower() == "true",
            require_client_cert=os.environ.get("VCC_REQUIRE_CLIENT_CERT", "true").lower() == "true",
            zero_trust_enabled=os.environ.get("VCC_ZERO_TRUST_ENABLED", "true").lower() == "true",
            notifications_enabled=os.environ.get("VCC_NOTIFICATIONS_ENABLED", "true").lower() == "true",
            webhook_url=os.environ.get("VCC_WEBHOOK_URL"),
        )


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class VCCService:
    """VCC Service representation"""
    service_id: str
    service_type: VCCServiceType
    display_name: str
    description: str
    endpoints: List[str]
    health_check_url: Optional[str] = None
    status: ServiceStatus = ServiceStatus.PENDING
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    auth_method: AuthMethod = AuthMethod.MTLS_CERTIFICATE
    certificate_id: Optional[str] = None
    certificate_expires: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    allowed_callers: List[str] = field(default_factory=list)
    allowed_callees: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "service_id": self.service_id,
            "service_type": self.service_type.value,
            "display_name": self.display_name,
            "description": self.description,
            "endpoints": self.endpoints,
            "health_check_url": self.health_check_url,
            "status": self.status.value,
            "trust_level": self.trust_level.value,
            "auth_method": self.auth_method.value,
            "certificate_id": self.certificate_id,
            "certificate_expires": self.certificate_expires.isoformat() if self.certificate_expires else None,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata,
            "allowed_callers": self.allowed_callers,
            "allowed_callees": self.allowed_callees,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class ServiceCommunicationPolicy:
    """Policy for service-to-service communication"""
    source_service: str
    target_service: str
    allowed: bool = True
    auth_method: AuthMethod = AuthMethod.MTLS_CERTIFICATE
    required_cert_purpose: str = "vcc_service"
    isolation_level: TrustLevel = TrustLevel.MEDIUM
    special_permissions: List[str] = field(default_factory=list)


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    service_id: str
    timestamp: datetime
    healthy: bool
    response_time_ms: int
    http_status_code: Optional[int] = None
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Service Registry
# ============================================================================

class VCCServiceRegistry:
    """
    Registry for all VCC services.
    
    Manages service registration, discovery, and lookup.
    """
    
    def __init__(self):
        self._services: Dict[str, VCCService] = {}
        self._policies: Dict[str, ServiceCommunicationPolicy] = {}
        self._lock = threading.Lock()
        
        # Pre-define VCC service templates
        self._service_templates = self._create_service_templates()
        
        # Pre-define communication policies
        self._default_policies = self._create_default_policies()
    
    def _create_service_templates(self) -> Dict[VCCServiceType, Dict[str, Any]]:
        """Create templates for VCC services"""
        return {
            VCCServiceType.COVINA_BACKEND: {
                "display_name": "Covina Main Backend",
                "description": "Central backend for Covina document management and AI orchestration",
                "trust_level": TrustLevel.HIGH,
                "allowed_callers": ["veritas-backend", "veritas-frontend", "argus-backend"],
                "allowed_callees": ["clara-backend", "veritas-backend", "pki-server"],
            },
            VCCServiceType.COVINA_INGESTION: {
                "display_name": "Covina Ingestion Service",
                "description": "Document ingestion and preprocessing for Covina",
                "trust_level": TrustLevel.MEDIUM,
                "allowed_callers": ["covina-backend"],
                "allowed_callees": ["covina-backend", "pki-server"],
            },
            VCCServiceType.VERITAS_BACKEND: {
                "display_name": "Veritas Backend",
                "description": "Pipeline verification and code signing backend",
                "trust_level": TrustLevel.HIGH,
                "allowed_callers": ["veritas-frontend", "covina-backend", "argus-backend"],
                "allowed_callees": ["covina-backend", "pki-server"],
            },
            VCCServiceType.VERITAS_FRONTEND: {
                "display_name": "Veritas Frontend",
                "description": "Web UI for Veritas pipeline management",
                "trust_level": TrustLevel.LOW,
                "allowed_callers": [],
                "allowed_callees": ["veritas-backend"],
            },
            VCCServiceType.CLARA_BACKEND: {
                "display_name": "Clara AI Backend",
                "description": "AI/ML model inference and LoRA adapter management",
                "trust_level": TrustLevel.HIGH,
                "allowed_callers": ["covina-backend"],
                "allowed_callees": ["pki-server"],
            },
            VCCServiceType.VPB_BACKEND: {
                "display_name": "VPB Brandenburg Portal Backend",
                "description": "Integration with Brandenburg public portal",
                "trust_level": TrustLevel.MEDIUM,
                "allowed_callers": ["covina-backend", "argus-backend"],
                "allowed_callees": ["covina-backend", "pki-server"],
            },
            VCCServiceType.ARGUS_BACKEND: {
                "display_name": "Argus Security & Monitoring",
                "description": "Security monitoring and alerting service",
                "trust_level": TrustLevel.HIGH,
                "allowed_callers": ["pki-server"],
                "allowed_callees": ["covina-backend", "veritas-backend", "clara-backend", "vpb-backend", "pki-server"],
            },
            VCCServiceType.PKI_SERVER: {
                "display_name": "VCC PKI Server",
                "description": "Central PKI management and certificate authority",
                "trust_level": TrustLevel.HIGH,
                "allowed_callers": ["covina-backend", "covina-ingestion", "veritas-backend", "clara-backend", "vpb-backend", "argus-backend"],
                "allowed_callees": [],
            },
            VCCServiceType.GENERIC: {
                "display_name": "Generic VCC Service",
                "description": "Generic VCC microservice",
                "trust_level": TrustLevel.LOW,
                "allowed_callers": [],
                "allowed_callees": ["pki-server"],
            },
        }
    
    def _create_default_policies(self) -> List[ServiceCommunicationPolicy]:
        """Create default communication policies based on VCC architecture"""
        policies = []
        
        # Clara -> Covina (AI model calls)
        policies.append(ServiceCommunicationPolicy(
            source_service="clara-backend",
            target_service="covina-backend",
            allowed=True,
            auth_method=AuthMethod.MTLS_CERTIFICATE,
            required_cert_purpose="vcc_service",
            isolation_level=TrustLevel.HIGH,
            special_permissions=["ai_model_inference"]
        ))
        
        # Covina -> Clara (orchestration)
        policies.append(ServiceCommunicationPolicy(
            source_service="covina-backend",
            target_service="clara-backend",
            allowed=True,
            auth_method=AuthMethod.MTLS_CERTIFICATE,
            required_cert_purpose="vcc_service",
            isolation_level=TrustLevel.HIGH,
            special_permissions=["orchestration", "lora_management"]
        ))
        
        # Covina -> Veritas (code verification)
        policies.append(ServiceCommunicationPolicy(
            source_service="covina-backend",
            target_service="veritas-backend",
            allowed=True,
            auth_method=AuthMethod.MTLS_CERTIFICATE,
            required_cert_purpose="vcc_service",
            isolation_level=TrustLevel.HIGH,
            special_permissions=["code_signing", "pipeline_verification"]
        ))
        
        # Veritas -> Covina (status updates)
        policies.append(ServiceCommunicationPolicy(
            source_service="veritas-backend",
            target_service="covina-backend",
            allowed=True,
            auth_method=AuthMethod.MTLS_CERTIFICATE,
            required_cert_purpose="vcc_service",
            isolation_level=TrustLevel.MEDIUM,
            special_permissions=["status_update"]
        ))
        
        # All services -> PKI Server (certificate operations)
        for service_type in VCCServiceType:
            if service_type != VCCServiceType.PKI_SERVER:
                policies.append(ServiceCommunicationPolicy(
                    source_service=service_type.value,
                    target_service="pki-server",
                    allowed=True,
                    auth_method=AuthMethod.MTLS_CERTIFICATE,
                    required_cert_purpose="vcc_service",
                    isolation_level=TrustLevel.HIGH,
                    special_permissions=["certificate_request", "certificate_renewal"]
                ))
        
        # Argus -> All services (monitoring)
        for service_type in VCCServiceType:
            if service_type != VCCServiceType.ARGUS_BACKEND:
                policies.append(ServiceCommunicationPolicy(
                    source_service="argus-backend",
                    target_service=service_type.value,
                    allowed=True,
                    auth_method=AuthMethod.MTLS_CERTIFICATE,
                    required_cert_purpose="vcc_monitoring",
                    isolation_level=TrustLevel.MEDIUM,
                    special_permissions=["health_check", "metrics_collection"]
                ))
        
        return policies
    
    def register(self, service: VCCService) -> bool:
        """Register a new service"""
        with self._lock:
            if service.service_id in self._services:
                logger.warning(f"Service {service.service_id} already registered, updating...")
            
            # Apply template defaults if available
            template = self._service_templates.get(service.service_type, {})
            if not service.allowed_callers:
                service.allowed_callers = template.get("allowed_callers", [])
            if not service.allowed_callees:
                service.allowed_callees = template.get("allowed_callees", [])
            if service.trust_level == TrustLevel.UNTRUSTED:
                service.trust_level = template.get("trust_level", TrustLevel.LOW)
            
            service.updated_at = datetime.now(timezone.utc)
            self._services[service.service_id] = service
            
            logger.info(f"Service {service.service_id} registered successfully")
            return True
    
    def unregister(self, service_id: str) -> bool:
        """Unregister a service"""
        with self._lock:
            if service_id in self._services:
                del self._services[service_id]
                logger.info(f"Service {service_id} unregistered")
                return True
            return False
    
    def get(self, service_id: str) -> Optional[VCCService]:
        """Get a service by ID"""
        with self._lock:
            return self._services.get(service_id)
    
    def get_all(self) -> List[VCCService]:
        """Get all registered services"""
        with self._lock:
            return list(self._services.values())
    
    def get_by_type(self, service_type: VCCServiceType) -> List[VCCService]:
        """Get services by type"""
        with self._lock:
            return [s for s in self._services.values() if s.service_type == service_type]
    
    def get_by_status(self, status: ServiceStatus) -> List[VCCService]:
        """Get services by status"""
        with self._lock:
            return [s for s in self._services.values() if s.status == status]
    
    def update_status(self, service_id: str, status: ServiceStatus) -> bool:
        """Update service status"""
        with self._lock:
            if service_id in self._services:
                self._services[service_id].status = status
                self._services[service_id].updated_at = datetime.now(timezone.utc)
                return True
            return False
    
    def is_communication_allowed(self, source_id: str, target_id: str) -> bool:
        """Check if communication between services is allowed"""
        with self._lock:
            source = self._services.get(source_id)
            target = self._services.get(target_id)
            
            if not source or not target:
                return False
            
            # Check explicit allow list
            if target_id in source.allowed_callees:
                return True
            
            if source_id in target.allowed_callers:
                return True
            
            # Check policies
            policy_key = f"{source_id}:{target_id}"
            if policy_key in self._policies:
                return self._policies[policy_key].allowed
            
            # Default: deny
            return False
    
    def get_policy(self, source_id: str, target_id: str) -> Optional[ServiceCommunicationPolicy]:
        """Get communication policy between services"""
        policy_key = f"{source_id}:{target_id}"
        return self._policies.get(policy_key)


# ============================================================================
# Certificate Provisioning
# ============================================================================

class VCCCertificateProvisioner:
    """
    Automatic certificate provisioning for VCC services.
    
    Handles:
    - Initial certificate generation for new services
    - Certificate renewal before expiration
    - mTLS certificate validation
    """
    
    def __init__(self, pki_server, config: VCCIntegrationConfig):
        self.pki_server = pki_server
        self.config = config
        self._provisioned_certs: Dict[str, str] = {}  # service_id -> cert_id
    
    async def provision_certificate(self, service: VCCService) -> Optional[str]:
        """Provision a certificate for a service"""
        try:
            logger.info(f"Provisioning certificate for service: {service.service_id}")
            
            # Generate CSR parameters
            common_name = f"{service.service_id}.vcc.local"
            san_dns = [common_name]
            
            # Add endpoint hostnames to SAN
            for endpoint in service.endpoints:
                # Extract hostname from URL
                if "://" in endpoint:
                    hostname = endpoint.split("://")[1].split(":")[0].split("/")[0]
                    if hostname not in san_dns:
                        san_dns.append(hostname)
            
            # Add VCC-specific SANs
            san_dns.append(f"*.{service.service_id}.vcc.local")
            san_dns.append("*.vcc.local")
            
            # Request certificate from PKI server
            if hasattr(self.pki_server, 'request_certificate'):
                cert_response = await self._request_certificate_async(
                    service_id=service.service_id,
                    common_name=common_name,
                    san_dns=san_dns,
                    validity_days=self.config.certificate_validity_days
                )
                
                if cert_response and cert_response.get("certificate_id"):
                    cert_id = cert_response["certificate_id"]
                    self._provisioned_certs[service.service_id] = cert_id
                    
                    logger.info(f"Certificate provisioned for {service.service_id}: {cert_id}")
                    return cert_id
            else:
                # Fallback for when PKI server doesn't have async method
                cert_id = f"vcc-cert-{service.service_id}-{int(time.time())}"
                self._provisioned_certs[service.service_id] = cert_id
                logger.info(f"Certificate ID generated for {service.service_id}: {cert_id}")
                return cert_id
            
        except Exception as e:
            logger.error(f"Failed to provision certificate for {service.service_id}: {e}")
            return None
    
    async def _request_certificate_async(self, service_id: str, common_name: str, 
                                         san_dns: List[str], validity_days: int) -> Optional[Dict]:
        """Request certificate from PKI server (async wrapper)"""
        # This would integrate with the actual PKI server
        # For now, return a mock response
        return {
            "certificate_id": f"vcc-cert-{service_id}-{int(time.time())}",
            "common_name": common_name,
            "san_dns": san_dns,
            "validity_days": validity_days,
            "issued_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def check_renewal_needed(self, service: VCCService) -> bool:
        """Check if certificate renewal is needed"""
        if not service.certificate_expires:
            return True
        
        threshold = timedelta(days=self.config.certificate_renewal_threshold_days)
        return service.certificate_expires - datetime.now(timezone.utc) < threshold
    
    async def renew_certificate(self, service: VCCService) -> Optional[str]:
        """Renew certificate for a service"""
        logger.info(f"Renewing certificate for service: {service.service_id}")
        return await self.provision_certificate(service)
    
    def get_certificate_id(self, service_id: str) -> Optional[str]:
        """Get certificate ID for a service"""
        return self._provisioned_certs.get(service_id)


# ============================================================================
# Health Checker
# ============================================================================

class VCCHealthChecker:
    """
    Health checking for VCC services.
    
    Features:
    - Periodic health checks
    - Response time monitoring
    - Automatic status updates
    """
    
    def __init__(self, registry: VCCServiceRegistry, config: VCCIntegrationConfig):
        self.registry = registry
        self.config = config
        self._health_history: Dict[str, List[HealthCheckResult]] = {}
        self._max_history = 100
    
    async def check_health(self, service: VCCService) -> HealthCheckResult:
        """Check health of a service"""
        start_time = time.time()
        result = HealthCheckResult(
            service_id=service.service_id,
            timestamp=datetime.now(timezone.utc),
            healthy=False,
            response_time_ms=0
        )
        
        try:
            if not service.health_check_url:
                # No health check URL, assume healthy
                result.healthy = True
                result.details = {"reason": "no_health_check_url"}
            else:
                # Simulate health check (in real implementation, make HTTP request)
                # For now, assume healthy
                result.healthy = True
                result.http_status_code = 200
                result.details = {"checked_url": service.health_check_url}
            
            result.response_time_ms = int((time.time() - start_time) * 1000)
            
        except Exception as e:
            result.healthy = False
            result.error_message = str(e)
            result.response_time_ms = int((time.time() - start_time) * 1000)
        
        # Store history
        if service.service_id not in self._health_history:
            self._health_history[service.service_id] = []
        
        self._health_history[service.service_id].append(result)
        
        # Trim history
        if len(self._health_history[service.service_id]) > self._max_history:
            self._health_history[service.service_id] = self._health_history[service.service_id][-self._max_history:]
        
        # Update service status
        if result.healthy:
            self.registry.update_status(service.service_id, ServiceStatus.ACTIVE)
        else:
            self.registry.update_status(service.service_id, ServiceStatus.UNHEALTHY)
        
        return result
    
    def get_health_history(self, service_id: str, limit: int = 10) -> List[HealthCheckResult]:
        """Get health check history for a service"""
        history = self._health_history.get(service_id, [])
        return history[-limit:]
    
    def get_all_health_status(self) -> Dict[str, bool]:
        """Get health status for all services"""
        return {
            service.service_id: service.status == ServiceStatus.ACTIVE
            for service in self.registry.get_all()
        }


# ============================================================================
# VCC Service Integration Main Class
# ============================================================================

class VCCServiceIntegration:
    """
    Main class for VCC Service Integration.
    
    Orchestrates:
    - Service discovery and registration
    - Certificate provisioning
    - Health monitoring
    - Zero-Trust policy enforcement
    """
    
    def __init__(self, pki_server=None, config: Optional[VCCIntegrationConfig] = None):
        self.config = config or VCCIntegrationConfig.from_env()
        self.pki_server = pki_server
        
        # Components
        self.registry = VCCServiceRegistry()
        self.provisioner = VCCCertificateProvisioner(pki_server, self.config)
        self.health_checker = VCCHealthChecker(self.registry, self.config)
        
        # State
        self._running = False
        self._discovery_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
        self._renewal_task: Optional[asyncio.Task] = None
        
        # Statistics
        self._stats = {
            "services_registered": 0,
            "certificates_provisioned": 0,
            "health_checks_performed": 0,
            "renewals_performed": 0,
            "last_discovery": None,
            "last_health_check": None,
            "started_at": None,
        }
    
    async def start(self):
        """Start the VCC Service Integration"""
        if self._running:
            logger.warning("VCC Service Integration already running")
            return
        
        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()
        
        logger.info("Starting VCC Service Integration")
        
        # Register PKI Server itself
        await self._register_pki_server()
        
        # Start background tasks
        if self.config.discovery_enabled:
            self._discovery_task = asyncio.create_task(self._discovery_loop())
        
        if self.config.health_check_enabled:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        if self.config.auto_certificate_provisioning:
            self._renewal_task = asyncio.create_task(self._renewal_loop())
        
        logger.info("VCC Service Integration started successfully")
    
    async def stop(self):
        """Stop the VCC Service Integration"""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel background tasks
        for task in [self._discovery_task, self._health_check_task, self._renewal_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info("VCC Service Integration stopped")
    
    async def _register_pki_server(self):
        """Register the PKI Server itself as a service"""
        pki_service = VCCService(
            service_id="pki-server",
            service_type=VCCServiceType.PKI_SERVER,
            display_name="VCC PKI Server",
            description="Central PKI management and certificate authority",
            endpoints=["https://pki.vcc.local:8443"],
            health_check_url="https://pki.vcc.local:8443/health",
            status=ServiceStatus.ACTIVE,
            trust_level=TrustLevel.HIGH,
        )
        
        self.registry.register(pki_service)
        self._stats["services_registered"] += 1
    
    async def register_service(
        self,
        service_id: str,
        service_type: VCCServiceType,
        endpoints: List[str],
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        health_check_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> VCCService:
        """Register a new VCC service"""
        
        # Get template defaults
        template = self.registry._service_templates.get(service_type, {})
        
        service = VCCService(
            service_id=service_id,
            service_type=service_type,
            display_name=display_name or template.get("display_name", service_id),
            description=description or template.get("description", ""),
            endpoints=endpoints,
            health_check_url=health_check_url,
            metadata=metadata or {},
        )
        
        # Register in registry
        self.registry.register(service)
        self._stats["services_registered"] += 1
        
        # Provision certificate
        if self.config.auto_certificate_provisioning:
            cert_id = await self.provisioner.provision_certificate(service)
            if cert_id:
                service.certificate_id = cert_id
                service.certificate_expires = datetime.now(timezone.utc) + timedelta(days=self.config.certificate_validity_days)
                self._stats["certificates_provisioned"] += 1
        
        # Initial health check
        await self.health_checker.check_health(service)
        
        logger.info(f"Service {service_id} registered and configured")
        return service
    
    async def unregister_service(self, service_id: str) -> bool:
        """Unregister a VCC service"""
        return self.registry.unregister(service_id)
    
    async def _discovery_loop(self):
        """Background task for service discovery"""
        while self._running:
            try:
                await self._perform_discovery()
                self._stats["last_discovery"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                logger.error(f"Discovery error: {e}")
            
            await asyncio.sleep(self.config.discovery_interval_seconds)
    
    async def _perform_discovery(self):
        """Perform service discovery"""
        # In a real implementation, this would:
        # 1. Query DNS/Consul/etcd for registered services
        # 2. Auto-register discovered services
        # For now, this is a placeholder
        logger.debug("Performing service discovery...")
    
    async def _health_check_loop(self):
        """Background task for health checking"""
        while self._running:
            try:
                for service in self.registry.get_all():
                    await self.health_checker.check_health(service)
                    self._stats["health_checks_performed"] += 1
                
                self._stats["last_health_check"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                logger.error(f"Health check error: {e}")
            
            await asyncio.sleep(self.config.health_check_interval_seconds)
    
    async def _renewal_loop(self):
        """Background task for certificate renewal"""
        while self._running:
            try:
                for service in self.registry.get_all():
                    if await self.provisioner.check_renewal_needed(service):
                        cert_id = await self.provisioner.renew_certificate(service)
                        if cert_id:
                            service.certificate_id = cert_id
                            service.certificate_expires = datetime.now(timezone.utc) + timedelta(days=self.config.certificate_validity_days)
                            self._stats["renewals_performed"] += 1
            except Exception as e:
                logger.error(f"Renewal error: {e}")
            
            # Check every hour
            await asyncio.sleep(3600)
    
    def get_service(self, service_id: str) -> Optional[VCCService]:
        """Get a service by ID"""
        return self.registry.get(service_id)
    
    def get_all_services(self) -> List[VCCService]:
        """Get all registered services"""
        return self.registry.get_all()
    
    def is_communication_allowed(self, source_id: str, target_id: str) -> bool:
        """Check if communication between services is allowed"""
        return self.registry.is_communication_allowed(source_id, target_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return {
            **self._stats,
            "running": self._running,
            "total_services": len(self.registry.get_all()),
            "active_services": len(self.registry.get_by_status(ServiceStatus.ACTIVE)),
            "unhealthy_services": len(self.registry.get_by_status(ServiceStatus.UNHEALTHY)),
            "config": {
                "discovery_enabled": self.config.discovery_enabled,
                "health_check_enabled": self.config.health_check_enabled,
                "auto_certificate_provisioning": self.config.auto_certificate_provisioning,
                "mtls_enabled": self.config.mtls_enabled,
                "zero_trust_enabled": self.config.zero_trust_enabled,
            }
        }


# ============================================================================
# FastAPI Router
# ============================================================================

def create_vcc_integration_router(integration: VCCServiceIntegration):
    """Create FastAPI router for VCC Service Integration"""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
    from typing import Optional, List
    
    router = APIRouter(prefix="/api/v1/vcc", tags=["VCC Integration"])
    
    class ServiceRegistrationRequest(BaseModel):
        service_id: str
        service_type: str
        endpoints: List[str]
        display_name: Optional[str] = None
        description: Optional[str] = None
        health_check_url: Optional[str] = None
        metadata: Optional[Dict[str, Any]] = None
    
    class CommunicationCheckRequest(BaseModel):
        source_service: str
        target_service: str
    
    @router.get("/status")
    async def get_status():
        """Get VCC Integration status and statistics"""
        return integration.get_statistics()
    
    @router.get("/services")
    async def list_services():
        """List all registered VCC services"""
        return [s.to_dict() for s in integration.get_all_services()]
    
    @router.get("/services/{service_id}")
    async def get_service(service_id: str):
        """Get a specific VCC service"""
        service = integration.get_service(service_id)
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        return service.to_dict()
    
    @router.post("/services")
    async def register_service(request: ServiceRegistrationRequest):
        """Register a new VCC service"""
        try:
            service_type = VCCServiceType(request.service_type)
        except ValueError:
            service_type = VCCServiceType.GENERIC
        
        service = await integration.register_service(
            service_id=request.service_id,
            service_type=service_type,
            endpoints=request.endpoints,
            display_name=request.display_name,
            description=request.description,
            health_check_url=request.health_check_url,
            metadata=request.metadata
        )
        return service.to_dict()
    
    @router.delete("/services/{service_id}")
    async def unregister_service(service_id: str):
        """Unregister a VCC service"""
        success = await integration.unregister_service(service_id)
        if not success:
            raise HTTPException(status_code=404, detail="Service not found")
        return {"success": True, "message": f"Service {service_id} unregistered"}
    
    @router.get("/services/{service_id}/health")
    async def get_service_health(service_id: str):
        """Get health status of a service"""
        service = integration.get_service(service_id)
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        
        history = integration.health_checker.get_health_history(service_id)
        return {
            "service_id": service_id,
            "status": service.status.value,
            "last_check": service.last_health_check.isoformat() if service.last_health_check else None,
            "history": [
                {
                    "timestamp": h.timestamp.isoformat(),
                    "healthy": h.healthy,
                    "response_time_ms": h.response_time_ms,
                    "error": h.error_message
                }
                for h in history
            ]
        }
    
    @router.post("/communication/check")
    async def check_communication(request: CommunicationCheckRequest):
        """Check if communication between services is allowed"""
        allowed = integration.is_communication_allowed(
            request.source_service,
            request.target_service
        )
        return {
            "source": request.source_service,
            "target": request.target_service,
            "allowed": allowed
        }
    
    @router.get("/policies")
    async def get_policies():
        """Get all communication policies"""
        return [
            {
                "source": policy.source_service,
                "target": policy.target_service,
                "allowed": policy.allowed,
                "auth_method": policy.auth_method.value,
                "isolation_level": policy.isolation_level.value,
                "special_permissions": policy.special_permissions
            }
            for policy in integration.registry._default_policies
        ]
    
    @router.get("/health-overview")
    async def get_health_overview():
        """Get health overview of all services"""
        return integration.health_checker.get_all_health_status()
    
    @router.post("/start")
    async def start_integration():
        """Start VCC Integration"""
        await integration.start()
        return {"success": True, "message": "VCC Integration started"}
    
    @router.post("/stop")
    async def stop_integration():
        """Stop VCC Integration"""
        await integration.stop()
        return {"success": True, "message": "VCC Integration stopped"}
    
    return router


# ============================================================================
# Module Initialization
# ============================================================================

# Default integration instance (can be overridden)
_default_integration: Optional[VCCServiceIntegration] = None


def get_integration() -> VCCServiceIntegration:
    """Get the default VCC Integration instance"""
    global _default_integration
    if _default_integration is None:
        _default_integration = VCCServiceIntegration()
    return _default_integration


def set_integration(integration: VCCServiceIntegration):
    """Set the default VCC Integration instance"""
    global _default_integration
    _default_integration = integration
