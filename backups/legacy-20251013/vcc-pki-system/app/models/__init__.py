# VCC PKI System - Pydantic Models
# Data models for API requests and responses

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

# Enums for type safety
class OrganizationType(str, Enum):
    government = "government"
    partner = "partner"
    external = "external"

class ServiceType(str, Enum):
    api = "api"
    orchestrator = "orchestrator"
    processor = "processor"
    ui = "ui"
    database = "database"

class ServiceStatus(str, Enum):
    active = "active"
    inactive = "inactive"
    discovered = "discovered"
    pending_cert = "pending_cert"
    error = "error"

class CertificatePurpose(str, Enum):
    vcc_service = "vcc_service"
    mtls_service = "mtls_service"
    code_signing = "code_signing"
    admin = "admin"
    external_integration = "external_integration"

class CertificateStatus(str, Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"

class EventCategory(str, Enum):
    authentication = "authentication"
    authorization = "authorization"
    certificate = "certificate"
    signature = "signature"
    service = "service"
    admin = "admin"

class ActorType(str, Enum):
    user = "user"
    service = "service"
    system = "system"
    external = "external"

# Base Models
class BaseResponse(BaseModel):
    """Base response model with common fields"""
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseResponse):
    """Error response model"""
    success: bool = False
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# Organization Models
class OrganizationBase(BaseModel):
    org_name: str = Field(..., min_length=1, max_length=255)
    org_type: OrganizationType = OrganizationType.government
    admin_contact: Optional[str] = Field(None, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    isolation_level: str = Field(default="strict", regex=r'^(strict|collaborative|federated)$')

class OrganizationCreate(OrganizationBase):
    org_id: str = Field(..., min_length=1, max_length=50, regex=r'^[a-z0-9-]+$')

class OrganizationResponse(OrganizationBase):
    org_id: str
    root_ca_id: Optional[str] = None
    created_at: datetime
    active: bool
    metadata: Optional[Dict[str, Any]] = {}

# VCC Service Models
class VCCServiceBase(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=50)
    service_type: ServiceType
    endpoint_url: Optional[str] = Field(None, regex=r'^https?://.*')
    health_endpoint: Optional[str] = None
    auto_cert_renewal: bool = True

class VCCServiceCreate(VCCServiceBase):
    service_id: str = Field(..., min_length=1, max_length=50, regex=r'^[a-z0-9-]+$')
    organization_id: str

class VCCServiceUpdate(BaseModel):
    service_name: Optional[str] = None
    endpoint_url: Optional[str] = None
    health_endpoint: Optional[str] = None
    status: Optional[ServiceStatus] = None
    auto_cert_renewal: Optional[bool] = None

class VCCServiceResponse(VCCServiceBase):
    service_id: str
    organization_id: str
    cert_id: Optional[str] = None
    discovered_at: datetime
    last_seen: datetime
    status: ServiceStatus
    service_metadata: Optional[Dict[str, Any]] = {}
    
    # Certificate information (joined from certificates table)
    cert_expires_at: Optional[datetime] = None
    cert_status: Optional[str] = None

# Certificate Authority Models
class CABase(BaseModel):
    ca_name: str = Field(..., min_length=1, max_length=100)
    ca_type: str = Field(..., regex=r'^(root|intermediate|issuing)$')
    key_algorithm: str = Field(default="RSA", regex=r'^(RSA|ECDSA)$')
    key_size: int = Field(default=2048, ge=2048, le=4096)
    usage_purpose: Optional[str] = None

class CACreate(CABase):
    parent_ca_id: Optional[str] = None
    organization_id: str
    validity_years: int = Field(default=10, ge=1, le=25)

class CAResponse(CABase):
    ca_id: str
    parent_ca_id: Optional[str] = None
    organization_id: str
    certificate_pem: str
    created_at: datetime
    expires_at: datetime
    status: CertificateStatus
    metadata: Optional[Dict[str, Any]] = {}

# Certificate Models
class CertificateBase(BaseModel):
    subject_dn: str
    purpose: CertificatePurpose
    service_domain: Optional[str] = None
    subject_alt_names: Optional[List[str]] = None
    auto_renewal: bool = True

class CertificateRequest(BaseModel):
    """Certificate Signing Request"""
    service_id: Optional[str] = None
    organization_id: str
    certificate_type: CertificatePurpose
    subject_data: Dict[str, str]
    san_domains: Optional[List[str]] = None
    validity_days: Optional[int] = None

class CertificateResponse(CertificateBase):
    cert_id: str
    serial_number: str
    issuing_ca_id: str
    organization_id: str
    service_id: Optional[str] = None
    certificate_pem: str
    key_usage: str
    extended_key_usage: str
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    last_used: Optional[datetime] = None
    usage_count: int

class CertificateRevocationRequest(BaseModel):
    cert_id: str
    revocation_reason: str = Field(..., min_length=1, max_length=255)

# Code Signature Models
class CodeSigningRequest(BaseModel):
    artifact_type: str = Field(..., regex=r'^(python_package|lora_adapter|pipeline_config|ui_bundle|docker_image)$')
    artifact_path: str
    artifact_name: Optional[str] = None
    service_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class CodeSignatureResponse(BaseModel):
    signature_id: str
    cert_id: str
    service_id: Optional[str] = None
    artifact_type: str
    artifact_path: str
    artifact_name: Optional[str] = None
    file_hash: str
    signature_algorithm: str
    signed_at: datetime
    vcc_metadata: Optional[Dict[str, Any]] = {}
    verified_count: int
    last_verified_at: Optional[datetime] = None
    signature_valid: bool

class CodeVerificationRequest(BaseModel):
    artifact_path: str
    signature_id: Optional[str] = None
    expected_service: Optional[str] = None

class CodeVerificationResponse(BaseModel):
    valid: bool
    signature_id: Optional[str] = None
    cert_id: Optional[str] = None
    service_identity: Optional[str] = None
    organization: Optional[str] = None
    signed_at: Optional[datetime] = None
    verification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None

# Audit Models  
class AuditEventBase(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=50)
    event_category: EventCategory
    actor_identity: str
    actor_type: ActorType
    target_resource: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = {}
    source_ip: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None

class AuditEventCreate(AuditEventBase):
    organization_id: Optional[str] = None
    service_id: Optional[str] = None

class AuditEventResponse(AuditEventBase):
    event_id: str
    organization_id: Optional[str] = None
    service_id: Optional[str] = None
    compliance_relevant: bool
    timestamp: datetime

# Health and Status Models
class ServiceHealthStatus(BaseModel):
    service_id: str
    service_name: str
    status: ServiceStatus
    endpoint_reachable: bool
    certificate_valid: bool
    certificate_expires_in_days: Optional[int] = None
    last_health_check: datetime
    error_message: Optional[str] = None

class PKIHealthStatus(BaseModel):
    overall_status: str = Field(..., regex=r'^(healthy|degraded|critical)$')
    database_status: str
    certificate_authorities_active: int
    active_certificates: int
    certificates_expiring_soon: int
    services_monitored: int
    services_healthy: int
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class SystemMetrics(BaseModel):
    total_organizations: int
    total_services: int
    total_certificates: int
    total_signatures: int
    certificates_issued_24h: int
    signatures_created_24h: int
    audit_events_24h: int
    database_size_mb: float
    uptime_hours: float

# Service Discovery Models
class ServiceDiscoveryResult(BaseModel):
    discovered_services: List[Dict[str, Any]]
    new_services_count: int
    updated_services_count: int
    unreachable_services: List[str]
    discovery_timestamp: datetime = Field(default_factory=datetime.utcnow)

class AutoProvisioningRequest(BaseModel):
    service_ids: Optional[List[str]] = None  # If None, provision all discovered services
    certificate_validity_days: Optional[int] = None
    force_renewal: bool = False

class AutoProvisioningResponse(BaseModel):
    provisioned_certificates: List[str]
    failed_services: List[Dict[str, str]]
    total_processed: int
    success_count: int
    failure_count: int

# Multi-tenant Models
class TenantPolicy(BaseModel):
    policy_name: str
    service_access_matrix: Dict[str, Any]
    data_sharing_level: str = Field(..., regex=r'^(none|metadata_only|full)$')
    cross_tenant_auth: bool = False
    certificate_sharing: bool = False
    audit_separation: bool = True

class TenantPolicyResponse(TenantPolicy):
    policy_id: str
    organization_id: str
    policy_active: bool
    created_at: datetime
    updated_at: datetime

# VCC Integration Models (for future implementation)
class VCCServiceIntegrationStatus(BaseModel):
    """Status of VCC-specific integrations (for TODO implementation)"""
    service_id: str
    integration_type: str = Field(..., regex=r'^(mtls|code_signing|health_monitoring|audit_integration)$')
    integration_active: bool
    last_sync: Optional[datetime] = None
    configuration: Optional[Dict[str, Any]] = {}
    error_status: Optional[str] = None

class VCCMockServiceConfig(BaseModel):
    """Configuration for mock VCC services (development/testing)"""
    service_id: str
    mock_endpoint_enabled: bool = True
    mock_health_status: str = Field(default="healthy", regex=r'^(healthy|degraded|critical|offline)$')
    mock_certificate_valid: bool = True
    mock_response_delay_ms: int = Field(default=100, ge=0, le=5000)
    custom_responses: Optional[Dict[str, Any]] = {}

# Validators
@validator('artifact_path')
def validate_artifact_path(cls, v):
    """Validate artifact path for security"""
    if '..' in v or v.startswith('/') or '\\' in v:
        raise ValueError('Invalid artifact path - potential directory traversal')
    return v

# Response wrapper for consistent API responses
class APIResponse(BaseModel):
    """Generic API response wrapper"""
    success: bool = True
    data: Optional[Any] = None
    message: Optional[str] = None
    error: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

# Utility function for creating responses
def create_success_response(data: Any = None, message: str = None, metadata: Dict[str, Any] = None) -> APIResponse:
    """Create standardized success response"""
    return APIResponse(
        success=True,
        data=data,
        message=message,
        metadata=metadata
    )

def create_error_response(error_message: str, error_code: str = None, 
                         error_details: Dict[str, Any] = None) -> APIResponse:
    """Create standardized error response"""
    return APIResponse(
        success=False,
        error={
            "message": error_message,
            "code": error_code,
            "details": error_details or {}
        }
    )

# Export all models
__all__ = [
    # Enums
    'OrganizationType', 'ServiceType', 'ServiceStatus', 'CertificatePurpose', 
    'CertificateStatus', 'EventCategory', 'ActorType',
    
    # Base Models
    'BaseResponse', 'ErrorResponse',
    
    # Organization Models
    'OrganizationBase', 'OrganizationCreate', 'OrganizationResponse',
    
    # Service Models
    'VCCServiceBase', 'VCCServiceCreate', 'VCCServiceUpdate', 'VCCServiceResponse',
    
    # Certificate Models
    'CertificateBase', 'CertificateRequest', 'CertificateResponse', 'CertificateRevocationRequest',
    
    # CA Models
    'CABase', 'CACreate', 'CAResponse',
    
    # Code Signing Models
    'CodeSigningRequest', 'CodeSignatureResponse', 'CodeVerificationRequest', 'CodeVerificationResponse',
    
    # Audit Models
    'AuditEventBase', 'AuditEventCreate', 'AuditEventResponse',
    
    # Health Models
    'ServiceHealthStatus', 'PKIHealthStatus', 'SystemMetrics',
    
    # Discovery Models
    'ServiceDiscoveryResult', 'AutoProvisioningRequest', 'AutoProvisioningResponse',
    
    # Tenant Models
    'TenantPolicy', 'TenantPolicyResponse',
    
    # VCC Integration Models
    'VCCServiceIntegrationStatus', 'VCCMockServiceConfig',
    
    # Response Models
    'APIResponse', 'create_success_response', 'create_error_response'
]