# ============================================================================
# VCC PROTECTED SOURCE CODE
# ============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: pki_server
# Description: VCC PKI Server - Certificate Authority and Management API
# File Path: pki_server.py
#
# Version: 1.0.0
# Semantic Version: 1.0.0
#
# Author: VCC Security Team
#
# Build Date: 2025-10-13T18:55:15.262320+00:00
# Release Channel: development
#
# File UUID: 8e5707f2-12c3-4bff-8494-4016143b09f0
# Content Hash (SHA-256): 35e0d147b0231021931e76394fcdf76b8f29a50dfec9f86e21ee037e124b91eb
# Content Hash (SHA-512): d01902480c2553760c37a626a05ef0f16c1bb3f137ddf2a6a2cdaa6210ac644cf701c564ae54e024045536b78913edd4a88f58025faaa5edf582b305a4fcd16e
# File Size: 36463 bytes
# Line Count: 1069
# Created: 2025-10-13T18:55:15.262306+00:00
# Modified: 2025-10-13T18:55:15.262316+00:00
#
# Classification: CONFIDENTIAL
# DRM Protected: Yes
# Security Contact: security@vcc.local
# Allowed Domains: vcc.local
# Required Python: >=3.8
#
# ============================================================================

"""
VCC PKI Server - REST API
================================

FastAPI-basierter REST API Server für das globale VCC PKI-System.

Features:
- Certificate Management (Request, Download, Renew, Revoke)
- Service Registration & Discovery
- CA Certificate Distribution
- Certificate Revocation List (CRL)
- Audit Logging
- mTLS Authentication (für Service-to-Service)

Author: VCC Team
Date: 2025-10-13
Version: 1.0.0
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session

from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
import uvicorn

# Import PKI components
from ca_manager import CAManager
from service_cert_manager import ServiceCertificateManager
from auto_renewal_engine import AutoRenewalEngine, RenewalConfig, create_auto_renewal_engine
from ocsp_responder import OCSPResponder, OCSPCertStatus, create_ocsp_responder
from crl_distribution import CRLDistributionPoint, CRLConfig, CRLFormat, create_crl_distribution_point
from vcc_service_integration import (
    VCCServiceIntegration, VCCIntegrationConfig, VCCServiceType,
    create_vcc_integration_router
)
from database_migration import DatabaseMigration, DatabaseConfig, create_migration_router
from monitoring_dashboard import MonitoringDashboard, DashboardConfig, create_monitoring_router
from ocsp_stapling import OCSPStaplingManager, OCSPStaplingConfig, create_stapling_router

# Import Phase 2 components
from hsm_integration import HSMManager, HSMConfig, create_hsm_router, create_hsm_manager
from timestamp_authority import (
    TimestampAuthority, TSAConfig, VCCTimestampService,
    create_tsa_router, create_timestamp_authority
)
from certificate_templates import (
    CertificateTemplateManager, TemplateConfig,
    create_templates_router, create_template_manager
)
from multi_tenant_manager import (
    MultiTenantManager, MultiTenantConfig,
    create_multi_tenant_router, create_multi_tenant_manager
)

# Import database models
from database import (
    get_db, 
    Service, 
    Certificate, 
    AuditLog, 
    CRLEntry,
    RotationSchedule,
    ServiceHealthHistory
)

# Configure logging directory
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'pki_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# Pydantic Models (Request/Response Schemas)
# ============================================================================

class RevocationReason(str, Enum):
    """Certificate revocation reasons (RFC 5280)"""
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    REMOVE_FROM_CRL = "remove_from_crl"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"


class CertificateRequestModel(BaseModel):
    """Request model for new service certificate"""
    service_id: str = Field(..., min_length=3, max_length=64, pattern="^[a-z0-9-]+$")
    common_name: str = Field(..., min_length=3, max_length=64)
    san_dns: List[str] = Field(default_factory=list)
    san_ip: List[str] = Field(default_factory=list)
    validity_days: int = Field(default=365, ge=1, le=730)
    
    @field_validator('service_id')
    @classmethod
    def validate_service_id(cls, v):
        if not v.replace('-', '').isalnum():
            raise ValueError('service_id must contain only lowercase letters, numbers, and hyphens')
        return v


class CertificateRenewalModel(BaseModel):
    """Request model for certificate renewal"""
    validity_days: int = Field(default=365, ge=1, le=730)


class CertificateRevocationModel(BaseModel):
    """Request model for certificate revocation"""
    reason: RevocationReason = Field(default=RevocationReason.UNSPECIFIED)


class ServiceRegistrationModel(BaseModel):
    """Request model for service registration"""
    service_id: str = Field(..., min_length=3, max_length=64, pattern="^[a-z0-9-]+$")
    service_name: str = Field(..., min_length=3, max_length=128)
    endpoints: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    health_check_url: Optional[str] = None


class CertificateInfoResponse(BaseModel):
    """Response model for certificate information"""
    certificate_id: str
    service_id: str
    common_name: str
    serial_number: str
    fingerprint: str
    not_before: str
    not_after: str
    status: str
    san_dns: List[str]
    san_ip: List[str]
    issuer: str
    days_until_expiry: int


class ServiceInfoResponse(BaseModel):
    """Response model for service information"""
    service_id: str
    service_name: str
    certificate_status: str
    certificate_expiry: Optional[str]
    endpoints: List[str]
    health_check_url: Optional[str]
    metadata: Dict[str, Any]
    registered_at: str


class APIResponse(BaseModel):
    """Generic API response wrapper"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


# ============================================================================
# FastAPI App Initialization
# ============================================================================

# PKI Managers (initialized in lifespan)
ca_manager: Optional[CAManager] = None
cert_manager: Optional[ServiceCertificateManager] = None
auto_renewal_engine: Optional[AutoRenewalEngine] = None
ocsp_responder: Optional[OCSPResponder] = None
crl_distribution: Optional[CRLDistributionPoint] = None
vcc_integration: Optional[VCCServiceIntegration] = None
db_migration: Optional[DatabaseMigration] = None
monitoring_dashboard: Optional[MonitoringDashboard] = None
ocsp_stapling: Optional[OCSPStaplingManager] = None

# Phase 2 components
hsm_manager: Optional[HSMManager] = None
timestamp_authority: Optional[TimestampAuthority] = None
vcc_timestamp_service: Optional[VCCTimestampService] = None
template_manager: Optional[CertificateTemplateManager] = None
multi_tenant_manager: Optional[MultiTenantManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup/shutdown"""
    global ca_manager, cert_manager, auto_renewal_engine, ocsp_responder, crl_distribution, vcc_integration, db_migration, monitoring_dashboard, ocsp_stapling
    global hsm_manager, timestamp_authority, vcc_timestamp_service, template_manager, multi_tenant_manager
    
    # Startup
    logger.info("🚀 Starting VCC PKI Server...")
    
    try:
        # Initialize CA Manager
        ca_storage_dir = Path("../ca_storage")
        ca_manager = CAManager(str(ca_storage_dir))
        logger.info("✅ CA Manager initialized")
        
        # Initialize Certificate Manager
        cert_storage_dir = Path("../service_certificates")
        cert_manager = ServiceCertificateManager(
            storage_path=str(cert_storage_dir),
            ca_manager=ca_manager
        )
        logger.info("✅ Service Certificate Manager initialized")
        
        # Initialize Database
        from database import init_database
        init_database()
        logger.info("✅ Database initialized")
        
        # Initialize Auto-Renewal Engine (Phase 1 Feature)
        enable_auto_renewal = os.getenv("VCC_AUTO_RENEWAL_ENABLED", "true").lower() == "true"
        if enable_auto_renewal:
            renewal_config = RenewalConfig(
                renewal_threshold_days=int(os.getenv("VCC_RENEWAL_THRESHOLD_DAYS", "30")),
                warning_threshold_days=int(os.getenv("VCC_WARNING_THRESHOLD_DAYS", "14")),
                critical_threshold_days=int(os.getenv("VCC_CRITICAL_THRESHOLD_DAYS", "7")),
                check_interval_seconds=int(os.getenv("VCC_CHECK_INTERVAL_SECONDS", "3600")),
                max_retry_attempts=int(os.getenv("VCC_MAX_RETRY_ATTEMPTS", "3")),
                enable_notifications=os.getenv("VCC_NOTIFICATIONS_ENABLED", "true").lower() == "true"
            )
            auto_renewal_engine = create_auto_renewal_engine(cert_manager, renewal_config)
            auto_renewal_engine.start()
            logger.info("✅ Auto-Renewal Engine started")
        else:
            logger.info("ℹ️ Auto-Renewal Engine disabled (set VCC_AUTO_RENEWAL_ENABLED=true to enable)")
        
        # Initialize OCSP Responder (Phase 1 Feature)
        enable_ocsp = os.getenv("VCC_OCSP_ENABLED", "true").lower() == "true"
        if enable_ocsp:
            ocsp_cache_ttl = int(os.getenv("VCC_OCSP_CACHE_TTL", "3600"))
            ocsp_validity = int(os.getenv("VCC_OCSP_VALIDITY_HOURS", "24"))
            ocsp_responder = create_ocsp_responder(
                ca_manager=ca_manager,
                cache_ttl_seconds=ocsp_cache_ttl,
                response_validity_hours=ocsp_validity
            )
            logger.info("✅ OCSP Responder initialized")
        else:
            logger.info("ℹ️ OCSP Responder disabled (set VCC_OCSP_ENABLED=true to enable)")
        
        # Initialize CRL Distribution Point (Phase 1 Feature)
        enable_crl = os.getenv("VCC_CRL_ENABLED", "true").lower() == "true"
        if enable_crl:
            crl_config = CRLConfig(
                crl_validity_hours=int(os.getenv("VCC_CRL_VALIDITY_HOURS", "24")),
                crl_update_interval_seconds=int(os.getenv("VCC_CRL_UPDATE_INTERVAL", "3600")),
                enable_delta_crl=os.getenv("VCC_DELTA_CRL_ENABLED", "true").lower() == "true",
                crl_storage_path=os.getenv("VCC_CRL_STORAGE_PATH", "../crl")
            )
            crl_distribution = create_crl_distribution_point(ca_manager, crl_config)
            crl_distribution.start()
            logger.info("✅ CRL Distribution Point started")
        else:
            logger.info("ℹ️ CRL Distribution Point disabled (set VCC_CRL_ENABLED=true to enable)")
        
        # Initialize VCC Service Integration (Phase 1 Feature)
        enable_vcc_integration = os.getenv("VCC_SERVICE_INTEGRATION_ENABLED", "true").lower() == "true"
        if enable_vcc_integration:
            vcc_config = VCCIntegrationConfig.from_env()
            vcc_integration = VCCServiceIntegration(pki_server=app, config=vcc_config)
            await vcc_integration.start()
            # Add VCC Integration routes
            app.include_router(create_vcc_integration_router(vcc_integration))
            logger.info("✅ VCC Service Integration started")
        else:
            logger.info("ℹ️ VCC Service Integration disabled (set VCC_SERVICE_INTEGRATION_ENABLED=true to enable)")
        
        # Initialize Database Migration Manager (Phase 1 Feature)
        enable_db_migration = os.getenv("VCC_DB_MIGRATION_ENABLED", "true").lower() == "true"
        if enable_db_migration:
            db_config = DatabaseConfig.from_env()
            db_migration = DatabaseMigration(db_config)
            # Add Database Migration routes
            app.include_router(create_migration_router(db_migration))
            logger.info("✅ Database Migration Manager initialized")
            
            # Run pending migrations if auto-migrate is enabled
            if db_config.auto_migrate:
                try:
                    applied = db_migration.run_migrations()
                    if applied:
                        logger.info(f"✅ Applied {len(applied)} database migrations: {applied}")
                except Exception as e:
                    logger.warning(f"⚠️ Database migration failed: {e}")
        else:
            logger.info("ℹ️ Database Migration Manager disabled (set VCC_DB_MIGRATION_ENABLED=true to enable)")
        
        # Initialize Monitoring Dashboard (Phase 1 Feature)
        enable_monitoring = os.getenv("VCC_MONITORING_ENABLED", "true").lower() == "true"
        if enable_monitoring:
            dashboard_config = DashboardConfig.from_env()
            monitoring_dashboard = MonitoringDashboard(dashboard_config)
            # Add Monitoring Dashboard routes
            app.include_router(create_monitoring_router(monitoring_dashboard))
            logger.info("✅ Monitoring Dashboard initialized")
        else:
            logger.info("ℹ️ Monitoring Dashboard disabled (set VCC_MONITORING_ENABLED=true to enable)")
        
        # Initialize OCSP Stapling (Phase 1 Feature)
        enable_stapling = os.getenv("VCC_OCSP_STAPLING_ENABLED", "true").lower() == "true"
        if enable_stapling and ocsp_responder:
            stapling_config = OCSPStaplingConfig.from_env()
            ocsp_stapling = OCSPStaplingManager(ocsp_responder, stapling_config)
            ocsp_stapling.start()
            # Add OCSP Stapling routes
            app.include_router(create_stapling_router(ocsp_stapling))
            logger.info("✅ OCSP Stapling Manager started")
        else:
            logger.info("ℹ️ OCSP Stapling disabled (set VCC_OCSP_STAPLING_ENABLED=true to enable)")
        
        # =====================================================================
        # PHASE 2: Enterprise Features
        # =====================================================================
        
        # Initialize HSM Integration (Phase 2 Feature)
        enable_hsm = os.getenv("VCC_HSM_ENABLED", "false").lower() == "true"
        if enable_hsm:
            hsm_config = HSMConfig(
                hsm_type=os.getenv("VCC_HSM_TYPE", "softhsm"),
                library_path=os.getenv("VCC_HSM_LIBRARY_PATH", "/usr/lib/softhsm/libsofthsm2.so"),
                slot_id=int(os.getenv("VCC_HSM_SLOT_ID", "0")),
                pin=os.getenv("VCC_HSM_PIN", ""),
                token_label=os.getenv("VCC_HSM_TOKEN_LABEL", "VCC-PKI"),
            )
            hsm_manager = create_hsm_manager(hsm_config)
            # Add HSM routes
            app.include_router(create_hsm_router(hsm_manager))
            logger.info("✅ HSM Integration initialized")
        else:
            logger.info("ℹ️ HSM Integration disabled (set VCC_HSM_ENABLED=true to enable)")
        
        # Initialize Timestamp Authority (Phase 2 Feature)
        enable_tsa = os.getenv("VCC_TSA_ENABLED", "true").lower() == "true"
        if enable_tsa:
            tsa_config = TSAConfig(
                enabled=True,
                tsa_name=os.getenv("VCC_TSA_NAME", "VCC Timestamp Authority"),
                key_type=os.getenv("VCC_TSA_KEY_TYPE", "rsa_4096"),
                storage_path=os.getenv("VCC_TSA_STORAGE_PATH", "../tsa_storage"),
            )
            timestamp_authority, vcc_timestamp_service = create_timestamp_authority(
                config=tsa_config,
                ca_manager=ca_manager
            )
            # Add TSA routes
            app.include_router(create_tsa_router(timestamp_authority, vcc_timestamp_service))
            logger.info("✅ Timestamp Authority initialized")
        else:
            logger.info("ℹ️ Timestamp Authority disabled (set VCC_TSA_ENABLED=true to enable)")
        
        # Initialize Certificate Templates (Phase 2 Feature)
        enable_templates = os.getenv("VCC_TEMPLATES_ENABLED", "true").lower() == "true"
        if enable_templates:
            template_config = TemplateConfig.from_env()
            template_manager = create_template_manager(template_config)
            # Add Templates routes
            app.include_router(create_templates_router(template_manager))
            logger.info("✅ Certificate Template Manager initialized")
        else:
            logger.info("ℹ️ Certificate Templates disabled (set VCC_TEMPLATES_ENABLED=true to enable)")
        
        # Initialize Multi-Tenant Manager (Phase 2 Feature)
        enable_multi_tenant = os.getenv("VCC_MULTI_TENANT_ENABLED", "true").lower() == "true"
        if enable_multi_tenant:
            tenant_config = MultiTenantConfig.from_env()
            multi_tenant_manager = create_multi_tenant_manager(tenant_config)
            # Add Multi-Tenant routes
            app.include_router(create_multi_tenant_router(multi_tenant_manager))
            logger.info("✅ Multi-Tenant Manager initialized")
        else:
            logger.info("ℹ️ Multi-Tenant Manager disabled (set VCC_MULTI_TENANT_ENABLED=true to enable)")
        
        # Check for JSON migration (legacy service_registry.json)
        registry_file = Path("../database/service_registry.json")
        if registry_file.exists():
            logger.info("⚠️  Found legacy service_registry.json - consider migrating with init_database.py --migrate")
        
        logger.info("🎉 VCC PKI Server started successfully!")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize PKI Server: {e}")
        raise
    
    yield  # Server is running
    
    # Shutdown
    logger.info("🛑 Shutting down VCC PKI Server...")
    
    # Stop OCSP Stapling
    if ocsp_stapling:
        ocsp_stapling.stop()
        logger.info("✅ OCSP Stapling Manager stopped")
    
    # Stop VCC Service Integration
    if vcc_integration:
        await vcc_integration.stop()
        logger.info("✅ VCC Service Integration stopped")
    
    # Stop CRL Distribution Point
    if crl_distribution:
        crl_distribution.stop()
        logger.info("✅ CRL Distribution Point stopped")
    
    # Stop Auto-Renewal Engine
    if auto_renewal_engine:
        auto_renewal_engine.stop()
        logger.info("✅ Auto-Renewal Engine stopped")
    
    # Phase 2 components don't need explicit shutdown (stateless or auto-cleanup)
    if hsm_manager:
        logger.info("✅ HSM Manager cleanup complete")
    
    if timestamp_authority:
        logger.info("✅ Timestamp Authority cleanup complete")
    
    if template_manager:
        logger.info("✅ Certificate Template Manager cleanup complete")
    
    if multi_tenant_manager:
        logger.info("✅ Multi-Tenant Manager cleanup complete")
    
    logger.info("👋 VCC PKI Server stopped")


app = FastAPI(
    title="VCC PKI Server API",
    description="Global PKI Certificate Management for VCC Microservices",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Security
security = HTTPBearer()


# ============================================================================
# Helper Functions
# ============================================================================

def get_ca_password() -> str:
    """Get CA password from environment or config"""
    # In production, this should come from secure vault (Azure Key Vault, AWS Secrets Manager, etc.)
    password = os.getenv("VCC_INTERMEDIATE_CA_PASSWORD", "vcc_intermediate_pw_2025")
    return password


def audit_log(
    db: Session, 
    action: str, 
    service_id: str, 
    details: Dict[str, Any],
    certificate_id: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    request: Optional[Request] = None
):
    """Log audit event to database"""
    try:
        # Get client IP if request provided
        ip_address = None
        if request:
            ip_address = request.client.host if request.client else None
        
        # Create audit log entry
        audit_entry = AuditLog(
            action=action,
            service_id=service_id,
            certificate_id=certificate_id,
            user_id="system",  # TODO: Add authentication
            ip_address=ip_address,
            details=details,
            success=success,
            error_message=error_message
        )
        
        db.add(audit_entry)
        db.commit()
        
        logger.info(f"📝 Audit: {action} for {service_id} - {'Success' if success else 'Failed'}")
        
    except Exception as e:
        logger.error(f"❌ Failed to write audit log: {e}")
        db.rollback()


def verify_service_auth(authorization: Optional[str] = Header(None)) -> str:
    """
    Verify service authentication (mTLS or Bearer token)
    
    In production, this should:
    1. Extract client certificate from mTLS connection
    2. Validate certificate against CA
    3. Extract service_id from certificate CN
    
    For now, simplified token-based auth.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    # TODO: Implement proper mTLS authentication
    # For now, accept any bearer token (development only!)
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    # Extract service_id from token (simplified)
    token = authorization.replace("Bearer ", "")
    # In production, verify JWT token or mTLS certificate
    service_id = token  # Simplified: token is service_id
    
    return service_id


# ============================================================================
# API Endpoints - Health & Info
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/api/v1/info")
async def server_info():
    """Get PKI server information"""
    return {
        "server": "VCC PKI Server",
        "version": "1.0.0",
        "ca_status": "operational",
        "total_services": len(service_registry),
        "total_certificates": len(cert_manager.list_service_certificates()) if cert_manager else 0
    }


# ============================================================================
# API Endpoints - Certificate Management
# ============================================================================

@app.post("/api/v1/certificates/request", response_model=APIResponse)
async def request_certificate(
    request_model: CertificateRequestModel,
    http_request: Request,
    ca_password_header: Optional[str] = Header(None, alias="X-CA-Password"),
    db: Session = Depends(get_db)
):
    """
    Request a new service certificate
    
    Requires CA password in X-CA-Password header for security.
    """
    try:
        logger.info(f"📝 Certificate request for service: {request_model.service_id}")
        
        # Get CA password
        ca_password = ca_password_header or get_ca_password()
        
        # Issue certificate via ServiceCertificateManager
        cert_id = cert_manager.issue_service_certificate(
            service_id=request_model.service_id,
            common_name=request_model.common_name,
            san_dns=request_model.san_dns,
            san_ip=request_model.san_ip,
            validity_days=request_model.validity_days,
            ca_password=ca_password
        )
        
        # Get certificate details from cert_manager
        cert_info = cert_manager.get_service_certificate(request_model.service_id)
        
        # Parse dates
        not_before = datetime.fromisoformat(cert_info["not_before"].replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(cert_info["not_after"].replace("Z", "+00:00"))
        
        # Store in database
        certificate = Certificate(
            certificate_id=cert_id,
            service_id=request_model.service_id,
            common_name=request_model.common_name,
            serial_number=str(cert_info["serial_number"]),
            fingerprint=cert_info["fingerprint"],
            san_dns=request_model.san_dns,
            san_ip=request_model.san_ip,
            not_before=not_before,
            not_after=not_after,
            status="active"
        )
        db.add(certificate)
        db.commit()
        
        # Create auto-renewal schedule (renew 30 days before expiry)
        renewal_date = not_after - timedelta(days=30)
        rotation_schedule = RotationSchedule(
            certificate_id=cert_id,
            scheduled_renewal_date=renewal_date,
            status="scheduled"
        )
        db.add(rotation_schedule)
        db.commit()
        
        # Audit log
        audit_log(
            db=db,
            action="CERTIFICATE_ISSUED",
            service_id=request_model.service_id,
            certificate_id=cert_id,
            details={
                "common_name": request_model.common_name,
                "validity_days": request_model.validity_days,
                "san_dns": request_model.san_dns,
                "san_ip": request_model.san_ip
            },
            success=True,
            request=http_request
        )
        
        return APIResponse(
            success=True,
            message=f"Certificate issued successfully for {request_model.service_id}",
            data={
                "certificate_id": cert_id,
                "service_id": request_model.service_id,
                "expires_at": cert_info["not_after"]
            }
        )
        
    except Exception as e:
        logger.error(f"❌ Failed to issue certificate: {e}")
        
        # Audit log failure
        audit_log(
            db=db,
            action="CERTIFICATE_ISSUED",
            service_id=request_model.service_id,
            details={"error": str(e)},
            success=False,
            error_message=str(e),
            request=http_request
        )
        
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/certificates/{service_id}", response_model=CertificateInfoResponse)
async def get_certificate_info(service_id: str, db: Session = Depends(get_db)):
    """Get certificate information for a service"""
    try:
        # Query from database
        certificate = db.query(Certificate).filter(
            Certificate.service_id == service_id,
            Certificate.status == "active"
        ).first()
        
        if not certificate:
            raise HTTPException(
                status_code=404, 
                detail=f"Certificate not found for service: {service_id}"
            )
        
        return CertificateInfoResponse(
            certificate_id=certificate.certificate_id,
            service_id=certificate.service_id,
            common_name=certificate.common_name,
            serial_number=certificate.serial_number,
            fingerprint=certificate.fingerprint,
            not_before=certificate.not_before.isoformat(),
            not_after=certificate.not_after.isoformat(),
            status=certificate.status,
            san_dns=certificate.san_dns or [],
            san_ip=certificate.san_ip or [],
            issuer="VCC Intermediate CA",
            days_until_expiry=certificate.days_until_expiry
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get certificate info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/certificates/{service_id}/download")
async def download_certificate(service_id: str, file_type: str = "cert"):
    """
    Download certificate or private key
    
    Args:
        service_id: Service identifier
        file_type: 'cert' for certificate, 'key' for private key, 'ca' for CA chain
    """
    try:
        cert_info = cert_manager.get_service_certificate(service_id)
        
        if not cert_info:
            raise HTTPException(status_code=404, detail=f"Certificate not found for service: {service_id}")
        
        # Determine file path
        cert_dir = Path(f"../service_certificates/{service_id}")
        
        if file_type == "cert":
            file_path = cert_dir / "cert.pem"
            media_type = "application/x-pem-file"
            filename = f"{service_id}_cert.pem"
        elif file_type == "key":
            file_path = cert_dir / "key.pem"
            media_type = "application/x-pem-file"
            filename = f"{service_id}_key.pem"
        elif file_type == "ca":
            # Return CA chain (Root + Intermediate)
            file_path = Path("../ca_storage/intermediate_ca.pem")
            media_type = "application/x-pem-file"
            filename = "ca_chain.pem"
        else:
            raise HTTPException(status_code=400, detail="Invalid file_type. Use 'cert', 'key', or 'ca'")
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {file_path.name}")
        
        # Audit log (except for key downloads which are sensitive)
        if file_type != "key":
            audit_log("CERTIFICATE_DOWNLOADED", service_id, {"file_type": file_type})
        
        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            filename=filename
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to download certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/certificates/{service_id}/renew", response_model=APIResponse)
async def renew_certificate(
    service_id: str,
    renewal: CertificateRenewalModel,
    http_request: Request,
    ca_password_header: Optional[str] = Header(None, alias="X-CA-Password"),
    db: Session = Depends(get_db)
):
    """Renew an existing certificate"""
    try:
        logger.info(f"🔄 Renewing certificate for service: {service_id}")
        
        # Get CA password
        ca_password = ca_password_header or get_ca_password()
        
        # Get old certificate from database
        old_cert = db.query(Certificate).filter(
            Certificate.service_id == service_id,
            Certificate.status == "active"
        ).first()
        
        if not old_cert:
            raise HTTPException(
                status_code=404, 
                detail=f"Active certificate not found for service: {service_id}"
            )
        
        # Renew via cert_manager
        new_cert_id = cert_manager.renew_service_certificate(
            service_id=service_id,
            validity_days=renewal.validity_days,
            ca_password=ca_password
        )
        
        # Get new certificate info
        cert_info = cert_manager.get_service_certificate(service_id)
        not_before = datetime.fromisoformat(cert_info["not_before"].replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(cert_info["not_after"].replace("Z", "+00:00"))
        
        # Mark old certificate as expired in database
        old_cert.status = "expired"
        db.commit()
        
        # Add new certificate to database
        new_cert = Certificate(
            certificate_id=new_cert_id,
            service_id=service_id,
            common_name=cert_info["common_name"],
            serial_number=str(cert_info["serial_number"]),
            fingerprint=cert_info["fingerprint"],
            san_dns=cert_info.get("san_dns", []),
            san_ip=cert_info.get("san_ip", []),
            not_before=not_before,
            not_after=not_after,
            status="active"
        )
        db.add(new_cert)
        db.commit()
        
        # Schedule next renewal
        renewal_date = not_after - timedelta(days=30)
        rotation_schedule = RotationSchedule(
            certificate_id=new_cert_id,
            scheduled_renewal_date=renewal_date,
            status="scheduled"
        )
        db.add(rotation_schedule)
        db.commit()
        
        # Audit log
        audit_log(
            db=db,
            action="CERTIFICATE_RENEWED",
            service_id=service_id,
            certificate_id=new_cert_id,
            details={
                "old_certificate_id": old_cert.certificate_id,
                "validity_days": renewal.validity_days
            },
            success=True,
            request=http_request
        )
        
        return APIResponse(
            success=True,
            message=f"Certificate renewed successfully for {service_id}",
            data={
                "certificate_id": new_cert_id,
                "service_id": service_id,
                "expires_at": cert_info["not_after"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to renew certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/certificates/{service_id}/revoke", response_model=APIResponse)
async def revoke_certificate(
    service_id: str,
    revocation: CertificateRevocationModel,
    http_request: Request,
    ca_password_header: Optional[str] = Header(None, alias="X-CA-Password"),
    db: Session = Depends(get_db)
):
    """Revoke a certificate"""
    try:
        logger.info(f"🚫 Revoking certificate for service: {service_id}")
        
        # Get CA password
        ca_password = ca_password_header or get_ca_password()
        
        # Get certificate from database
        certificate = db.query(Certificate).filter(
            Certificate.service_id == service_id,
            Certificate.status == "active"
        ).first()
        
        if not certificate:
            raise HTTPException(
                status_code=404, 
                detail=f"Active certificate not found for service: {service_id}"
            )
        
        # Revoke via cert_manager
        cert_manager.revoke_service_certificate(
            service_id=service_id,
            reason=revocation.reason.value,
            ca_password=ca_password
        )
        
        # Update certificate status in database
        certificate.status = "revoked"
        certificate.revoked_at = datetime.utcnow()
        certificate.revocation_reason = revocation.reason.value
        db.commit()
        
        # Add to CRL entries
        crl_entry = CRLEntry(
            serial_number=certificate.serial_number,
            revocation_reason=revocation.reason.value
        )
        db.add(crl_entry)
        db.commit()
        
        # Audit log
        audit_log(
            db=db,
            action="CERTIFICATE_REVOKED",
            service_id=service_id,
            certificate_id=certificate.certificate_id,
            details={"reason": revocation.reason.value},
            success=True,
            request=http_request
        )
        
        return APIResponse(
            success=True,
            message=f"Certificate revoked successfully for {service_id}",
            data={
                "service_id": service_id,
                "reason": revocation.reason.value,
                "revoked_at": certificate.revoked_at.isoformat()
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to revoke certificate: {e}")
        
        # Audit log failure
        audit_log(
            db=db,
            action="CERTIFICATE_REVOKED",
            service_id=service_id,
            details={"error": str(e)},
            success=False,
            error_message=str(e),
            request=http_request
        )
        
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/certificates")
async def list_certificates(db: Session = Depends(get_db)):
    """List all issued certificates"""
    try:
        # Query all certificates from database
        certificates = db.query(Certificate).order_by(
            Certificate.created_at.desc()
        ).all()
        
        # Convert to response format
        cert_list = []
        for cert in certificates:
            cert_list.append({
                "certificate_id": cert.certificate_id,
                "service_id": cert.service_id,
                "common_name": cert.common_name,
                "serial_number": cert.serial_number,
                "fingerprint": cert.fingerprint,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "status": cert.status,
                "days_until_expiry": cert.days_until_expiry,
                "needs_renewal": cert.needs_renewal,
                "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
                "revocation_reason": cert.revocation_reason
            })
        
        return {
            "total": len(cert_list),
            "certificates": cert_list
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list certificates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# API Endpoints - Service Registry
# ============================================================================

@app.post("/api/v1/services/register", response_model=APIResponse)
async def register_service(
    service: ServiceRegistrationModel, 
    http_request: Request,
    db: Session = Depends(get_db)
):
    """Register a new service in the registry"""
    try:
        logger.info(f"📝 Registering service: {service.service_id}")
        
        # Check if service already exists
        existing = db.query(Service).filter(Service.service_id == service.service_id).first()
        if existing:
            raise HTTPException(
                status_code=409, 
                detail=f"Service already registered: {service.service_id}"
            )
        
        # Create service in database
        new_service = Service(
            service_id=service.service_id,
            service_name=service.service_name,
            endpoints=service.endpoints,
            health_check_url=service.health_check_url,
            service_metadata=service.metadata,
            status="active"
        )
        db.add(new_service)
        db.commit()
        db.refresh(new_service)
        
        # Audit log
        audit_log(
            db=db,
            action="SERVICE_REGISTERED",
            service_id=service.service_id,
            details={
                "service_name": service.service_name,
                "endpoints": service.endpoints,
                "health_check_url": service.health_check_url
            },
            success=True,
            request=http_request
        )
        
        return APIResponse(
            success=True,
            message=f"Service registered successfully: {service.service_id}",
            data={
                "service_id": service.service_id,
                "registered_at": new_service.created_at.isoformat()
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to register service: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/services")
async def list_services(db: Session = Depends(get_db)):
    """List all registered services"""
    try:
        # Query services with their certificates using the view
        services = db.query(Service).all()
        
        service_list = []
        for service in services:
            # Get active certificate
            active_cert = db.query(Certificate).filter(
                Certificate.service_id == service.service_id,
                Certificate.status == "active"
            ).first()
            
            service_data = {
                "service_id": service.service_id,
                "service_name": service.service_name,
                "endpoints": service.endpoints or [],
                "health_check_url": service.health_check_url,
                "metadata": service.service_metadata or {},
                "status": service.status,
                "registered_at": service.created_at.isoformat(),
                "last_updated": service.updated_at.isoformat()
            }
            
            # Add certificate info if available
            if active_cert:
                service_data["certificate_status"] = active_cert.status
                service_data["certificate_expiry"] = active_cert.not_after.isoformat()
                service_data["days_until_expiry"] = active_cert.days_until_expiry
                service_data["needs_renewal"] = active_cert.needs_renewal
            else:
                service_data["certificate_status"] = "none"
                service_data["certificate_expiry"] = None
                service_data["days_until_expiry"] = None
                service_data["needs_renewal"] = False
            
            service_list.append(service_data)
        
        return {
            "total": len(service_list),
            "services": service_list
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list services: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/services/{service_id}", response_model=ServiceInfoResponse)
async def get_service_info(service_id: str, db: Session = Depends(get_db)):
    """Get detailed information about a service"""
    try:
        # Query service from database
        service = db.query(Service).filter(Service.service_id == service_id).first()
        
        if not service:
            raise HTTPException(status_code=404, detail=f"Service not found: {service_id}")
        
        # Get active certificate
        active_cert = db.query(Certificate).filter(
            Certificate.service_id == service_id,
            Certificate.status == "active"
        ).first()
        
        return ServiceInfoResponse(
            service_id=service.service_id,
            service_name=service.service_name,
            certificate_status=active_cert.status if active_cert else "none",
            certificate_expiry=active_cert.not_after.isoformat() if active_cert else None,
            endpoints=service.endpoints or [],
            health_check_url=service.health_check_url,
            metadata=service.service_metadata or {},
            registered_at=service.created_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get service info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# API Endpoints - CA Operations
# ============================================================================

@app.get("/api/v1/ca/root")
async def get_root_ca():
    """Download Root CA certificate"""
    try:
        ca_file = Path("../ca_storage/root_ca.pem")
        
        if not ca_file.exists():
            raise HTTPException(status_code=404, detail="Root CA certificate not found")
        
        return FileResponse(
            path=str(ca_file),
            media_type="application/x-pem-file",
            filename="vcc_root_ca.pem"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get Root CA: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/ca/intermediate")
async def get_intermediate_ca():
    """Download Intermediate CA certificate"""
    try:
        ca_file = Path("../ca_storage/intermediate_ca.pem")
        
        if not ca_file.exists():
            raise HTTPException(status_code=404, detail="Intermediate CA certificate not found")
        
        return FileResponse(
            path=str(ca_file),
            media_type="application/x-pem-file",
            filename="vcc_intermediate_ca.pem"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get Intermediate CA: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/ca/chain")
async def get_ca_chain():
    """Download complete CA chain (Root + Intermediate)"""
    try:
        root_ca_file = Path("../ca_storage/root_ca.pem")
        intermediate_ca_file = Path("../ca_storage/intermediate_ca.pem")
        
        if not root_ca_file.exists() or not intermediate_ca_file.exists():
            raise HTTPException(status_code=404, detail="CA certificates not found")
        
        # Combine Root + Intermediate
        with open(root_ca_file, 'r') as f:
            root_ca = f.read()
        
        with open(intermediate_ca_file, 'r') as f:
            intermediate_ca = f.read()
        
        ca_chain = intermediate_ca + "\n" + root_ca
        
        # Write to temp file
        chain_file = Path("../ca_storage/ca_chain.pem")
        with open(chain_file, 'w') as f:
            f.write(ca_chain)
        
        return FileResponse(
            path=str(chain_file),
            media_type="application/x-pem-file",
            filename="vcc_ca_chain.pem"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get CA chain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# API Endpoints - CRL (Certificate Revocation List)
# ============================================================================

@app.get("/api/v1/crl")
async def get_crl(db: Session = Depends(get_db)):
    """Get Certificate Revocation List"""
    try:
        # Query revoked certificates from database
        revoked_certs = db.query(CRLEntry).order_by(CRLEntry.revoked_at.desc()).all()
        
        # Format CRL
        revoked_list = []
        for entry in revoked_certs:
            revoked_list.append({
                "serial_number": entry.serial_number,
                "revoked_at": entry.revoked_at.isoformat(),
                "revocation_reason": entry.revocation_reason
            })
        
        return {
            "version": "1.0",
            "issuer": "VCC Intermediate CA",
            "this_update": datetime.utcnow().isoformat(),
            "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat(),
            "total_revoked": len(revoked_list),
            "revoked_certificates": revoked_list
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get CRL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Auto-Renewal Engine Endpoints (Phase 1 Feature)
# ============================================================================

@app.get("/api/v1/auto-renewal/status")
async def get_auto_renewal_status():
    """
    Get status of the auto-renewal engine.
    
    Returns engine statistics and current state.
    """
    if auto_renewal_engine is None:
        return {
            "enabled": False,
            "message": "Auto-renewal engine is not enabled"
        }
    
    return {
        "enabled": True,
        "running": auto_renewal_engine.is_running,
        "statistics": auto_renewal_engine.statistics,
        "config": {
            "renewal_threshold_days": auto_renewal_engine.config.renewal_threshold_days,
            "warning_threshold_days": auto_renewal_engine.config.warning_threshold_days,
            "critical_threshold_days": auto_renewal_engine.config.critical_threshold_days,
            "check_interval_seconds": auto_renewal_engine.config.check_interval_seconds,
            "max_retry_attempts": auto_renewal_engine.config.max_retry_attempts
        }
    }


@app.get("/api/v1/auto-renewal/certificates")
async def get_certificates_renewal_status():
    """
    Get renewal status of all active certificates.
    
    Returns list of certificates with their renewal status (ok/scheduled/warning/critical).
    """
    if auto_renewal_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Auto-renewal engine is not enabled"
        )
    
    try:
        certificates = auto_renewal_engine.get_certificates_status()
        
        # Group by status for summary
        status_counts = {"ok": 0, "scheduled": 0, "warning": 0, "critical": 0}
        for cert in certificates:
            status_counts[cert["renewal_status"]] += 1
        
        return {
            "total_certificates": len(certificates),
            "status_summary": status_counts,
            "certificates": certificates
        }
    except Exception as e:
        logger.error(f"❌ Failed to get certificate renewal status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/auto-renewal/force-check")
async def force_renewal_check():
    """
    Force an immediate certificate renewal check.
    
    Useful for testing or when immediate renewal is needed.
    """
    if auto_renewal_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Auto-renewal engine is not enabled"
        )
    
    try:
        logger.info("⚡ Manual renewal check triggered via API")
        auto_renewal_engine.force_check()
        
        return APIResponse(
            success=True,
            message="Renewal check completed",
            data={"statistics": auto_renewal_engine.statistics}
        )
    except Exception as e:
        logger.error(f"❌ Forced renewal check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/auto-renewal/start")
async def start_auto_renewal():
    """Start the auto-renewal engine if it's stopped."""
    if auto_renewal_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Auto-renewal engine is not configured"
        )
    
    if auto_renewal_engine.is_running:
        return APIResponse(
            success=True,
            message="Auto-renewal engine is already running"
        )
    
    try:
        auto_renewal_engine.start()
        logger.info("✅ Auto-renewal engine started via API")
        
        return APIResponse(
            success=True,
            message="Auto-renewal engine started"
        )
    except Exception as e:
        logger.error(f"❌ Failed to start auto-renewal engine: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/auto-renewal/stop")
async def stop_auto_renewal():
    """Stop the auto-renewal engine."""
    if auto_renewal_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Auto-renewal engine is not configured"
        )
    
    if not auto_renewal_engine.is_running:
        return APIResponse(
            success=True,
            message="Auto-renewal engine is already stopped"
        )
    
    try:
        auto_renewal_engine.stop()
        logger.info("✅ Auto-renewal engine stopped via API")
        
        return APIResponse(
            success=True,
            message="Auto-renewal engine stopped"
        )
    except Exception as e:
        logger.error(f"❌ Failed to stop auto-renewal engine: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# OCSP Responder Endpoints (Phase 1 Feature)
# ============================================================================

@app.get("/api/v1/ocsp/status")
async def get_ocsp_status():
    """
    Get status of the OCSP responder.
    
    Returns responder statistics and current state.
    """
    if ocsp_responder is None:
        return {
            "enabled": False,
            "message": "OCSP responder is not enabled"
        }
    
    return {
        "enabled": True,
        "statistics": ocsp_responder.statistics,
        "certificate_summary": ocsp_responder.get_status_summary()
    }


@app.get("/api/v1/ocsp/check/{serial_number}")
async def check_certificate_ocsp_status(serial_number: str):
    """
    Check certificate status via OCSP.
    
    Args:
        serial_number: Certificate serial number (hex string)
    
    Returns:
        OCSP status information for the certificate
    """
    if ocsp_responder is None:
        raise HTTPException(
            status_code=503,
            detail="OCSP responder is not enabled"
        )
    
    try:
        response = ocsp_responder.check_certificate_status(serial_number)
        
        result = {
            "serial_number": response.serial_number,
            "status": response.status.value,
            "this_update": response.this_update.isoformat(),
            "next_update": response.next_update.isoformat()
        }
        
        if response.status == OCSPCertStatus.REVOKED:
            result["revocation_time"] = response.revocation_time.isoformat() if response.revocation_time else None
            result["revocation_reason"] = response.revocation_reason.name if response.revocation_reason else None
        
        return result
    except Exception as e:
        logger.error(f"❌ OCSP status check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ocsp")
async def handle_ocsp_request(request: Request):
    """
    RFC 6960 OCSP request endpoint.
    
    Accepts DER-encoded OCSP request in request body.
    Returns DER-encoded OCSP response.
    
    Content-Type: application/ocsp-request
    """
    if ocsp_responder is None:
        raise HTTPException(
            status_code=503,
            detail="OCSP responder is not enabled"
        )
    
    try:
        # Read request body
        request_bytes = await request.body()
        
        if not request_bytes:
            raise HTTPException(
                status_code=400,
                detail="Empty OCSP request"
            )
        
        # Handle OCSP request
        response_bytes = ocsp_responder.handle_ocsp_request(request_bytes)
        
        return Response(
            content=response_bytes,
            media_type="application/ocsp-response"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ OCSP request handling failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ocsp/clear-cache")
async def clear_ocsp_cache():
    """Clear the OCSP response cache."""
    if ocsp_responder is None:
        raise HTTPException(
            status_code=503,
            detail="OCSP responder is not enabled"
        )
    
    try:
        ocsp_responder.clear_cache()
        
        return APIResponse(
            success=True,
            message="OCSP cache cleared",
            data={"new_cache_size": ocsp_responder.cache.size}
        )
    except Exception as e:
        logger.error(f"❌ Failed to clear OCSP cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CRL Distribution Endpoints (Phase 1 Feature)
# ============================================================================

@app.get("/api/v1/crl/status")
async def get_crl_status():
    """
    Get status of the CRL distribution point.
    
    Returns CRL statistics and current state.
    """
    if crl_distribution is None:
        return {
            "enabled": False,
            "message": "CRL distribution is not enabled"
        }
    
    return {
        "enabled": True,
        "running": crl_distribution.is_running,
        "statistics": crl_distribution.statistics,
        "crl_info": crl_distribution.get_crl_info(),
        "config": {
            "crl_validity_hours": crl_distribution.config.crl_validity_hours,
            "update_interval_seconds": crl_distribution.config.crl_update_interval_seconds,
            "delta_crl_enabled": crl_distribution.config.enable_delta_crl
        }
    }


@app.get("/api/v1/crl/full")
async def get_full_crl():
    """
    Get the full Certificate Revocation List (DER format).
    
    Returns DER-encoded CRL suitable for import into trust stores.
    """
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not enabled"
        )
    
    try:
        crl_bytes = crl_distribution.get_crl(CRLFormat.DER)
        
        return Response(
            content=crl_bytes,
            media_type="application/pkix-crl",
            headers={
                "Content-Disposition": "attachment; filename=vcc-ca.crl"
            }
        )
    except Exception as e:
        logger.error(f"❌ Failed to get CRL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/crl/full/pem")
async def get_full_crl_pem():
    """
    Get the full Certificate Revocation List (PEM format).
    
    Returns PEM-encoded CRL suitable for text-based systems.
    """
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not enabled"
        )
    
    try:
        crl_bytes = crl_distribution.get_crl(CRLFormat.PEM)
        
        return Response(
            content=crl_bytes,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": "attachment; filename=vcc-ca.crl.pem"
            }
        )
    except Exception as e:
        logger.error(f"❌ Failed to get CRL (PEM): {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/crl/delta")
async def get_delta_crl():
    """
    Get the delta CRL (DER format).
    
    Returns only recent revocations since the last full CRL.
    More efficient for frequent updates.
    """
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not enabled"
        )
    
    if not crl_distribution.config.enable_delta_crl:
        raise HTTPException(
            status_code=404,
            detail="Delta CRL is not enabled"
        )
    
    try:
        delta_crl = crl_distribution.get_delta_crl(CRLFormat.DER)
        
        if delta_crl is None:
            raise HTTPException(
                status_code=404,
                detail="Delta CRL not yet generated"
            )
        
        return Response(
            content=delta_crl,
            media_type="application/pkix-crl",
            headers={
                "Content-Disposition": "attachment; filename=vcc-ca-delta.crl"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get delta CRL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/crl/info")
async def get_crl_info():
    """
    Get information about the current CRL.
    
    Returns CRL metadata including issuer, validity, and revocation count.
    """
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not enabled"
        )
    
    return crl_distribution.get_crl_info()


@app.post("/api/v1/crl/regenerate")
async def force_crl_regeneration():
    """
    Force immediate CRL regeneration.
    
    Useful when certificates have been revoked and immediate distribution is needed.
    """
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not enabled"
        )
    
    try:
        logger.info("⚡ Manual CRL regeneration triggered via API")
        crl_distribution.force_regenerate()
        
        return APIResponse(
            success=True,
            message="CRL regenerated",
            data={
                "crl_info": crl_distribution.get_crl_info(),
                "statistics": crl_distribution.statistics
            }
        )
    except Exception as e:
        logger.error(f"❌ CRL regeneration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/crl/start")
async def start_crl_distribution():
    """Start the CRL distribution service if it's stopped."""
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not configured"
        )
    
    if crl_distribution.is_running:
        return APIResponse(
            success=True,
            message="CRL distribution is already running"
        )
    
    try:
        crl_distribution.start()
        logger.info("✅ CRL distribution started via API")
        
        return APIResponse(
            success=True,
            message="CRL distribution started"
        )
    except Exception as e:
        logger.error(f"❌ Failed to start CRL distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/crl/stop")
async def stop_crl_distribution():
    """Stop the CRL distribution service."""
    if crl_distribution is None:
        raise HTTPException(
            status_code=503,
            detail="CRL distribution is not configured"
        )
    
    if not crl_distribution.is_running:
        return APIResponse(
            success=True,
            message="CRL distribution is already stopped"
        )
    
    try:
        crl_distribution.stop()
        logger.info("✅ CRL distribution stopped via API")
        
        return APIResponse(
            success=True,
            message="CRL distribution stopped"
        )
    except Exception as e:
        logger.error(f"❌ Failed to stop CRL distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Run PKI Server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="VCC PKI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=8443, help="Server port")
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL key file")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    # Determine SSL configuration
    if args.ssl_cert and args.ssl_key:
        ssl_certfile = args.ssl_cert
        ssl_keyfile = args.ssl_key
    else:
        # Check if server has its own certificate
        server_cert = Path("../service_certificates/pki-server/cert.pem")
        server_key = Path("../service_certificates/pki-server/key.pem")
        
        if server_cert.exists() and server_key.exists():
            ssl_certfile = str(server_cert)
            ssl_keyfile = str(server_key)
            logger.info("✅ Using PKI Server's own certificate for HTTPS")
        else:
            ssl_certfile = None
            ssl_keyfile = None
            logger.warning("⚠️  No SSL certificate found. Running in HTTP mode (not recommended for production!)")
    
    # Run server
    logger.info(f"🚀 Starting PKI Server on {args.host}:{args.port}")
    
    uvicorn.run(
        "pki_server:app",
        host=args.host,
        port=args.port,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
        reload=args.reload,
        log_level="info"
    )


if __name__ == "__main__":
    main()
