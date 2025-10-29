# VCC PKI System - FastAPI Main Application
# Production-ready PKI API server with comprehensive endpoints

from fastapi import FastAPI, HTTPException, Depends, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
import time
from datetime import datetime
from pathlib import Path
import os
import uvicorn

# Import core components
from app.core.config import VCCPKIConfig, create_config
from app.core.database import VCCPKIDatabase
from app.services.crypto_service import VCCCryptoService
from app.services.pki_service import VCCPKIService
from app.core.security import SecurityManager, UserContext, Permission, create_permission_checker
from app.api import api_router
from app.models import *
from app.services.timestamp_authority import VCCTimestampAuthorityFactory
from app.api.v1.tsa import initialize_tsa_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

# Global app state
class AppState:
    def __init__(self):
        self.config: VCCPKIConfig = None
        self.database: VCCPKIDatabase = None
        self.crypto_service: VCCCryptoService = None
        self.pki_service: VCCPKIService = None
        self.security_manager: SecurityManager = None
        self.startup_time = None

app_state = AppState()

# FastAPI app
app = FastAPI(
    title="VCC PKI System API",
    description="Production-ready Public Key Infrastructure for VCC Ecosystem",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Include API routers
app.include_router(api_router)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.vcc.internal"]
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request
    logger.info(f"📥 {request.method} {request.url.path} from {request.client.host}")
    
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(f"📤 {request.method} {request.url.path} -> {response.status_code} ({process_time:.3f}s)")
    
    # Add timing header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# Dependency injection
def get_pki_service() -> VCCPKIService:
    """Get PKI service instance"""
    if not app_state.pki_service:
        raise HTTPException(status_code=503, detail="PKI service not initialized")
    return app_state.pki_service

def get_database() -> VCCPKIDatabase:
    """Get database instance"""
    if not app_state.database:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return app_state.database

def get_security_manager() -> SecurityManager:
    """Get security manager instance"""
    if not app_state.security_manager:
        raise HTTPException(status_code=503, detail="Security manager not initialized")
    return app_state.security_manager

# Security integration - use SecurityManager for all authentication
def get_current_user() -> UserContext:
    """Get current user - delegates to SecurityManager"""
    return app_state.security_manager.get_current_user

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize application components"""
    logger.info("🚀 Starting VCC PKI System...")
    
    try:
        # Load configuration
        environment = os.getenv("VCC_PKI_ENVIRONMENT", "development")
        app_state.config = create_config(environment)
        logger.info(f"   📋 Configuration loaded: {environment} mode")
        
        # Initialize database
        app_state.database = VCCPKIDatabase(
            app_state.config.database_path,
            app_state.config.database_encryption_key
        )
        logger.info("   🗄️  Database initialized")
        
        # Initialize crypto service
        app_state.crypto_service = VCCCryptoService(app_state.config)
        logger.info("   🔐 Cryptographic service initialized")
        
        # Initialize security manager
        app_state.security_manager = SecurityManager(app_state.config)
        logger.info("   🔒 Security manager initialized")
        
        # Initialize PKI service
        app_state.pki_service = VCCPKIService(
            app_state.config, 
            app_state.database, 
            app_state.crypto_service
        )
        logger.info("   🏛️  PKI service initialized")
        
        app_state.startup_time = datetime.utcnow()
        
        # Initialize TSA Service
        logger.info("   🕐 Initializing TSA service...")
        await initialize_tsa_service()
        logger.info("   🕐 TSA service initialized")
        
        # Log initialization summary
        stats = app_state.database.get_database_stats()
        logger.info("   📊 System Status:")
        logger.info(f"      - Services: {stats.get('vcc_services_count', 0)}")
        logger.info(f"      - Certificates: {stats.get('certificates_count', 0)}")
        logger.info(f"      - Organizations: {stats.get('organizations_count', 0)}")
        
        logger.info("✅ VCC PKI System with TSA startup completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down VCC PKI System...")
    logger.info("✅ Shutdown completed")

# Health and Status Endpoints
@app.get("/health", response_model=APIResponse)
async def health_check():
    """Basic health check endpoint"""
    return create_success_response(
        data={"status": "healthy", "timestamp": datetime.utcnow().isoformat()},
        message="VCC PKI System is operational"
    )

@app.get("/status", response_model=APIResponse)
async def system_status(
    pki_service: VCCPKIService = Depends(get_pki_service),
    current_user: UserContext = Depends(create_permission_checker(Permission.SYSTEM_HEALTH))
):
    """Comprehensive system status"""
    health_result = pki_service.get_system_health()
    
    if health_result.success:
        uptime_hours = (datetime.utcnow() - app_state.startup_time).total_seconds() / 3600
        health_result.data["uptime_hours"] = round(uptime_hours, 2)
        health_result.data["mock_mode"] = app_state.config.mock_mode
        
    return health_result

# Organization Management Endpoints
@app.post("/api/v1/organizations", response_model=APIResponse)
async def create_organization(
    org_data: OrganizationCreate,
    current_user: UserContext = Depends(create_permission_checker(Permission.ORG_CREATE)),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Create new organization"""
    try:
        
        with db.get_connection() as conn:
            conn.execute("""
                INSERT INTO organizations (org_id, org_name, org_type, admin_contact, isolation_level)
                VALUES (?, ?, ?, ?, ?)
            """, (org_data.org_id, org_data.org_name, org_data.org_type, 
                  org_data.admin_contact, org_data.isolation_level))
        
        # Log audit event
        db.log_audit_event(
            event_type='org_created',
            event_category='admin',
            actor_identity=current_user.username,
            actor_type='user',
            target_resource=org_data.org_id,
            event_data={'org_name': org_data.org_name}
        )
        
        return create_success_response(
            data={'org_id': org_data.org_id},
            message=f"Organization '{org_data.org_name}' created successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to create organization: {e}")
        return create_error_response(f"Failed to create organization: {str(e)}", "ORG_CREATE_FAILED")

@app.get("/api/v1/organizations", response_model=APIResponse)
async def list_organizations(
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """List all organizations"""
    try:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            results = conn.execute("SELECT * FROM organizations WHERE active = TRUE ORDER BY org_name").fetchall()
            organizations = [dict(row) for row in results]
        
        return create_success_response(
            data=organizations,
            message=f"Found {len(organizations)} organizations"
        )
        
    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        return create_error_response(f"Failed to list organizations: {str(e)}", "ORG_LIST_FAILED")

# VCC Service Management Endpoints
@app.get("/api/v1/services", response_model=APIResponse)
async def list_vcc_services(
    organization_id: str = "brandenburg-gov",
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """List VCC services"""
    try:
        services = db.get_vcc_services(organization_id)
        return create_success_response(
            data=services,
            message=f"Found {len(services)} VCC services"
        )
        
    except Exception as e:
        logger.error(f"Failed to list services: {e}")
        return create_error_response(f"Failed to list services: {str(e)}", "SERVICE_LIST_FAILED")

@app.post("/api/v1/services", response_model=APIResponse)
async def register_vcc_service(
    service_data: VCCServiceCreate,
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Register new VCC service"""
    try:
        with db.get_connection() as conn:
            conn.execute("""
                INSERT INTO vcc_services (
                    service_id, service_name, service_type, endpoint_url, 
                    health_endpoint, organization_id, auto_cert_renewal, service_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                service_data.service_id, service_data.service_name, service_data.service_type,
                service_data.endpoint_url, service_data.health_endpoint, service_data.organization_id,
                service_data.auto_cert_renewal, "{}"
            ))
        
        # Log audit event
        db.log_audit_event(
            event_type='service_registered',
            event_category='service',
            actor_identity=current_user['user'],
            actor_type='user',
            target_resource=service_data.service_id,
            organization_id=service_data.organization_id,
            event_data={'service_name': service_data.service_name}
        )
        
        return create_success_response(
            data={'service_id': service_data.service_id},
            message=f"Service '{service_data.service_name}' registered successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to register service: {e}")
        return create_error_response(f"Failed to register service: {str(e)}", "SERVICE_REGISTER_FAILED")

# Certificate Authority Endpoints
@app.get("/api/v1/ca/list", response_model=APIResponse)
async def list_cas(
    organization_id: str = None,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """List certificate authorities"""
    return pki_service.list_certificate_authorities(organization_id)

@app.post("/api/v1/ca/create-issuing-ca", response_model=APIResponse)
async def create_issuing_ca(
    ca_data: CACreate,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """Create new issuing CA"""
    # TODO: Check admin permissions
    return pki_service.create_issuing_ca(ca_data)

# Certificate Management Endpoints
@app.post("/api/v1/certs/request", response_model=APIResponse)
async def request_certificate(
    cert_request: CertificateRequest,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """Request new certificate"""
    
    if cert_request.certificate_type == CertificatePurpose.vcc_service:
        return pki_service.issue_service_certificate(
            cert_request.service_id, 
            cert_request.organization_id
        )
    elif cert_request.certificate_type == CertificatePurpose.code_signing:
        return pki_service.issue_code_signing_certificate(
            cert_request.subject_data.get("common_name", "Unknown Signer"),
            cert_request.organization_id
        )
    else:
        return create_error_response("Certificate type not supported yet", "CERT_TYPE_NOT_SUPPORTED")

@app.get("/api/v1/certs/list", response_model=APIResponse)
async def list_certificates(
    organization_id: str = None,
    service_id: str = None,
    purpose: str = None,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """List certificates"""
    return pki_service.list_certificates(organization_id, service_id, purpose)

@app.post("/api/v1/certs/revoke/{cert_id}", response_model=APIResponse)
async def revoke_certificate(
    cert_id: str,
    revocation: CertificateRevocationRequest,
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Revoke certificate"""
    try:
        with db.get_connection() as conn:
            conn.execute("""
                UPDATE certificates 
                SET revoked_at = CURRENT_TIMESTAMP, revocation_reason = ?
                WHERE cert_id = ? AND revoked_at IS NULL
            """, (revocation.revocation_reason, cert_id))
            
            if conn.rowcount == 0:
                return create_error_response("Certificate not found or already revoked", "CERT_NOT_FOUND")
        
        # Log audit event
        db.log_audit_event(
            event_type='cert_revoked',
            event_category='certificate',
            actor_identity=current_user['user'],
            actor_type='user',
            target_resource=cert_id,
            event_data={'revocation_reason': revocation.revocation_reason}
        )
        
        return create_success_response(
            data={'cert_id': cert_id, 'revoked_at': datetime.utcnow().isoformat()},
            message="Certificate revoked successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to revoke certificate: {e}")
        return create_error_response(f"Failed to revoke certificate: {str(e)}", "CERT_REVOKE_FAILED")

@app.get("/api/v1/certs/status/{cert_id}", response_model=APIResponse)
async def get_certificate_status(
    cert_id: str,
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Get certificate status"""
    try:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute("""
                SELECT cert_id, purpose, expires_at, revoked_at, revocation_reason, 
                       created_at, last_used, usage_count
                FROM certificates WHERE cert_id = ?
            """, (cert_id,)).fetchone()
            
            if not result:
                return create_error_response("Certificate not found", "CERT_NOT_FOUND")
            
            cert_info = dict(result)
            
            # Determine status
            now = datetime.utcnow()
            expires_at = datetime.fromisoformat(cert_info['expires_at'].replace('Z', '+00:00'))
            
            if cert_info['revoked_at']:
                status = "revoked"
            elif expires_at <= now:
                status = "expired"
            else:
                status = "active"
            
            cert_info['status'] = status
            cert_info['expires_in_days'] = (expires_at - now).days if status == 'active' else None
            
            return create_success_response(
                data=cert_info,
                message=f"Certificate status: {status}"
            )
            
    except Exception as e:
        logger.error(f"Failed to get certificate status: {e}")
        return create_error_response(f"Failed to get certificate status: {str(e)}", "CERT_STATUS_FAILED")

# Code Signing Endpoints
@app.post("/api/v1/sign/python-package", response_model=APIResponse)
async def sign_python_package(
    signing_request: CodeSigningRequest,
    cert_id: str,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """Sign Python package"""
    return pki_service.sign_code_artifact(signing_request, cert_id)

@app.post("/api/v1/verify/signature", response_model=APIResponse)
async def verify_signature(
    verification_request: CodeVerificationRequest,
    current_user: dict = Depends(verify_token),
    pki_service: VCCPKIService = Depends(get_pki_service)
):
    """Verify code signature"""
    return pki_service.verify_code_signature(verification_request)

@app.get("/api/v1/sign/audit/{signature_id}", response_model=APIResponse)
async def get_signature_audit(
    signature_id: str,
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Get signature audit information"""
    try:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute("""
                SELECT s.*, c.subject_dn, c.purpose, srv.service_name
                FROM vcc_code_signatures s
                LEFT JOIN certificates c ON s.cert_id = c.cert_id
                LEFT JOIN vcc_services srv ON s.service_id = srv.service_id
                WHERE s.signature_id = ?
            """, (signature_id,)).fetchone()
            
            if not result:
                return create_error_response("Signature not found", "SIGNATURE_NOT_FOUND")
            
            signature_info = dict(result)
            
            return create_success_response(
                data=signature_info,
                message="Signature audit information retrieved"
            )
            
    except Exception as e:
        logger.error(f"Failed to get signature audit: {e}")
        return create_error_response(f"Failed to get signature audit: {str(e)}", "SIGNATURE_AUDIT_FAILED")

# CRL Endpoint (basic implementation)
@app.get("/api/v1/crl/{ca_id}", response_model=APIResponse)
async def get_crl(
    ca_id: str,
    db: VCCPKIDatabase = Depends(get_database)
):
    """Get Certificate Revocation List"""
    try:
        # TODO: Generate proper CRL using cryptography library
        # For now, return JSON list of revoked certificates
        
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            results = conn.execute("""
                SELECT cert_id, serial_number, revoked_at, revocation_reason
                FROM certificates 
                WHERE issuing_ca_id = ? AND revoked_at IS NOT NULL
                ORDER BY revoked_at DESC
            """, (ca_id,)).fetchall()
            
            revoked_certs = [dict(row) for row in results]
            
            crl_data = {
                'ca_id': ca_id,
                'generated_at': datetime.utcnow().isoformat(),
                'revoked_certificates': revoked_certs,
                'count': len(revoked_certs)
            }
            
            return create_success_response(
                data=crl_data,
                message=f"CRL for CA {ca_id} - {len(revoked_certs)} revoked certificates"
            )
            
    except Exception as e:
        logger.error(f"Failed to generate CRL: {e}")
        return create_error_response(f"Failed to generate CRL: {str(e)}", "CRL_GENERATION_FAILED")

# Audit and Compliance Endpoints  
@app.get("/api/v1/audit/events", response_model=APIResponse)
async def get_audit_events(
    organization_id: str = None,
    service_id: str = None,
    event_category: str = None,
    limit: int = 100,
    current_user: dict = Depends(verify_token),
    db: VCCPKIDatabase = Depends(get_database)
):
    """Get audit events"""
    try:
        events = db.get_audit_trail(organization_id, service_id, event_category, limit)
        
        return create_success_response(
            data=events,
            message=f"Retrieved {len(events)} audit events"
        )
        
    except Exception as e:
        logger.error(f"Failed to get audit events: {e}")
        return create_error_response(f"Failed to get audit events: {str(e)}", "AUDIT_FAILED")

# Mock VCC Service Endpoints (for testing integration)
@app.get("/api/v1/mock/vcc-services/{service_id}/health", response_model=APIResponse)
async def mock_vcc_service_health(service_id: str):
    """Mock VCC service health endpoint for testing"""
    if not app_state.config.mock_mode:
        raise HTTPException(status_code=404, detail="Mock endpoints only available in mock mode")
    
    # Simulate different health statuses
    mock_statuses = {
        "argus": {"status": "healthy", "endpoint": "http://localhost:12091"},
        "covina": {"status": "healthy", "endpoint": "http://localhost:8001"},
        "clara": {"status": "degraded", "endpoint": "http://localhost:8002", "issue": "High memory usage"},
        "veritas": {"status": "healthy", "endpoint": "http://localhost:8003"},
        "vpb": {"status": "healthy", "endpoint": "http://localhost:8004"}
    }
    
    service_health = mock_statuses.get(service_id, {"status": "unknown"})
    
    return create_success_response(
        data={
            "service_id": service_id,
            "timestamp": datetime.utcnow().isoformat(),
            **service_health
        },
        message=f"Mock health status for {service_id}"
    )

# Import sqlite3 for database operations
import sqlite3

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=create_error_response(
            exc.detail,
            f"HTTP_{exc.status_code}"
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content=create_error_response(
            "Internal server error" if not app_state.config.mock_mode else str(exc),
            "INTERNAL_SERVER_ERROR"
        ).dict()
    )

# Development server
if __name__ == "__main__":
    print("🚀 Starting VCC PKI System API Server...")
    
    # Load config
    config = create_config()
    
    uvicorn.run(
        "main:app",
        host=config.api_host,
        port=config.api_port,
        reload=config.mock_mode,
        workers=1 if config.mock_mode else config.api_workers,
        log_level=config.log_level.lower()
    )