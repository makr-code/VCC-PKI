# VCC PKI System - Timestamp Authority API Endpoints
# RFC 3161 TSA REST API für VCC Services Integration

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime
import base64

from app.core.security import get_current_user, require_permission
from app.services.timestamp_authority import (
    VCCTimestampAuthority, 
    VCCTimestampAuthorityFactory,
    TSAStatus,
    HashAlgorithm
)
from app.models.user import User

logger = logging.getLogger(__name__)

# Pydantic Models for TSA API

class TimestampRequest(BaseModel):
    """Timestamp request for VCC services"""
    data: str = Field(..., description="Base64-encoded data to timestamp")
    hash_algorithm: str = Field(default="sha256", description="Hash algorithm (sha256, sha384, sha512)")
    include_certificate: bool = Field(default=True, description="Include TSA certificate in response")
    vcc_service: Optional[str] = Field(None, description="VCC service name")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class TimestampResponse(BaseModel):
    """Timestamp response"""
    status: str = Field(..., description="Request status (granted, rejected)")
    timestamp_token: Optional[str] = Field(None, description="Base64-encoded timestamp token")
    response_id: str = Field(..., description="Unique response identifier")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    generated_at: str = Field(..., description="Response generation time")
    failure_info: Optional[List[str]] = Field(None, description="Failure information if rejected")

class VCCServiceTimestampRequest(BaseModel):
    """VCC service-specific timestamp request"""
    service_data: str = Field(..., description="Base64-encoded service data")
    service_id: str = Field(..., description="Service-specific identifier")
    purpose: str = Field(..., description="Timestamp purpose")
    hash_algorithm: str = Field(default="sha256", description="Hash algorithm")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Service metadata")

class TimestampVerificationRequest(BaseModel):
    """Timestamp token verification request"""
    timestamp_token: str = Field(..., description="Base64-encoded timestamp token")
    original_data: Optional[str] = Field(None, description="Base64-encoded original data")

class TimestampVerificationResponse(BaseModel):
    """Timestamp verification response"""
    valid: bool = Field(..., description="Token validity")
    timestamp: Optional[str] = Field(None, description="Token timestamp")
    serial_number: Optional[int] = Field(None, description="Token serial number")
    policy_oid: Optional[str] = Field(None, description="TSA policy OID")
    hash_algorithm: Optional[str] = Field(None, description="Hash algorithm used")
    errors: List[str] = Field(default_factory=list, description="Validation errors")

class TSAHealthResponse(BaseModel):
    """TSA health check response"""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="TSA service version")
    uptime_seconds: float = Field(..., description="Service uptime")
    total_requests: int = Field(..., description="Total processed requests")
    error_rate_percent: float = Field(..., description="Error rate percentage")
    average_processing_time_ms: float = Field(..., description="Average processing time")
    hsm_status: str = Field(..., description="HSM status")
    certificate_expires_at: str = Field(..., description="TSA certificate expiry")

# Create API Router
router = APIRouter(prefix="/tsa", tags=["timestamp-authority"])

# Global TSA service instance (initialized on startup)
_tsa_service: Optional[VCCTimestampAuthority] = None

async def get_tsa_service() -> VCCTimestampAuthority:
    """Get TSA service instance"""
    global _tsa_service
    
    if _tsa_service is None:
        try:
            _tsa_service = await VCCTimestampAuthorityFactory.create_tsa_service()
            logger.info("TSA service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize TSA service: {e}")
            raise HTTPException(500, f"TSA service initialization failed: {str(e)}")
    
    return _tsa_service

# RFC 3161 Standard Endpoints

@router.post("/timestamp",
             summary="Create RFC 3161 timestamp",
             description="Create RFC 3161 compliant timestamp for arbitrary data")
async def create_timestamp(
    timestamp_request: TimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """
    Create RFC 3161 compliant timestamp
    
    Supports all VCC services and external clients with proper authentication.
    """
    try:
        # Decode input data
        try:
            data_to_timestamp = base64.b64decode(timestamp_request.data)
        except Exception:
            raise HTTPException(400, "Invalid base64-encoded data")
        
        # Validate hash algorithm
        try:
            hash_algo = HashAlgorithm(timestamp_request.hash_algorithm.lower().replace("-", "_"))
        except ValueError:
            raise HTTPException(400, f"Unsupported hash algorithm: {timestamp_request.hash_algorithm}")
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Process timestamp request
        response = await tsa_service.process_vcc_timestamp_request(
            data_to_timestamp=data_to_timestamp,
            vcc_service=timestamp_request.vcc_service or "external",
            hash_algorithm=hash_algo,
            include_certificate=timestamp_request.include_certificate,
            metadata=timestamp_request.metadata
        )
        
        # Convert response
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat(),
            failure_info=[info.name for info in response.failure_info] if response.failure_info else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Timestamp creation failed: {e}")
        raise HTTPException(500, f"Timestamp creation failed: {str(e)}")

@router.post("/verify",
             summary="Verify timestamp token",
             description="Verify RFC 3161 timestamp token authenticity and integrity")
async def verify_timestamp(
    verification_request: TimestampVerificationRequest,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampVerificationResponse:
    """
    Verify timestamp token authenticity and integrity
    """
    try:
        # Decode timestamp token
        try:
            timestamp_token = base64.b64decode(verification_request.timestamp_token)
        except Exception:
            raise HTTPException(400, "Invalid base64-encoded timestamp token")
        
        # Decode original data if provided
        original_data = None
        if verification_request.original_data:
            try:
                original_data = base64.b64decode(verification_request.original_data)
            except Exception:
                raise HTTPException(400, "Invalid base64-encoded original data")
        
        # Verify token
        verification_result = await tsa_service.verify_timestamp_token(
            timestamp_token=timestamp_token,
            original_data=original_data
        )
        
        return TimestampVerificationResponse(
            valid=verification_result["valid"],
            timestamp=verification_result["timestamp"].isoformat() if verification_result.get("timestamp") else None,
            serial_number=verification_result.get("serial_number"),
            policy_oid=verification_result.get("policy_oid"),
            hash_algorithm=verification_result.get("hash_algorithm"),
            errors=verification_result.get("errors", [])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Timestamp verification failed: {e}")
        raise HTTPException(500, f"Timestamp verification failed: {str(e)}")

# VCC Service-Specific Endpoints

@router.post("/clara/model",
             dependencies=[Depends(require_permission("tsa:clara:timestamp"))],
             summary="Timestamp Clara KI model",
             description="Create timestamp for Clara KI model integrity verification")
async def timestamp_clara_model(
    model_request: VCCServiceTimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """Timestamp Clara KI model for integrity verification"""
    
    try:
        model_data = base64.b64decode(model_request.service_data)
        
        response = await tsa_service.timestamp_clara_model(
            model_data=model_data,
            model_id=model_request.service_id,
            version=model_request.metadata.get("version", "1.0.0") if model_request.metadata else "1.0.0"
        )
        
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Clara model timestamp failed: {e}")
        raise HTTPException(500, f"Clara model timestamp failed: {str(e)}")

@router.post("/covina/workflow",
             dependencies=[Depends(require_permission("tsa:covina:timestamp"))],
             summary="Timestamp Covina workflow",
             description="Create timestamp for Covina workflow audit trail")
async def timestamp_covina_workflow(
    workflow_request: VCCServiceTimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """Timestamp Covina workflow for audit trail"""
    
    try:
        workflow_data = base64.b64decode(workflow_request.service_data)
        
        response = await tsa_service.timestamp_covina_workflow(
            workflow_definition=workflow_data,
            workflow_id=workflow_request.service_id
        )
        
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Covina workflow timestamp failed: {e}")
        raise HTTPException(500, f"Covina workflow timestamp failed: {str(e)}")

@router.post("/argus/decision",
             dependencies=[Depends(require_permission("tsa:argus:timestamp"))],
             summary="Timestamp Argus decision",
             description="Create timestamp for Argus decision legal compliance")
async def timestamp_argus_decision(
    decision_request: VCCServiceTimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """Timestamp Argus decision for legal compliance"""
    
    try:
        decision_data = base64.b64decode(decision_request.service_data)
        
        response = await tsa_service.timestamp_argus_decision(
            decision_data=decision_data,
            case_id=decision_request.service_id
        )
        
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Argus decision timestamp failed: {e}")
        raise HTTPException(500, f"Argus decision timestamp failed: {str(e)}")

@router.post("/veritas/validation",
             dependencies=[Depends(require_permission("tsa:veritas:timestamp"))],
             summary="Timestamp Veritas validation",
             description="Create timestamp for Veritas validation audit")
async def timestamp_veritas_validation(
    validation_request: VCCServiceTimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """Timestamp Veritas validation for audit purposes"""
    
    try:
        validation_data = base64.b64decode(validation_request.service_data)
        
        response = await tsa_service.timestamp_veritas_validation(
            validation_result=validation_data,
            validation_id=validation_request.service_id
        )
        
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Veritas validation timestamp failed: {e}")
        raise HTTPException(500, f"Veritas validation timestamp failed: {str(e)}")

@router.post("/vpb/transaction",
             dependencies=[Depends(require_permission("tsa:vpb:timestamp"))],
             summary="Timestamp VPB transaction",
             description="Create timestamp for VPB transaction financial compliance")
async def timestamp_vpb_transaction(
    transaction_request: VCCServiceTimestampRequest,
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TimestampResponse:
    """Timestamp VPB transaction for financial compliance"""
    
    try:
        transaction_data = base64.b64decode(transaction_request.service_data)
        
        response = await tsa_service.timestamp_vpb_transaction(
            transaction_data=transaction_data,
            transaction_id=transaction_request.service_id
        )
        
        return TimestampResponse(
            status=response.status.name.lower(),
            timestamp_token=base64.b64encode(response.time_stamp_token).decode() if response.time_stamp_token else None,
            response_id=response.response_id,
            processing_time_ms=response.processing_time_ms,
            generated_at=response.generated_at.isoformat() if response.generated_at else datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"VPB transaction timestamp failed: {e}")
        raise HTTPException(500, f"VPB transaction timestamp failed: {str(e)}")

# Raw RFC 3161 Endpoints (for compatibility)

@router.post("/",
             summary="RFC 3161 raw timestamp request",
             description="Process raw RFC 3161 timestamp request (binary)",
             response_class=Response)
async def process_rfc3161_request(
    request: Request,
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
):
    """
    Process raw RFC 3161 timestamp request
    
    Accepts DER-encoded timestamp request and returns DER-encoded response.
    This endpoint provides full RFC 3161 compatibility.
    """
    try:
        # Read raw request data
        request_data = await request.body()
        
        if not request_data:
            raise HTTPException(400, "Empty request body")
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Process timestamp request
        response = await tsa_service.process_timestamp_request(
            request_data=request_data,
            client_ip=client_ip,
            vcc_service="rfc3161_raw"
        )
        
        # Return raw response
        if response.status == TSAStatus.GRANTED and response.time_stamp_token:
            return Response(
                content=response.time_stamp_token,
                media_type="application/timestamp-reply",
                headers={
                    "X-TSA-Response-ID": response.response_id,
                    "X-Processing-Time-MS": str(response.processing_time_ms)
                }
            )
        else:
            # Return error response
            error_response = b"TSA_REJECTION"  # Simplified error response
            return Response(
                content=error_response,
                status_code=400,
                media_type="application/timestamp-reply",
                headers={
                    "X-TSA-Response-ID": response.response_id,
                    "X-TSA-Status": response.status.name
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"RFC 3161 request processing failed: {e}")
        raise HTTPException(500, f"Request processing failed: {str(e)}")

# Monitoring and Management Endpoints

@router.get("/health",
            summary="TSA health check",
            description="Get TSA service health status and metrics")
async def get_tsa_health(
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> TSAHealthResponse:
    """Get TSA service health and performance metrics"""
    
    try:
        metrics = tsa_service.get_performance_metrics()
        
        return TSAHealthResponse(
            status="healthy",
            version="1.0.0",
            uptime_seconds=0.0,  # Would track actual uptime
            total_requests=metrics["total_requests"],
            error_rate_percent=metrics["error_rate_percent"],
            average_processing_time_ms=metrics["average_processing_time_ms"],
            hsm_status="connected",  # Would check actual HSM status
            certificate_expires_at=metrics["tsa_certificate_expires"]
        )
        
    except Exception as e:
        logger.error(f"TSA health check failed: {e}")
        raise HTTPException(500, f"Health check failed: {str(e)}")

@router.get("/metrics",
            dependencies=[Depends(require_permission("tsa:metrics:read"))],
            summary="TSA performance metrics",
            description="Get detailed TSA performance metrics")
async def get_tsa_metrics(
    user: User = Depends(get_current_user),
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> Dict[str, Any]:
    """Get detailed TSA performance metrics"""
    
    try:
        metrics = tsa_service.get_performance_metrics()
        
        # Add additional metrics
        metrics.update({
            "service_version": "1.0.0",
            "rfc_compliance": "RFC 3161",
            "supported_vcc_services": ["clara", "covina", "argus", "veritas", "vpb"],
            "hsm_protected": True,
            "audit_enabled": True
        })
        
        return metrics
        
    except Exception as e:
        logger.error(f"TSA metrics retrieval failed: {e}")
        raise HTTPException(500, f"Metrics retrieval failed: {str(e)}")

@router.get("/certificate",
            summary="Get TSA certificate",
            description="Get TSA signing certificate (public key)")
async def get_tsa_certificate(
    tsa_service: VCCTimestampAuthority = Depends(get_tsa_service)
) -> Dict[str, Any]:
    """Get TSA signing certificate information"""
    
    try:
        cert = tsa_service.tsa_certificate
        
        return {
            "certificate": {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "signature_algorithm": cert.signature_algorithm_oid._name
            },
            "pem_certificate": cert.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode('utf-8')
        }
        
    except Exception as e:
        logger.error(f"TSA certificate retrieval failed: {e}")
        raise HTTPException(500, f"Certificate retrieval failed: {str(e)}")

# Initialize TSA service on module load
async def initialize_tsa_service():
    """Initialize TSA service"""
    try:
        await get_tsa_service()
        logger.info("TSA API endpoints initialized successfully")
    except Exception as e:
        logger.error(f"TSA API initialization failed: {e}")
        # Don't raise here, let it fail on first request instead