# VCC PKI System - TSA Database Models
# SQLAlchemy models für Timestamp Authority

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, LargeBinary, Float, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.core.database import Base

class TSARequest(Base):
    """TSA Request audit log"""
    __tablename__ = "tsa_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(100), unique=True, nullable=False, index=True)
    
    # Request details
    client_ip = Column(String(45), nullable=True)  # IPv6 support
    vcc_service = Column(String(50), nullable=True, index=True)
    hash_algorithm = Column(String(20), nullable=False)
    message_hash = Column(LargeBinary, nullable=False)
    
    # TSA response
    status = Column(String(20), nullable=False, index=True)  # granted, rejected, etc.
    serial_number = Column(Integer, nullable=True, index=True)
    timestamp_token_size = Column(Integer, nullable=True)
    
    # Performance metrics
    processing_time_ms = Column(Float, nullable=True)
    
    # Metadata
    metadata = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

class TSACertificate(Base):
    """TSA signing certificates"""
    __tablename__ = "tsa_certificates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Certificate details
    serial_number = Column(String(100), unique=True, nullable=False)
    subject_dn = Column(String(500), nullable=False)
    issuer_dn = Column(String(500), nullable=False)
    
    # Validity
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)
    
    # Certificate data
    certificate_pem = Column(Text, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    
    # HSM information
    hsm_slot_id = Column(Integer, nullable=True)
    hsm_key_label = Column(String(100), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(100), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class TSAToken(Base):
    """Issued timestamp tokens for audit and verification"""
    __tablename__ = "tsa_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Token identification
    serial_number = Column(Integer, unique=True, nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 of token
    
    # Request reference
    request_id = Column(String(100), nullable=False, index=True)
    
    # Token details
    policy_oid = Column(String(100), nullable=False)
    message_imprint = Column(LargeBinary, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    accuracy_seconds = Column(Integer, nullable=True)
    
    # VCC service information
    vcc_service = Column(String(50), nullable=True, index=True)
    service_metadata = Column(JSON, nullable=True)
    
    # Token data (for verification)
    token_der = Column(LargeBinary, nullable=False)  # Full DER-encoded token
    signature_algorithm = Column(String(50), nullable=False)
    
    # Certificate used
    tsa_cert_serial = Column(String(100), nullable=False)
    
    # Audit information
    client_ip = Column(String(45), nullable=True)
    user_id = Column(UUID(as_uuid=True), nullable=True)  # If authenticated
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class TSAPerformanceMetrics(Base):
    """TSA performance metrics aggregation"""
    __tablename__ = "tsa_performance_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Time window
    metric_date = Column(DateTime(timezone=True), nullable=False, index=True)
    metric_hour = Column(Integer, nullable=False)  # 0-23
    
    # Request counts
    total_requests = Column(Integer, default=0, nullable=False)
    successful_requests = Column(Integer, default=0, nullable=False)
    failed_requests = Column(Integer, default=0, nullable=False)
    
    # Performance metrics
    avg_processing_time_ms = Column(Float, nullable=True)
    min_processing_time_ms = Column(Float, nullable=True)
    max_processing_time_ms = Column(Float, nullable=True)
    
    # VCC service breakdown
    clara_requests = Column(Integer, default=0, nullable=False)
    covina_requests = Column(Integer, default=0, nullable=False)
    argus_requests = Column(Integer, default=0, nullable=False)
    veritas_requests = Column(Integer, default=0, nullable=False)
    vpb_requests = Column(Integer, default=0, nullable=False)
    external_requests = Column(Integer, default=0, nullable=False)
    
    # Error analysis
    error_breakdown = Column(JSON, nullable=True)  # Error types and counts
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class TSAConfiguration(Base):
    """TSA configuration settings"""
    __tablename__ = "tsa_configuration"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Configuration key
    config_key = Column(String(100), unique=True, nullable=False, index=True)
    config_value = Column(Text, nullable=False)
    config_type = Column(String(20), nullable=False)  # string, integer, boolean, json
    
    # Metadata
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=True, index=True)  # general, security, performance
    
    # Change tracking
    created_by = Column(UUID(as_uuid=True), nullable=True)
    updated_by = Column(UUID(as_uuid=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())