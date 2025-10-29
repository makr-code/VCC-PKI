"""
VCC PKI Server - Database Models

SQLAlchemy ORM models for the PKI Server database.

Usage:
    from database import get_db, Service, Certificate
    
    db = next(get_db())
    services = db.query(Service).all()
"""

from datetime import datetime, timezone
from typing import Optional, List
from pathlib import Path

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool

# Base class for all models
Base = declarative_base()

# Database engine (will be initialized on first import)
_engine = None
_SessionLocal = None


# ============================================================================
# Database Setup
# ============================================================================

def get_database_path() -> Path:
    """Get database file path"""
    return Path(__file__).parent.parent / "database" / "pki_server.db"


def init_database(db_path: Optional[str] = None):
    """Initialize database connection"""
    global _engine, _SessionLocal
    
    if _engine is not None:
        return _engine
    
    if db_path is None:
        db_path = str(get_database_path())
    
    # Create engine
    _engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    
    # Create session factory
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    
    return _engine


def get_db() -> Session:
    """Get database session (dependency injection for FastAPI)"""
    if _SessionLocal is None:
        init_database()
    
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# Models
# ============================================================================

class Service(Base):
    """Service model - represents a registered microservice"""
    __tablename__ = "services"
    
    service_id = Column(String, primary_key=True)
    service_name = Column(String, nullable=False)
    description = Column(Text)
    endpoints = Column(Text)  # JSON array
    health_check_url = Column(String)
    service_metadata = Column(Text)  # JSON object (renamed from 'metadata' to avoid SQLAlchemy conflict)
    status = Column(String, default="active")
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime)
    
    # Relationships
    certificates = relationship("Certificate", back_populates="service", cascade="all, delete-orphan")
    health_history = relationship("ServiceHealthHistory", back_populates="service", cascade="all, delete-orphan")
    rotation_schedules = relationship("RotationSchedule", back_populates="service", cascade="all, delete-orphan")
    
    __table_args__ = (
        CheckConstraint("status IN ('active', 'inactive', 'maintenance')"),
    )
    
    def __repr__(self):
        return f"<Service(service_id='{self.service_id}', name='{self.service_name}', status='{self.status}')>"


class Certificate(Base):
    """Certificate model - represents an issued X.509 certificate"""
    __tablename__ = "certificates"
    
    certificate_id = Column(String, primary_key=True)
    service_id = Column(String, ForeignKey("services.service_id", ondelete="CASCADE"), nullable=False)
    common_name = Column(String, nullable=False)
    serial_number = Column(String, unique=True, nullable=False)
    fingerprint = Column(String, nullable=False)
    subject_dn = Column(String, nullable=False)
    issuer_dn = Column(String, nullable=False)
    san_dns = Column(Text)  # JSON array
    san_ip = Column(Text)  # JSON array
    key_size = Column(Integer, default=2048)
    signature_algorithm = Column(String, default="SHA256")
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    status = Column(String, default="active")
    revoked_at = Column(DateTime)
    revocation_reason = Column(String)
    issued_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    cert_file_path = Column(String)
    key_file_path = Column(String)
    
    # Relationships
    service = relationship("Service", back_populates="certificates")
    crl_entry = relationship("CRLEntry", back_populates="certificate", uselist=False, cascade="all, delete-orphan")
    rotation_schedule = relationship("RotationSchedule", back_populates="certificate", uselist=False, cascade="all, delete-orphan")
    
    __table_args__ = (
        CheckConstraint("status IN ('active', 'revoked', 'expired')"),
        CheckConstraint("revocation_reason IN ('unspecified', 'key_compromise', 'ca_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation', 'certificate_hold', 'remove_from_crl', 'privilege_withdrawn', 'aa_compromise') OR revocation_reason IS NULL"),
    )
    
    def __repr__(self):
        return f"<Certificate(cert_id='{self.certificate_id}', service='{self.service_id}', status='{self.status}')>"
    
    @property
    def days_until_expiry(self) -> int:
        """Calculate days until certificate expiry"""
        if self.not_after:
            delta = self.not_after - datetime.now(timezone.utc)
            return delta.days
        return 0
    
    @property
    def needs_renewal(self) -> bool:
        """Check if certificate needs renewal (< 30 days until expiry)"""
        return self.days_until_expiry < 30


class CRLEntry(Base):
    """CRL Entry model - represents a revoked certificate"""
    __tablename__ = "crl_entries"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    certificate_id = Column(String, ForeignKey("certificates.certificate_id", ondelete="CASCADE"), nullable=False)
    serial_number = Column(String, nullable=False)
    revoked_at = Column(DateTime, nullable=False)
    revocation_reason = Column(String, nullable=False)
    invalidity_date = Column(DateTime)
    
    # Relationships
    certificate = relationship("Certificate", back_populates="crl_entry")
    
    def __repr__(self):
        return f"<CRLEntry(serial='{self.serial_number}', reason='{self.revocation_reason}')>"


class AuditLog(Base):
    """Audit Log model - tracks all PKI operations"""
    __tablename__ = "audit_log"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action = Column(String, nullable=False)
    service_id = Column(String)
    certificate_id = Column(String)
    user_id = Column(String)
    ip_address = Column(String)
    details = Column(Text)  # JSON object
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    
    __table_args__ = (
        CheckConstraint("action IN ('CERTIFICATE_ISSUED', 'CERTIFICATE_RENEWED', 'CERTIFICATE_REVOKED', 'CERTIFICATE_DOWNLOADED', 'SERVICE_REGISTERED', 'SERVICE_UPDATED', 'SERVICE_DEREGISTERED', 'HEALTH_CHECK_FAILED', 'CA_ACCESS')"),
    )
    
    def __repr__(self):
        return f"<AuditLog(action='{self.action}', service='{self.service_id}', timestamp='{self.timestamp}')>"


class RotationSchedule(Base):
    """Rotation Schedule model - tracks automatic certificate renewal"""
    __tablename__ = "rotation_schedule"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    certificate_id = Column(String, ForeignKey("certificates.certificate_id", ondelete="CASCADE"), nullable=False)
    service_id = Column(String, ForeignKey("services.service_id", ondelete="CASCADE"), nullable=False)
    scheduled_renewal_date = Column(DateTime, nullable=False)
    status = Column(String, default="pending")
    last_attempt = Column(DateTime)
    attempt_count = Column(Integer, default=0)
    error_message = Column(Text)
    completed_at = Column(DateTime)
    
    # Relationships
    certificate = relationship("Certificate", back_populates="rotation_schedule")
    service = relationship("Service", back_populates="rotation_schedules")
    
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'completed', 'failed', 'skipped')"),
    )
    
    def __repr__(self):
        return f"<RotationSchedule(cert='{self.certificate_id}', scheduled='{self.scheduled_renewal_date}', status='{self.status}')>"


class ServiceHealthHistory(Base):
    """Service Health History model - tracks health check results"""
    __tablename__ = "service_health_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String, ForeignKey("services.service_id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String, nullable=False)
    response_time_ms = Column(Integer)
    http_status_code = Column(Integer)
    error_message = Column(Text)
    
    # Relationships
    service = relationship("Service", back_populates="health_history")
    
    __table_args__ = (
        CheckConstraint("status IN ('healthy', 'unhealthy', 'unknown')"),
    )
    
    def __repr__(self):
        return f"<ServiceHealthHistory(service='{self.service_id}', status='{self.status}', timestamp='{self.timestamp}')>"


class DBMetadata(Base):
    """Database Metadata model - stores database metadata"""
    __tablename__ = "db_metadata"
    
    key = Column(String, primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<DBMetadata(key='{self.key}', value='{self.value}')>"


# ============================================================================
# Helper Functions
# ============================================================================

def create_all_tables(engine=None):
    """Create all tables in the database"""
    if engine is None:
        engine = init_database()
    
    Base.metadata.create_all(bind=engine)


def drop_all_tables(engine=None):
    """Drop all tables in the database (WARNING: destructive!)"""
    if engine is None:
        engine = init_database()
    
    Base.metadata.drop_all(bind=engine)


# Initialize database on module import
init_database()
