"""
VCC PKI Server - Database Migration Module

Provides database migration support from SQLite to PostgreSQL
and enhanced database features for production deployment.

Features:
- SQLite to PostgreSQL migration
- Schema versioning
- Automated migrations
- Multi-tenant support
- Enhanced audit trail
- Backup and restore utilities

Usage:
    from database_migration import DatabaseMigration
    
    migration = DatabaseMigration()
    
    # Migrate from SQLite to PostgreSQL
    await migration.migrate_to_postgresql(
        postgresql_url="postgresql://user:pass@localhost/vcc_pki"
    )
    
    # Run schema migrations
    await migration.run_migrations()

Author: VCC-PKI Team
Date: November 2025
"""

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean, DateTime, 
    ForeignKey, CheckConstraint, Index, Enum as SQLEnum, LargeBinary,
    Table, MetaData, inspect, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool, QueuePool

logger = logging.getLogger(__name__)

# Base for migration-specific models
MigrationBase = declarative_base()


# ============================================================================
# Enumerations
# ============================================================================

class DatabaseType(Enum):
    """Supported database types"""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


class MigrationStatus(Enum):
    """Migration status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class IsolationLevel(Enum):
    """Organization isolation levels for multi-tenant support"""
    STRICT = "strict"          # Complete data isolation
    COLLABORATIVE = "collaborative"  # Shared read, isolated write
    FEDERATED = "federated"    # Full cross-org access


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class DatabaseConfig:
    """Database configuration"""
    
    # Connection settings
    database_type: DatabaseType = DatabaseType.SQLITE
    sqlite_path: str = "../database/pki_server.db"
    postgresql_url: Optional[str] = None
    
    # Pool settings
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    # Feature flags
    multi_tenant_enabled: bool = False
    audit_chain_enabled: bool = True
    encryption_enabled: bool = False
    
    # Migration settings
    auto_migrate: bool = True
    backup_before_migrate: bool = True
    migration_timeout: int = 3600
    
    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        """Load configuration from environment variables"""
        db_type = os.environ.get("VCC_DATABASE_TYPE", "sqlite")
        
        return cls(
            database_type=DatabaseType(db_type.lower()),
            sqlite_path=os.environ.get("VCC_SQLITE_PATH", "../database/pki_server.db"),
            postgresql_url=os.environ.get("VCC_POSTGRESQL_URL"),
            pool_size=int(os.environ.get("VCC_DB_POOL_SIZE", "5")),
            max_overflow=int(os.environ.get("VCC_DB_MAX_OVERFLOW", "10")),
            pool_timeout=int(os.environ.get("VCC_DB_POOL_TIMEOUT", "30")),
            pool_recycle=int(os.environ.get("VCC_DB_POOL_RECYCLE", "3600")),
            multi_tenant_enabled=os.environ.get("VCC_MULTI_TENANT", "false").lower() == "true",
            audit_chain_enabled=os.environ.get("VCC_AUDIT_CHAIN", "true").lower() == "true",
            encryption_enabled=os.environ.get("VCC_DB_ENCRYPTION", "false").lower() == "true",
            auto_migrate=os.environ.get("VCC_AUTO_MIGRATE", "true").lower() == "true",
            backup_before_migrate=os.environ.get("VCC_BACKUP_BEFORE_MIGRATE", "true").lower() == "true",
        )


# ============================================================================
# Migration Models
# ============================================================================

class SchemaVersion(MigrationBase):
    """Tracks schema versions and migrations"""
    __tablename__ = "schema_versions"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    applied_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(20), default="completed")
    checksum = Column(String(64))
    rollback_script = Column(Text)
    
    def __repr__(self):
        return f"<SchemaVersion(version='{self.version}', status='{self.status}')>"


# ============================================================================
# Enhanced Production Models (PostgreSQL)
# ============================================================================

# These models are enhanced versions for PostgreSQL production

class Organization(MigrationBase):
    """Organization model for multi-tenant support"""
    __tablename__ = "organizations"
    
    org_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_name = Column(String(255), nullable=False, unique=True)
    display_name = Column(String(255))
    description = Column(Text)
    isolation_level = Column(String(20), default="strict")
    contact_email = Column(String(255))
    contact_phone = Column(String(50))
    address = Column(Text)
    status = Column(String(20), default="active")
    settings = Column(Text)  # JSON
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        CheckConstraint("isolation_level IN ('strict', 'collaborative', 'federated')"),
        CheckConstraint("status IN ('active', 'inactive', 'suspended')"),
    )
    
    def __repr__(self):
        return f"<Organization(org_id='{self.org_id}', name='{self.org_name}')>"


class CertificateAuthority(MigrationBase):
    """Certificate Authority model for multi-CA support"""
    __tablename__ = "certificate_authorities"
    
    ca_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    ca_name = Column(String(255), nullable=False)
    ca_type = Column(String(20), nullable=False)  # root, intermediate, issuing
    parent_ca_id = Column(String(36), ForeignKey("certificate_authorities.ca_id"))
    subject_dn = Column(String(500), nullable=False)
    key_algorithm = Column(String(20), default="RSA")
    key_size = Column(Integer, default=4096)
    signature_algorithm = Column(String(50), default="SHA256")
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    serial_number = Column(String(100), unique=True, nullable=False)
    certificate_pem = Column(Text, nullable=False)
    private_key_encrypted = Column(LargeBinary)  # Encrypted private key
    hsm_key_label = Column(String(255))  # HSM key reference
    crl_distribution_point = Column(String(500))
    ocsp_responder_url = Column(String(500))
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        CheckConstraint("ca_type IN ('root', 'intermediate', 'issuing')"),
        CheckConstraint("key_algorithm IN ('RSA', 'EC', 'ED25519')"),
        CheckConstraint("status IN ('active', 'revoked', 'expired', 'pending')"),
    )
    
    def __repr__(self):
        return f"<CertificateAuthority(ca_id='{self.ca_id}', name='{self.ca_name}', type='{self.ca_type}')>"


class CertificateTemplate(MigrationBase):
    """Certificate template for policy-based issuance"""
    __tablename__ = "certificate_templates"
    
    template_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    template_name = Column(String(255), nullable=False)
    description = Column(Text)
    validity_days = Column(Integer, default=365)
    key_usage = Column(Text)  # JSON array
    extended_key_usage = Column(Text)  # JSON array
    subject_pattern = Column(String(500))
    san_allowed = Column(Boolean, default=True)
    auto_renewal = Column(Boolean, default=True)
    renewal_threshold_days = Column(Integer, default=30)
    require_approval = Column(Boolean, default=False)
    allowed_requesters = Column(Text)  # JSON array
    constraints = Column(Text)  # JSON object
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<CertificateTemplate(template_id='{self.template_id}', name='{self.template_name}')>"


class EnhancedCertificate(MigrationBase):
    """Enhanced certificate model with multi-tenant and template support"""
    __tablename__ = "certificates_enhanced"
    
    cert_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    ca_id = Column(String(36), ForeignKey("certificate_authorities.ca_id", ondelete="CASCADE"))
    template_id = Column(String(36), ForeignKey("certificate_templates.template_id"))
    service_id = Column(String(255))
    common_name = Column(String(255), nullable=False)
    serial_number = Column(String(100), unique=True, nullable=False)
    fingerprint_sha256 = Column(String(64), nullable=False)
    fingerprint_sha1 = Column(String(40))
    subject_dn = Column(String(500), nullable=False)
    issuer_dn = Column(String(500), nullable=False)
    san_dns = Column(Text)  # JSON array
    san_ip = Column(Text)  # JSON array
    san_email = Column(Text)  # JSON array
    san_uri = Column(Text)  # JSON array
    key_algorithm = Column(String(20), default="RSA")
    key_size = Column(Integer, default=2048)
    signature_algorithm = Column(String(50), default="SHA256")
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    certificate_pem = Column(Text, nullable=False)
    certificate_chain_pem = Column(Text)
    private_key_encrypted = Column(LargeBinary)
    hsm_key_label = Column(String(255))
    status = Column(String(20), default="active")
    revoked_at = Column(DateTime)
    revocation_reason = Column(String(50))
    auto_renewal = Column(Boolean, default=True)
    renewal_threshold_days = Column(Integer, default=30)
    renewed_from_cert_id = Column(String(36))
    renewed_to_cert_id = Column(String(36))
    issued_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    cert_metadata = Column(Text)  # JSON (renamed from 'metadata' to avoid SQLAlchemy conflict)
    
    __table_args__ = (
        CheckConstraint("status IN ('active', 'revoked', 'expired', 'pending', 'suspended')"),
        Index("idx_cert_org", "org_id"),
        Index("idx_cert_service", "service_id"),
        Index("idx_cert_status", "status"),
        Index("idx_cert_expiry", "not_after"),
        Index("idx_cert_serial", "serial_number"),
    )
    
    def __repr__(self):
        return f"<EnhancedCertificate(cert_id='{self.cert_id}', cn='{self.common_name}', status='{self.status}')>"


class OCSPResponse(MigrationBase):
    """OCSP response cache"""
    __tablename__ = "ocsp_responses"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    serial_number = Column(String(100), nullable=False, index=True)
    response_status = Column(String(20), nullable=False)
    cert_status = Column(String(20), nullable=False)
    this_update = Column(DateTime, nullable=False)
    next_update = Column(DateTime, nullable=False)
    response_der = Column(LargeBinary, nullable=False)
    responder_id = Column(String(255))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index("idx_ocsp_serial", "serial_number"),
        Index("idx_ocsp_next_update", "next_update"),
    )


class VCCCodeSignature(MigrationBase):
    """VCC Code Signature model"""
    __tablename__ = "vcc_code_signatures"
    
    signature_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    cert_id = Column(String(36), ForeignKey("certificates_enhanced.cert_id", ondelete="SET NULL"))
    artifact_type = Column(String(100), nullable=False)
    artifact_name = Column(String(500), nullable=False)
    artifact_version = Column(String(50))
    artifact_hash_sha256 = Column(String(64), nullable=False)
    artifact_hash_sha512 = Column(String(128))
    signature_der = Column(LargeBinary, nullable=False)
    timestamp_token = Column(LargeBinary)  # RFC 3161
    timestamp_authority = Column(String(255))
    signed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    signer_cn = Column(String(255), nullable=False)
    signer_email = Column(String(255))
    vcc_metadata = Column(Text)  # JSON
    verification_status = Column(String(20), default="valid")
    
    __table_args__ = (
        CheckConstraint("artifact_type IN ('python_package', 'lora_adapter', 'pipeline_config', 'model_weights', 'container_image', 'source_code', 'generic')"),
        Index("idx_sig_artifact", "artifact_name"),
        Index("idx_sig_hash", "artifact_hash_sha256"),
    )
    
    def __repr__(self):
        return f"<VCCCodeSignature(signature_id='{self.signature_id}', artifact='{self.artifact_name}')>"


class EnhancedAuditLog(MigrationBase):
    """Enhanced audit log with blockchain-inspired chain"""
    __tablename__ = "audit_log_enhanced"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))  # certificate, service, ca, etc.
    resource_id = Column(String(36))
    service_id = Column(String(255))
    user_id = Column(String(255))
    user_email = Column(String(255))
    ip_address = Column(String(45))  # IPv6 support
    user_agent = Column(String(500))
    request_id = Column(String(36))
    details = Column(Text)  # JSON
    success = Column(Boolean, default=True)
    error_code = Column(String(50))
    error_message = Column(Text)
    previous_hash = Column(String(64))
    entry_hash = Column(String(64))
    
    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_org", "org_id"),
    )
    
    def __repr__(self):
        return f"<EnhancedAuditLog(id={self.id}, action='{self.action}', timestamp='{self.timestamp}')>"
    
    def calculate_hash(self, previous_hash: str = "") -> str:
        """Calculate hash for this entry (blockchain-inspired)"""
        data = f"{self.timestamp.isoformat()}{self.action}{self.resource_type}{self.resource_id}{self.user_id}{self.details}{previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()


class ComplianceReport(MigrationBase):
    """Compliance report model"""
    __tablename__ = "compliance_reports"
    
    report_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.org_id", ondelete="CASCADE"))
    report_type = Column(String(50), nullable=False)  # gdpr, bsi, iso27001, custom
    report_name = Column(String(255), nullable=False)
    report_period_start = Column(DateTime, nullable=False)
    report_period_end = Column(DateTime, nullable=False)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    generated_by = Column(String(255))
    status = Column(String(20), default="draft")
    findings = Column(Text)  # JSON
    recommendations = Column(Text)  # JSON
    evidence_refs = Column(Text)  # JSON array of audit log IDs
    report_content = Column(Text)  # Full report in JSON/HTML
    signed_by = Column(String(255))
    signature = Column(LargeBinary)
    
    __table_args__ = (
        CheckConstraint("report_type IN ('gdpr', 'bsi', 'iso27001', 'soc2', 'custom')"),
        CheckConstraint("status IN ('draft', 'final', 'archived')"),
    )


# ============================================================================
# Migration Manager
# ============================================================================

class DatabaseMigration:
    """
    Database migration manager.
    
    Handles:
    - Schema versioning
    - SQLite to PostgreSQL migration
    - Forward and backward migrations
    - Data integrity verification
    """
    
    SCHEMA_VERSIONS = [
        ("1.0.0", "Initial schema", "initial_schema"),
        ("1.1.0", "Add multi-tenant support", "add_multi_tenant"),
        ("1.2.0", "Add certificate templates", "add_templates"),
        ("1.3.0", "Add enhanced audit log", "add_enhanced_audit"),
        ("1.4.0", "Add OCSP cache table", "add_ocsp_cache"),
        ("1.5.0", "Add VCC code signatures", "add_code_signatures"),
        ("1.6.0", "Add compliance reports", "add_compliance"),
    ]
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig.from_env()
        self._engine = None
        self._session_factory = None
        self._metadata = MetaData()
    
    def get_engine(self, database_type: Optional[DatabaseType] = None):
        """Get database engine"""
        db_type = database_type or self.config.database_type
        
        if db_type == DatabaseType.POSTGRESQL:
            if not self.config.postgresql_url:
                raise ValueError("PostgreSQL URL not configured")
            
            return create_engine(
                self.config.postgresql_url,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                poolclass=QueuePool
            )
        else:
            db_path = Path(self.config.sqlite_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            return create_engine(
                f"sqlite:///{db_path}",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool
            )
    
    def get_session(self) -> Session:
        """Get database session"""
        if self._session_factory is None:
            if self._engine is None:
                self._engine = self.get_engine()
            self._session_factory = sessionmaker(bind=self._engine)
        
        return self._session_factory()
    
    def get_current_version(self) -> Optional[str]:
        """Get current schema version"""
        try:
            session = self.get_session()
            result = session.execute(
                text("SELECT version FROM schema_versions ORDER BY applied_at DESC LIMIT 1")
            ).fetchone()
            return result[0] if result else None
        except Exception:
            return None
    
    def create_migration_tables(self):
        """Create migration tracking tables"""
        engine = self.get_engine()
        MigrationBase.metadata.create_all(engine, tables=[
            SchemaVersion.__table__
        ])
    
    def backup_database(self, backup_path: Optional[str] = None) -> str:
        """Backup the current database"""
        if self.config.database_type == DatabaseType.SQLITE:
            db_path = Path(self.config.sqlite_path)
            if not db_path.exists():
                raise FileNotFoundError(f"Database not found: {db_path}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = backup_path or str(db_path.parent / f"backup_{timestamp}.db")
            
            shutil.copy2(db_path, backup_path)
            logger.info(f"Database backed up to: {backup_path}")
            return backup_path
        else:
            # PostgreSQL backup would use pg_dump
            raise NotImplementedError("PostgreSQL backup not implemented")
    
    def run_migrations(self) -> List[str]:
        """Run all pending migrations"""
        applied = []
        current_version = self.get_current_version()
        
        # Create migration tables if needed
        self.create_migration_tables()
        
        for version, description, migration_func in self.SCHEMA_VERSIONS:
            if current_version and version <= current_version:
                continue
            
            logger.info(f"Running migration {version}: {description}")
            
            try:
                # Run the migration
                migration_method = getattr(self, f"_migrate_{migration_func}", None)
                if migration_method:
                    migration_method()
                
                # Record the migration
                session = self.get_session()
                schema_version = SchemaVersion(
                    version=version,
                    description=description,
                    status="completed",
                    checksum=hashlib.sha256(description.encode()).hexdigest()
                )
                session.add(schema_version)
                session.commit()
                
                applied.append(version)
                logger.info(f"Migration {version} completed")
                
            except Exception as e:
                logger.error(f"Migration {version} failed: {e}")
                raise
        
        return applied
    
    def migrate_to_postgresql(
        self,
        postgresql_url: str,
        batch_size: int = 1000
    ) -> Dict[str, int]:
        """Migrate data from SQLite to PostgreSQL"""
        logger.info("Starting migration from SQLite to PostgreSQL")
        
        # Backup SQLite first
        if self.config.backup_before_migrate:
            self.backup_database()
        
        # Connect to both databases
        sqlite_engine = self.get_engine(DatabaseType.SQLITE)
        pg_engine = create_engine(postgresql_url, pool_size=5)
        
        # Create tables in PostgreSQL
        MigrationBase.metadata.create_all(pg_engine)
        
        # Get table names
        inspector = inspect(sqlite_engine)
        tables = inspector.get_table_names()
        
        migrated = {}
        
        for table_name in tables:
            if table_name.startswith("sqlite_"):
                continue
            
            logger.info(f"Migrating table: {table_name}")
            
            # Read data from SQLite
            with sqlite_engine.connect() as sqlite_conn:
                result = sqlite_conn.execute(text(f"SELECT * FROM {table_name}"))
                rows = result.fetchall()
                columns = result.keys()
            
            if not rows:
                migrated[table_name] = 0
                continue
            
            # Write to PostgreSQL in batches
            with pg_engine.connect() as pg_conn:
                for i in range(0, len(rows), batch_size):
                    batch = rows[i:i + batch_size]
                    
                    # Build insert statement
                    columns_str = ", ".join(columns)
                    placeholders = ", ".join([f":{col}" for col in columns])
                    insert_sql = text(f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})")
                    
                    for row in batch:
                        try:
                            pg_conn.execute(insert_sql, dict(zip(columns, row)))
                        except Exception as e:
                            logger.warning(f"Error inserting row in {table_name}: {e}")
                    
                    pg_conn.commit()
            
            migrated[table_name] = len(rows)
            logger.info(f"Migrated {len(rows)} rows from {table_name}")
        
        logger.info(f"Migration completed. Tables migrated: {migrated}")
        return migrated
    
    # ========================================================================
    # Individual Migrations
    # ========================================================================
    
    def _migrate_initial_schema(self):
        """Initial schema migration"""
        engine = self.get_engine()
        MigrationBase.metadata.create_all(engine)
    
    def _migrate_add_multi_tenant(self):
        """Add multi-tenant support"""
        engine = self.get_engine()
        Organization.__table__.create(engine, checkfirst=True)
    
    def _migrate_add_templates(self):
        """Add certificate templates"""
        engine = self.get_engine()
        CertificateTemplate.__table__.create(engine, checkfirst=True)
    
    def _migrate_add_enhanced_audit(self):
        """Add enhanced audit log"""
        engine = self.get_engine()
        EnhancedAuditLog.__table__.create(engine, checkfirst=True)
    
    def _migrate_add_ocsp_cache(self):
        """Add OCSP cache table"""
        engine = self.get_engine()
        OCSPResponse.__table__.create(engine, checkfirst=True)
    
    def _migrate_add_code_signatures(self):
        """Add VCC code signatures"""
        engine = self.get_engine()
        VCCCodeSignature.__table__.create(engine, checkfirst=True)
    
    def _migrate_add_compliance(self):
        """Add compliance reports"""
        engine = self.get_engine()
        ComplianceReport.__table__.create(engine, checkfirst=True)
    
    # ========================================================================
    # Verification
    # ========================================================================
    
    def verify_data_integrity(self) -> Dict[str, Any]:
        """Verify database data integrity"""
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": [],
            "errors": [],
            "warnings": [],
        }
        
        session = self.get_session()
        
        # Check schema version
        version = self.get_current_version()
        results["schema_version"] = version
        results["checks"].append(f"Schema version: {version}")
        
        # Check table counts
        try:
            for model in [Organization, CertificateAuthority, EnhancedCertificate, 
                         EnhancedAuditLog, VCCCodeSignature]:
                try:
                    count = session.query(model).count()
                    results["checks"].append(f"{model.__tablename__}: {count} records")
                except Exception:
                    results["warnings"].append(f"Table {model.__tablename__} not found")
        except Exception as e:
            results["errors"].append(f"Error checking tables: {e}")
        
        # Verify audit chain integrity
        if self.config.audit_chain_enabled:
            try:
                audit_logs = session.query(EnhancedAuditLog).order_by(EnhancedAuditLog.id).all()
                previous_hash = ""
                chain_valid = True
                
                for log in audit_logs:
                    if log.entry_hash:
                        expected_hash = log.calculate_hash(previous_hash)
                        if log.entry_hash != expected_hash:
                            chain_valid = False
                            results["errors"].append(f"Audit chain broken at entry {log.id}")
                            break
                        previous_hash = log.entry_hash
                
                if chain_valid:
                    results["checks"].append("Audit chain integrity verified")
                else:
                    results["errors"].append("Audit chain integrity check failed")
            except Exception as e:
                results["warnings"].append(f"Could not verify audit chain: {e}")
        
        results["success"] = len(results["errors"]) == 0
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        session = self.get_session()
        stats = {
            "database_type": self.config.database_type.value,
            "schema_version": self.get_current_version(),
            "multi_tenant_enabled": self.config.multi_tenant_enabled,
            "tables": {},
        }
        
        # Count records in each table
        models = [
            ("organizations", Organization),
            ("certificate_authorities", CertificateAuthority),
            ("certificates", EnhancedCertificate),
            ("templates", CertificateTemplate),
            ("audit_logs", EnhancedAuditLog),
            ("code_signatures", VCCCodeSignature),
            ("compliance_reports", ComplianceReport),
        ]
        
        for name, model in models:
            try:
                count = session.query(model).count()
                stats["tables"][name] = count
            except Exception:
                stats["tables"][name] = "N/A"
        
        return stats


# ============================================================================
# FastAPI Router
# ============================================================================

def create_migration_router(migration: DatabaseMigration):
    """Create FastAPI router for database migration"""
    from fastapi import APIRouter, HTTPException
    
    router = APIRouter(prefix="/api/v1/database", tags=["Database"])
    
    @router.get("/status")
    async def get_status():
        """Get database status"""
        return migration.get_statistics()
    
    @router.get("/version")
    async def get_version():
        """Get current schema version"""
        version = migration.get_current_version()
        return {"version": version}
    
    @router.post("/migrate")
    async def run_migrations():
        """Run pending migrations"""
        try:
            applied = migration.run_migrations()
            return {
                "success": True,
                "applied_versions": applied,
                "current_version": migration.get_current_version()
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.post("/backup")
    async def backup_database():
        """Backup the database"""
        try:
            backup_path = migration.backup_database()
            return {"success": True, "backup_path": backup_path}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/verify")
    async def verify_integrity():
        """Verify database integrity"""
        return migration.verify_data_integrity()
    
    return router


# ============================================================================
# Module Initialization
# ============================================================================

# Default migration instance
_default_migration: Optional[DatabaseMigration] = None


def get_migration() -> DatabaseMigration:
    """Get the default migration instance"""
    global _default_migration
    if _default_migration is None:
        _default_migration = DatabaseMigration()
    return _default_migration


def set_migration(migration: DatabaseMigration):
    """Set the default migration instance"""
    global _default_migration
    _default_migration = migration
