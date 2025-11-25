# ============================================================================
# VCC PROTECTED SOURCE CODE
# ============================================================================
#
# Copyright (c) 2025 VCC - Veritas Control Center
# License: Proprietary
# Contact: legal@vcc.local
#
# Module: multi_tenant_manager
# Description: Multi-Tenant and Multi-Organization Management for VCC-PKI
# File Path: multi_tenant_manager.py
#
# Version: 1.0.0
# Phase: 2 - Enterprise Features
#
# Author: VCC Security Team
#
# Classification: CONFIDENTIAL
# Security Contact: security@vcc.local
# Allowed Domains: vcc.local
# Required Python: >=3.8
#
# ============================================================================

"""
VCC PKI Multi-Tenant Manager
============================

Enterprise-grade multi-tenant and multi-organization support for VCC-PKI.

Features:
- Organization isolation (strict/collaborative/federated)
- Role-based access control (RBAC)
- Per-organization CA hierarchy
- Cross-organization certificate trust
- Quota management
- Audit trails per organization

Phase: 2 - Enterprise Features
Standards: GDPR, BSI IT-Grundschutz
"""

import os
import uuid
import json
import logging
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from threading import Lock
from functools import wraps

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class IsolationLevel(str, Enum):
    """Organization isolation levels"""
    STRICT = "strict"  # Complete isolation, no sharing
    COLLABORATIVE = "collaborative"  # Can share with approved orgs
    FEDERATED = "federated"  # Part of trust federation


class OrganizationStatus(str, Enum):
    """Organization status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING_APPROVAL = "pending_approval"
    ARCHIVED = "archived"


class TenantRole(str, Enum):
    """Tenant user roles"""
    SUPER_ADMIN = "super_admin"  # Cross-org admin
    ORG_ADMIN = "org_admin"  # Organization administrator
    CERT_MANAGER = "cert_manager"  # Certificate management
    SERVICE_ACCOUNT = "service_account"  # Automated service
    CODE_SIGNER = "code_signer"  # Code signing only
    AUDITOR = "auditor"  # Read-only audit access
    VIEWER = "viewer"  # Read-only access


class PermissionType(str, Enum):
    """Permission types"""
    CREATE_CERTIFICATE = "create_certificate"
    REVOKE_CERTIFICATE = "revoke_certificate"
    RENEW_CERTIFICATE = "renew_certificate"
    VIEW_CERTIFICATE = "view_certificate"
    MANAGE_USERS = "manage_users"
    MANAGE_TEMPLATES = "manage_templates"
    SIGN_CODE = "sign_code"
    VIEW_AUDIT = "view_audit"
    MANAGE_ORGANIZATION = "manage_organization"
    CROSS_ORG_TRUST = "cross_org_trust"
    HSM_ACCESS = "hsm_access"
    TSA_ACCESS = "tsa_access"


# Role permissions mapping
ROLE_PERMISSIONS: Dict[TenantRole, Set[PermissionType]] = {
    TenantRole.SUPER_ADMIN: set(PermissionType),  # All permissions
    TenantRole.ORG_ADMIN: {
        PermissionType.CREATE_CERTIFICATE,
        PermissionType.REVOKE_CERTIFICATE,
        PermissionType.RENEW_CERTIFICATE,
        PermissionType.VIEW_CERTIFICATE,
        PermissionType.MANAGE_USERS,
        PermissionType.MANAGE_TEMPLATES,
        PermissionType.SIGN_CODE,
        PermissionType.VIEW_AUDIT,
        PermissionType.MANAGE_ORGANIZATION,
        PermissionType.HSM_ACCESS,
        PermissionType.TSA_ACCESS,
    },
    TenantRole.CERT_MANAGER: {
        PermissionType.CREATE_CERTIFICATE,
        PermissionType.REVOKE_CERTIFICATE,
        PermissionType.RENEW_CERTIFICATE,
        PermissionType.VIEW_CERTIFICATE,
        PermissionType.VIEW_AUDIT,
    },
    TenantRole.SERVICE_ACCOUNT: {
        PermissionType.CREATE_CERTIFICATE,
        PermissionType.RENEW_CERTIFICATE,
        PermissionType.VIEW_CERTIFICATE,
    },
    TenantRole.CODE_SIGNER: {
        PermissionType.VIEW_CERTIFICATE,
        PermissionType.SIGN_CODE,
        PermissionType.TSA_ACCESS,
    },
    TenantRole.AUDITOR: {
        PermissionType.VIEW_CERTIFICATE,
        PermissionType.VIEW_AUDIT,
    },
    TenantRole.VIEWER: {
        PermissionType.VIEW_CERTIFICATE,
    },
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class OrganizationQuota:
    """Organization resource quotas"""
    max_certificates: int = 1000
    max_users: int = 100
    max_services: int = 50
    max_templates: int = 20
    max_code_signatures_per_day: int = 1000
    max_timestamps_per_day: int = 10000
    certificate_validity_max_days: int = 730
    hsm_key_slots: int = 10


@dataclass
class TenantUser:
    """Tenant user representation"""
    user_id: str
    org_id: str
    username: str
    email: str
    role: TenantRole
    api_key_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    status: str = "active"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def has_permission(self, permission: PermissionType) -> bool:
        """Check if user has a specific permission"""
        return permission in ROLE_PERMISSIONS.get(self.role, set())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding sensitive data)"""
        return {
            "user_id": self.user_id,
            "org_id": self.org_id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "status": self.status,
            "permissions": [p.value for p in ROLE_PERMISSIONS.get(self.role, set())],
        }


@dataclass
class Organization:
    """Organization/Tenant representation"""
    org_id: str
    name: str
    display_name: str
    isolation_level: IsolationLevel = IsolationLevel.STRICT
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    quota: OrganizationQuota = field(default_factory=OrganizationQuota)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    contact_email: Optional[str] = None
    technical_contact: Optional[str] = None
    trusted_orgs: List[str] = field(default_factory=list)  # For COLLABORATIVE/FEDERATED
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Usage counters
    certificate_count: int = 0
    user_count: int = 0
    service_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "org_id": self.org_id,
            "name": self.name,
            "display_name": self.display_name,
            "isolation_level": self.isolation_level.value,
            "status": self.status.value,
            "quota": asdict(self.quota),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "contact_email": self.contact_email,
            "technical_contact": self.technical_contact,
            "trusted_orgs": self.trusted_orgs,
            "usage": {
                "certificates": self.certificate_count,
                "users": self.user_count,
                "services": self.service_count,
            },
        }


@dataclass
class TenantSession:
    """User session for authentication"""
    session_id: str
    user_id: str
    org_id: str
    role: TenantRole
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=8))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at


@dataclass
class TenantAuditEntry:
    """Audit log entry for tenant operations"""
    audit_id: str
    org_id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class MultiTenantConfig:
    """Configuration for multi-tenant manager"""
    enable_multi_tenant: bool = True
    default_quota: OrganizationQuota = field(default_factory=OrganizationQuota)
    session_timeout_hours: int = 8
    max_sessions_per_user: int = 5
    enable_cross_org_trust: bool = True
    enable_federation: bool = True
    storage_path: str = "../tenant_data"
    
    @classmethod
    def from_env(cls) -> "MultiTenantConfig":
        """Create config from environment variables"""
        default_quota = OrganizationQuota(
            max_certificates=int(os.getenv("VCC_TENANT_MAX_CERTS", "1000")),
            max_users=int(os.getenv("VCC_TENANT_MAX_USERS", "100")),
            max_services=int(os.getenv("VCC_TENANT_MAX_SERVICES", "50")),
            max_templates=int(os.getenv("VCC_TENANT_MAX_TEMPLATES", "20")),
            max_code_signatures_per_day=int(os.getenv("VCC_TENANT_MAX_SIGNATURES_DAY", "1000")),
            max_timestamps_per_day=int(os.getenv("VCC_TENANT_MAX_TIMESTAMPS_DAY", "10000")),
            certificate_validity_max_days=int(os.getenv("VCC_TENANT_MAX_CERT_VALIDITY", "730")),
            hsm_key_slots=int(os.getenv("VCC_TENANT_HSM_SLOTS", "10")),
        )
        
        return cls(
            enable_multi_tenant=os.getenv("VCC_MULTI_TENANT_ENABLED", "true").lower() == "true",
            default_quota=default_quota,
            session_timeout_hours=int(os.getenv("VCC_SESSION_TIMEOUT_HOURS", "8")),
            max_sessions_per_user=int(os.getenv("VCC_MAX_SESSIONS_PER_USER", "5")),
            enable_cross_org_trust=os.getenv("VCC_CROSS_ORG_TRUST", "true").lower() == "true",
            enable_federation=os.getenv("VCC_FEDERATION_ENABLED", "true").lower() == "true",
            storage_path=os.getenv("VCC_TENANT_STORAGE_PATH", "../tenant_data"),
        )


# ============================================================================
# Multi-Tenant Manager
# ============================================================================

class MultiTenantManager:
    """
    Enterprise multi-tenant and multi-organization manager.
    
    Provides:
    - Organization management (CRUD)
    - User management with RBAC
    - Session management
    - Quota enforcement
    - Cross-organization trust
    - Audit logging
    """
    
    def __init__(self, config: Optional[MultiTenantConfig] = None):
        """Initialize the multi-tenant manager"""
        self.config = config or MultiTenantConfig()
        self._lock = Lock()
        
        # In-memory storage (would be database in production)
        self._organizations: Dict[str, Organization] = {}
        self._users: Dict[str, TenantUser] = {}  # user_id -> user
        self._sessions: Dict[str, TenantSession] = {}  # session_id -> session
        self._audit_log: List[TenantAuditEntry] = []
        self._api_keys: Dict[str, str] = {}  # api_key_hash -> user_id
        
        # Statistics
        self._stats = {
            "organizations_created": 0,
            "users_created": 0,
            "sessions_created": 0,
            "authentication_attempts": 0,
            "authentication_failures": 0,
            "quota_exceeded_events": 0,
        }
        
        # Initialize storage
        self._storage_path = Path(self.config.storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)
        
        # Load persisted data
        self._load_data()
        
        # Create default organization if none exist
        if not self._organizations:
            self._create_default_organization()
        
        logger.info("✅ Multi-Tenant Manager initialized")
    
    def _load_data(self):
        """Load persisted data from storage"""
        orgs_file = self._storage_path / "organizations.json"
        users_file = self._storage_path / "users.json"
        
        if orgs_file.exists():
            try:
                with open(orgs_file, 'r') as f:
                    orgs_data = json.load(f)
                for org_data in orgs_data:
                    org = Organization(
                        org_id=org_data["org_id"],
                        name=org_data["name"],
                        display_name=org_data["display_name"],
                        isolation_level=IsolationLevel(org_data.get("isolation_level", "strict")),
                        status=OrganizationStatus(org_data.get("status", "active")),
                        contact_email=org_data.get("contact_email"),
                        technical_contact=org_data.get("technical_contact"),
                        trusted_orgs=org_data.get("trusted_orgs", []),
                    )
                    self._organizations[org.org_id] = org
                logger.info(f"✅ Loaded {len(self._organizations)} organizations from storage")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load organizations: {e}")
        
        if users_file.exists():
            try:
                with open(users_file, 'r') as f:
                    users_data = json.load(f)
                for user_data in users_data:
                    user = TenantUser(
                        user_id=user_data["user_id"],
                        org_id=user_data["org_id"],
                        username=user_data["username"],
                        email=user_data["email"],
                        role=TenantRole(user_data["role"]),
                        api_key_hash=user_data.get("api_key_hash"),
                        status=user_data.get("status", "active"),
                    )
                    self._users[user.user_id] = user
                    if user.api_key_hash:
                        self._api_keys[user.api_key_hash] = user.user_id
                logger.info(f"✅ Loaded {len(self._users)} users from storage")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load users: {e}")
    
    def _save_data(self):
        """Save data to persistent storage"""
        orgs_file = self._storage_path / "organizations.json"
        users_file = self._storage_path / "users.json"
        
        try:
            # Save organizations
            orgs_data = []
            for org in self._organizations.values():
                orgs_data.append({
                    "org_id": org.org_id,
                    "name": org.name,
                    "display_name": org.display_name,
                    "isolation_level": org.isolation_level.value,
                    "status": org.status.value,
                    "contact_email": org.contact_email,
                    "technical_contact": org.technical_contact,
                    "trusted_orgs": org.trusted_orgs,
                })
            with open(orgs_file, 'w') as f:
                json.dump(orgs_data, f, indent=2)
            
            # Save users (excluding sensitive data)
            users_data = []
            for user in self._users.values():
                users_data.append({
                    "user_id": user.user_id,
                    "org_id": user.org_id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role.value,
                    "api_key_hash": user.api_key_hash,
                    "status": user.status,
                })
            with open(users_file, 'w') as f:
                json.dump(users_data, f, indent=2)
            
        except Exception as e:
            logger.error(f"❌ Failed to save data: {e}")
    
    def _create_default_organization(self):
        """Create the default (root) organization"""
        default_org = Organization(
            org_id="vcc-root",
            name="vcc-root",
            display_name="VCC Root Organization",
            isolation_level=IsolationLevel.STRICT,
            status=OrganizationStatus.ACTIVE,
            contact_email="admin@vcc.local",
            technical_contact="security@vcc.local",
        )
        self._organizations[default_org.org_id] = default_org
        
        # Create default super admin
        admin_user = TenantUser(
            user_id=str(uuid.uuid4()),
            org_id="vcc-root",
            username="admin",
            email="admin@vcc.local",
            role=TenantRole.SUPER_ADMIN,
        )
        # Generate API key
        api_key = self._generate_api_key(admin_user.user_id)
        admin_user.api_key_hash = self._hash_api_key(api_key)
        
        self._users[admin_user.user_id] = admin_user
        self._api_keys[admin_user.api_key_hash] = admin_user.user_id
        
        self._save_data()
        
        logger.info(f"✅ Created default organization: vcc-root")
        logger.info(f"✅ Created default admin user (API Key: {api_key[:8]}...)")
    
    def _generate_api_key(self, user_id: str) -> str:
        """Generate a secure API key"""
        return f"vcc_{secrets.token_urlsafe(32)}"
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def _audit(
        self,
        org_id: str,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None
    ):
        """Record an audit entry"""
        entry = TenantAuditEntry(
            audit_id=str(uuid.uuid4()),
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
            error_message=error_message,
            ip_address=ip_address,
        )
        self._audit_log.append(entry)
        
        # Keep only last 10000 entries in memory
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]
    
    # ========================================================================
    # Organization Management
    # ========================================================================
    
    def create_organization(
        self,
        name: str,
        display_name: str,
        isolation_level: IsolationLevel = IsolationLevel.STRICT,
        contact_email: Optional[str] = None,
        technical_contact: Optional[str] = None,
        quota: Optional[OrganizationQuota] = None,
        requester_user_id: Optional[str] = None
    ) -> Organization:
        """
        Create a new organization.
        
        Args:
            name: Organization identifier (lowercase, alphanumeric + hyphens)
            display_name: Human-readable name
            isolation_level: Level of isolation from other organizations
            contact_email: Primary contact email
            technical_contact: Technical/security contact email
            quota: Custom resource quotas (uses defaults if not specified)
            requester_user_id: User making the request (for audit)
        
        Returns:
            Created Organization
        """
        with self._lock:
            # Validate name
            if not name.replace('-', '').isalnum() or not name.islower():
                raise ValueError("Organization name must be lowercase alphanumeric with hyphens only")
            
            # Check if exists
            if name in self._organizations:
                raise ValueError(f"Organization already exists: {name}")
            
            # Create organization
            org = Organization(
                org_id=name,
                name=name,
                display_name=display_name,
                isolation_level=isolation_level,
                status=OrganizationStatus.ACTIVE,
                contact_email=contact_email,
                technical_contact=technical_contact,
                quota=quota or self.config.default_quota,
            )
            
            self._organizations[org.org_id] = org
            self._stats["organizations_created"] += 1
            
            # Audit
            self._audit(
                org_id=org.org_id,
                user_id=requester_user_id or "system",
                action="ORGANIZATION_CREATED",
                resource_type="organization",
                resource_id=org.org_id,
                details={
                    "display_name": display_name,
                    "isolation_level": isolation_level.value,
                }
            )
            
            self._save_data()
            
            logger.info(f"✅ Created organization: {org.org_id}")
            return org
    
    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID"""
        return self._organizations.get(org_id)
    
    def list_organizations(
        self,
        status: Optional[OrganizationStatus] = None,
        isolation_level: Optional[IsolationLevel] = None
    ) -> List[Organization]:
        """
        List organizations with optional filtering.
        
        Args:
            status: Filter by status
            isolation_level: Filter by isolation level
        
        Returns:
            List of matching organizations
        """
        orgs = list(self._organizations.values())
        
        if status:
            orgs = [o for o in orgs if o.status == status]
        
        if isolation_level:
            orgs = [o for o in orgs if o.isolation_level == isolation_level]
        
        return orgs
    
    def update_organization(
        self,
        org_id: str,
        display_name: Optional[str] = None,
        contact_email: Optional[str] = None,
        technical_contact: Optional[str] = None,
        status: Optional[OrganizationStatus] = None,
        requester_user_id: Optional[str] = None
    ) -> Organization:
        """Update organization details"""
        with self._lock:
            org = self._organizations.get(org_id)
            if not org:
                raise ValueError(f"Organization not found: {org_id}")
            
            if display_name:
                org.display_name = display_name
            if contact_email:
                org.contact_email = contact_email
            if technical_contact:
                org.technical_contact = technical_contact
            if status:
                org.status = status
            
            org.updated_at = datetime.utcnow()
            
            # Audit
            self._audit(
                org_id=org_id,
                user_id=requester_user_id or "system",
                action="ORGANIZATION_UPDATED",
                resource_type="organization",
                resource_id=org_id,
            )
            
            self._save_data()
            return org
    
    def add_trusted_organization(
        self,
        org_id: str,
        trusted_org_id: str,
        requester_user_id: Optional[str] = None
    ) -> Organization:
        """Add a trusted organization for cross-org certificate trust"""
        with self._lock:
            org = self._organizations.get(org_id)
            if not org:
                raise ValueError(f"Organization not found: {org_id}")
            
            trusted_org = self._organizations.get(trusted_org_id)
            if not trusted_org:
                raise ValueError(f"Trusted organization not found: {trusted_org_id}")
            
            if org.isolation_level == IsolationLevel.STRICT:
                raise ValueError("Strict isolation organizations cannot have trusted orgs")
            
            if trusted_org_id not in org.trusted_orgs:
                org.trusted_orgs.append(trusted_org_id)
                org.updated_at = datetime.utcnow()
                
                # Audit
                self._audit(
                    org_id=org_id,
                    user_id=requester_user_id or "system",
                    action="TRUSTED_ORG_ADDED",
                    resource_type="organization",
                    resource_id=org_id,
                    details={"trusted_org_id": trusted_org_id}
                )
                
                self._save_data()
            
            return org
    
    def remove_trusted_organization(
        self,
        org_id: str,
        trusted_org_id: str,
        requester_user_id: Optional[str] = None
    ) -> Organization:
        """Remove a trusted organization"""
        with self._lock:
            org = self._organizations.get(org_id)
            if not org:
                raise ValueError(f"Organization not found: {org_id}")
            
            if trusted_org_id in org.trusted_orgs:
                org.trusted_orgs.remove(trusted_org_id)
                org.updated_at = datetime.utcnow()
                
                # Audit
                self._audit(
                    org_id=org_id,
                    user_id=requester_user_id or "system",
                    action="TRUSTED_ORG_REMOVED",
                    resource_type="organization",
                    resource_id=org_id,
                    details={"trusted_org_id": trusted_org_id}
                )
                
                self._save_data()
            
            return org
    
    # ========================================================================
    # User Management
    # ========================================================================
    
    def create_user(
        self,
        org_id: str,
        username: str,
        email: str,
        role: TenantRole,
        generate_api_key: bool = True,
        requester_user_id: Optional[str] = None
    ) -> tuple[TenantUser, Optional[str]]:
        """
        Create a new user in an organization.
        
        Args:
            org_id: Organization ID
            username: Username (unique within org)
            email: Email address
            role: User role
            generate_api_key: Whether to generate an API key
            requester_user_id: User making the request
        
        Returns:
            Tuple of (user, api_key) - api_key is None if not generated
        """
        with self._lock:
            org = self._organizations.get(org_id)
            if not org:
                raise ValueError(f"Organization not found: {org_id}")
            
            # Check quota
            if org.user_count >= org.quota.max_users:
                self._stats["quota_exceeded_events"] += 1
                raise ValueError(f"User quota exceeded for organization: {org_id}")
            
            # Check for duplicate username in org
            for user in self._users.values():
                if user.org_id == org_id and user.username == username:
                    raise ValueError(f"Username already exists in organization: {username}")
            
            # Create user
            user = TenantUser(
                user_id=str(uuid.uuid4()),
                org_id=org_id,
                username=username,
                email=email,
                role=role,
            )
            
            api_key = None
            if generate_api_key:
                api_key = self._generate_api_key(user.user_id)
                user.api_key_hash = self._hash_api_key(api_key)
                self._api_keys[user.api_key_hash] = user.user_id
            
            self._users[user.user_id] = user
            org.user_count += 1
            self._stats["users_created"] += 1
            
            # Audit
            self._audit(
                org_id=org_id,
                user_id=requester_user_id or "system",
                action="USER_CREATED",
                resource_type="user",
                resource_id=user.user_id,
                details={
                    "username": username,
                    "role": role.value,
                }
            )
            
            self._save_data()
            
            logger.info(f"✅ Created user: {username} in org: {org_id}")
            return user, api_key
    
    def get_user(self, user_id: str) -> Optional[TenantUser]:
        """Get user by ID"""
        return self._users.get(user_id)
    
    def get_user_by_username(self, org_id: str, username: str) -> Optional[TenantUser]:
        """Get user by username within an organization"""
        for user in self._users.values():
            if user.org_id == org_id and user.username == username:
                return user
        return None
    
    def list_users(
        self,
        org_id: Optional[str] = None,
        role: Optional[TenantRole] = None,
        status: Optional[str] = None
    ) -> List[TenantUser]:
        """
        List users with optional filtering.
        
        Args:
            org_id: Filter by organization
            role: Filter by role
            status: Filter by status
        
        Returns:
            List of matching users
        """
        users = list(self._users.values())
        
        if org_id:
            users = [u for u in users if u.org_id == org_id]
        
        if role:
            users = [u for u in users if u.role == role]
        
        if status:
            users = [u for u in users if u.status == status]
        
        return users
    
    def update_user_role(
        self,
        user_id: str,
        new_role: TenantRole,
        requester_user_id: Optional[str] = None
    ) -> TenantUser:
        """Update user's role"""
        with self._lock:
            user = self._users.get(user_id)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            old_role = user.role
            user.role = new_role
            
            # Audit
            self._audit(
                org_id=user.org_id,
                user_id=requester_user_id or "system",
                action="USER_ROLE_CHANGED",
                resource_type="user",
                resource_id=user_id,
                details={
                    "old_role": old_role.value,
                    "new_role": new_role.value,
                }
            )
            
            self._save_data()
            return user
    
    def regenerate_api_key(
        self,
        user_id: str,
        requester_user_id: Optional[str] = None
    ) -> str:
        """
        Regenerate API key for a user.
        
        Returns the new API key (only visible once!)
        """
        with self._lock:
            user = self._users.get(user_id)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            # Remove old key
            if user.api_key_hash:
                del self._api_keys[user.api_key_hash]
            
            # Generate new key
            new_api_key = self._generate_api_key(user_id)
            user.api_key_hash = self._hash_api_key(new_api_key)
            self._api_keys[user.api_key_hash] = user_id
            
            # Audit
            self._audit(
                org_id=user.org_id,
                user_id=requester_user_id or user_id,
                action="API_KEY_REGENERATED",
                resource_type="user",
                resource_id=user_id,
            )
            
            self._save_data()
            
            logger.info(f"✅ Regenerated API key for user: {user.username}")
            return new_api_key
    
    def disable_user(
        self,
        user_id: str,
        requester_user_id: Optional[str] = None
    ) -> TenantUser:
        """Disable a user account"""
        with self._lock:
            user = self._users.get(user_id)
            if not user:
                raise ValueError(f"User not found: {user_id}")
            
            user.status = "disabled"
            
            # Invalidate all sessions
            self._invalidate_user_sessions(user_id)
            
            # Audit
            self._audit(
                org_id=user.org_id,
                user_id=requester_user_id or "system",
                action="USER_DISABLED",
                resource_type="user",
                resource_id=user_id,
            )
            
            self._save_data()
            
            logger.info(f"✅ Disabled user: {user.username}")
            return user
    
    def _invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user"""
        sessions_to_remove = [
            sid for sid, session in self._sessions.items()
            if session.user_id == user_id
        ]
        for sid in sessions_to_remove:
            del self._sessions[sid]
    
    # ========================================================================
    # Authentication & Sessions
    # ========================================================================
    
    def authenticate_api_key(
        self,
        api_key: str,
        ip_address: Optional[str] = None
    ) -> Optional[TenantSession]:
        """
        Authenticate using API key and create session.
        
        Args:
            api_key: API key
            ip_address: Client IP address
        
        Returns:
            TenantSession if authentication successful, None otherwise
        """
        self._stats["authentication_attempts"] += 1
        
        api_key_hash = self._hash_api_key(api_key)
        user_id = self._api_keys.get(api_key_hash)
        
        if not user_id:
            self._stats["authentication_failures"] += 1
            logger.warning(f"⚠️ Authentication failed: Invalid API key")
            return None
        
        user = self._users.get(user_id)
        if not user or user.status != "active":
            self._stats["authentication_failures"] += 1
            logger.warning(f"⚠️ Authentication failed: User inactive")
            return None
        
        org = self._organizations.get(user.org_id)
        if not org or org.status != OrganizationStatus.ACTIVE:
            self._stats["authentication_failures"] += 1
            logger.warning(f"⚠️ Authentication failed: Organization inactive")
            return None
        
        # Create session
        session = TenantSession(
            session_id=str(uuid.uuid4()),
            user_id=user_id,
            org_id=user.org_id,
            role=user.role,
            ip_address=ip_address,
            expires_at=datetime.utcnow() + timedelta(hours=self.config.session_timeout_hours),
        )
        
        # Enforce max sessions per user
        user_sessions = [s for s in self._sessions.values() if s.user_id == user_id]
        if len(user_sessions) >= self.config.max_sessions_per_user:
            # Remove oldest session
            oldest = min(user_sessions, key=lambda s: s.created_at)
            del self._sessions[oldest.session_id]
        
        self._sessions[session.session_id] = session
        self._stats["sessions_created"] += 1
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Audit
        self._audit(
            org_id=user.org_id,
            user_id=user_id,
            action="USER_AUTHENTICATED",
            resource_type="session",
            resource_id=session.session_id,
            ip_address=ip_address,
        )
        
        logger.info(f"✅ User authenticated: {user.username}")
        return session
    
    def validate_session(self, session_id: str) -> Optional[TenantSession]:
        """
        Validate a session and return it if valid.
        
        Args:
            session_id: Session ID
        
        Returns:
            TenantSession if valid, None otherwise
        """
        session = self._sessions.get(session_id)
        
        if not session:
            return None
        
        if session.is_expired:
            # Cleanup expired session
            del self._sessions[session_id]
            return None
        
        return session
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate (logout) a session"""
        if session_id in self._sessions:
            session = self._sessions[session_id]
            del self._sessions[session_id]
            
            # Audit
            self._audit(
                org_id=session.org_id,
                user_id=session.user_id,
                action="SESSION_INVALIDATED",
                resource_type="session",
                resource_id=session_id,
            )
            
            return True
        return False
    
    # ========================================================================
    # Quota Management
    # ========================================================================
    
    def check_quota(
        self,
        org_id: str,
        resource_type: str,
        increment: int = 1
    ) -> bool:
        """
        Check if an operation would exceed quota.
        
        Args:
            org_id: Organization ID
            resource_type: Type of resource (certificates, users, services, etc.)
            increment: Amount to add
        
        Returns:
            True if quota allows, False if would exceed
        """
        org = self._organizations.get(org_id)
        if not org:
            return False
        
        quota_map = {
            "certificates": (org.certificate_count, org.quota.max_certificates),
            "users": (org.user_count, org.quota.max_users),
            "services": (org.service_count, org.quota.max_services),
        }
        
        if resource_type not in quota_map:
            return True
        
        current, maximum = quota_map[resource_type]
        return (current + increment) <= maximum
    
    def increment_usage(
        self,
        org_id: str,
        resource_type: str,
        increment: int = 1
    ):
        """Increment resource usage counter"""
        with self._lock:
            org = self._organizations.get(org_id)
            if not org:
                return
            
            if resource_type == "certificates":
                org.certificate_count += increment
            elif resource_type == "users":
                org.user_count += increment
            elif resource_type == "services":
                org.service_count += increment
    
    def get_quota_status(self, org_id: str) -> Dict[str, Any]:
        """Get quota usage status for an organization"""
        org = self._organizations.get(org_id)
        if not org:
            return {}
        
        return {
            "org_id": org_id,
            "certificates": {
                "used": org.certificate_count,
                "max": org.quota.max_certificates,
                "percentage": (org.certificate_count / org.quota.max_certificates) * 100,
            },
            "users": {
                "used": org.user_count,
                "max": org.quota.max_users,
                "percentage": (org.user_count / org.quota.max_users) * 100,
            },
            "services": {
                "used": org.service_count,
                "max": org.quota.max_services,
                "percentage": (org.service_count / org.quota.max_services) * 100,
            },
        }
    
    # ========================================================================
    # Authorization
    # ========================================================================
    
    def check_permission(
        self,
        session: TenantSession,
        permission: PermissionType,
        target_org_id: Optional[str] = None
    ) -> bool:
        """
        Check if session has permission for an operation.
        
        Args:
            session: User session
            permission: Required permission
            target_org_id: Target organization (for cross-org operations)
        
        Returns:
            True if permitted, False otherwise
        """
        user = self._users.get(session.user_id)
        if not user:
            return False
        
        # Check if user has the permission
        if not user.has_permission(permission):
            return False
        
        # Cross-org check
        if target_org_id and target_org_id != session.org_id:
            # Only super_admin can do cross-org
            if user.role != TenantRole.SUPER_ADMIN:
                # Check if organizations have trust relationship
                org = self._organizations.get(session.org_id)
                if not org or target_org_id not in org.trusted_orgs:
                    # Check CROSS_ORG_TRUST permission
                    if not user.has_permission(PermissionType.CROSS_ORG_TRUST):
                        return False
        
        return True
    
    def require_permission(self, permission: PermissionType):
        """Decorator to require a specific permission"""
        def decorator(func):
            @wraps(func)
            def wrapper(session: TenantSession, *args, **kwargs):
                if not self.check_permission(session, permission):
                    raise PermissionError(f"Permission denied: {permission.value}")
                return func(session, *args, **kwargs)
            return wrapper
        return decorator
    
    # ========================================================================
    # Audit & Statistics
    # ========================================================================
    
    def get_audit_log(
        self,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100
    ) -> List[TenantAuditEntry]:
        """
        Get audit log entries with filtering.
        
        Args:
            org_id: Filter by organization
            user_id: Filter by user
            action: Filter by action
            limit: Maximum entries to return
        
        Returns:
            List of audit entries
        """
        entries = self._audit_log.copy()
        entries.reverse()  # Most recent first
        
        if org_id:
            entries = [e for e in entries if e.org_id == org_id]
        
        if user_id:
            entries = [e for e in entries if e.user_id == user_id]
        
        if action:
            entries = [e for e in entries if e.action == action]
        
        return entries[:limit]
    
    @property
    def statistics(self) -> Dict[str, Any]:
        """Get multi-tenant statistics"""
        return {
            **self._stats,
            "total_organizations": len(self._organizations),
            "total_users": len(self._users),
            "active_sessions": len([s for s in self._sessions.values() if not s.is_expired]),
            "audit_log_entries": len(self._audit_log),
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get multi-tenant manager status"""
        return {
            "enabled": self.config.enable_multi_tenant,
            "statistics": self.statistics,
            "config": {
                "session_timeout_hours": self.config.session_timeout_hours,
                "max_sessions_per_user": self.config.max_sessions_per_user,
                "cross_org_trust_enabled": self.config.enable_cross_org_trust,
                "federation_enabled": self.config.enable_federation,
            },
        }


# ============================================================================
# FastAPI Router Factory
# ============================================================================

def create_multi_tenant_router(manager: MultiTenantManager):
    """Create FastAPI router for multi-tenant management"""
    from fastapi import APIRouter, HTTPException, Header, Depends
    from pydantic import BaseModel, Field
    from typing import Optional, List
    
    router = APIRouter(prefix="/api/v1/tenants", tags=["Multi-Tenant"])
    
    # Request/Response Models
    class CreateOrganizationRequest(BaseModel):
        name: str = Field(..., min_length=3, max_length=64, pattern="^[a-z0-9-]+$")
        display_name: str = Field(..., min_length=3, max_length=128)
        isolation_level: str = Field(default="strict")
        contact_email: Optional[str] = None
        technical_contact: Optional[str] = None
    
    class CreateUserRequest(BaseModel):
        username: str = Field(..., min_length=3, max_length=64)
        email: str
        role: str = Field(default="viewer")
        generate_api_key: bool = True
    
    class UpdateOrganizationRequest(BaseModel):
        display_name: Optional[str] = None
        contact_email: Optional[str] = None
        technical_contact: Optional[str] = None
        status: Optional[str] = None
    
    class TrustOrganizationRequest(BaseModel):
        trusted_org_id: str
    
    # Dependency for session validation
    async def get_session(authorization: str = Header(...)) -> TenantSession:
        """Validate authorization header and return session"""
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        
        token = authorization.replace("Bearer ", "")
        
        # Check if it's an API key (starts with vcc_)
        if token.startswith("vcc_"):
            session = manager.authenticate_api_key(token)
        else:
            # Check if it's a session ID
            session = manager.validate_session(token)
        
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        return session
    
    # Endpoints
    @router.get("/status")
    async def get_tenant_status():
        """Get multi-tenant manager status"""
        return manager.get_status()
    
    @router.get("/organizations")
    async def list_organizations(
        status: Optional[str] = None,
        isolation_level: Optional[str] = None,
        session: TenantSession = Depends(get_session)
    ):
        """List all organizations"""
        status_enum = OrganizationStatus(status) if status else None
        isolation_enum = IsolationLevel(isolation_level) if isolation_level else None
        
        orgs = manager.list_organizations(status=status_enum, isolation_level=isolation_enum)
        return {
            "total": len(orgs),
            "organizations": [o.to_dict() for o in orgs]
        }
    
    @router.get("/organizations/{org_id}")
    async def get_organization(
        org_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Get organization details"""
        org = manager.get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail=f"Organization not found: {org_id}")
        return org.to_dict()
    
    @router.post("/organizations")
    async def create_organization(
        request: CreateOrganizationRequest,
        session: TenantSession = Depends(get_session)
    ):
        """Create a new organization"""
        if not manager.check_permission(session, PermissionType.MANAGE_ORGANIZATION):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            org = manager.create_organization(
                name=request.name,
                display_name=request.display_name,
                isolation_level=IsolationLevel(request.isolation_level),
                contact_email=request.contact_email,
                technical_contact=request.technical_contact,
                requester_user_id=session.user_id,
            )
            return {"success": True, "organization": org.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.put("/organizations/{org_id}")
    async def update_organization(
        org_id: str,
        request: UpdateOrganizationRequest,
        session: TenantSession = Depends(get_session)
    ):
        """Update organization details"""
        if not manager.check_permission(session, PermissionType.MANAGE_ORGANIZATION, org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            status_enum = OrganizationStatus(request.status) if request.status else None
            org = manager.update_organization(
                org_id=org_id,
                display_name=request.display_name,
                contact_email=request.contact_email,
                technical_contact=request.technical_contact,
                status=status_enum,
                requester_user_id=session.user_id,
            )
            return {"success": True, "organization": org.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/organizations/{org_id}/trust")
    async def add_trusted_organization(
        org_id: str,
        request: TrustOrganizationRequest,
        session: TenantSession = Depends(get_session)
    ):
        """Add a trusted organization"""
        if not manager.check_permission(session, PermissionType.CROSS_ORG_TRUST, org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            org = manager.add_trusted_organization(
                org_id=org_id,
                trusted_org_id=request.trusted_org_id,
                requester_user_id=session.user_id,
            )
            return {"success": True, "organization": org.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.delete("/organizations/{org_id}/trust/{trusted_org_id}")
    async def remove_trusted_organization(
        org_id: str,
        trusted_org_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Remove a trusted organization"""
        if not manager.check_permission(session, PermissionType.CROSS_ORG_TRUST, org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            org = manager.remove_trusted_organization(
                org_id=org_id,
                trusted_org_id=trusted_org_id,
                requester_user_id=session.user_id,
            )
            return {"success": True, "organization": org.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/organizations/{org_id}/quota")
    async def get_organization_quota(
        org_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Get organization quota status"""
        quota_status = manager.get_quota_status(org_id)
        if not quota_status:
            raise HTTPException(status_code=404, detail=f"Organization not found: {org_id}")
        return quota_status
    
    @router.get("/users")
    async def list_users(
        org_id: Optional[str] = None,
        role: Optional[str] = None,
        session: TenantSession = Depends(get_session)
    ):
        """List users"""
        role_enum = TenantRole(role) if role else None
        users = manager.list_users(org_id=org_id, role=role_enum)
        return {
            "total": len(users),
            "users": [u.to_dict() for u in users]
        }
    
    @router.get("/users/{user_id}")
    async def get_user(
        user_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Get user details"""
        user = manager.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
        return user.to_dict()
    
    @router.post("/organizations/{org_id}/users")
    async def create_user(
        org_id: str,
        request: CreateUserRequest,
        session: TenantSession = Depends(get_session)
    ):
        """Create a new user in an organization"""
        if not manager.check_permission(session, PermissionType.MANAGE_USERS, org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            user, api_key = manager.create_user(
                org_id=org_id,
                username=request.username,
                email=request.email,
                role=TenantRole(request.role),
                generate_api_key=request.generate_api_key,
                requester_user_id=session.user_id,
            )
            result = {"success": True, "user": user.to_dict()}
            if api_key:
                result["api_key"] = api_key
                result["api_key_warning"] = "Store this API key securely. It will not be shown again."
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/users/{user_id}/regenerate-key")
    async def regenerate_api_key(
        user_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Regenerate API key for a user"""
        user = manager.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
        
        if not manager.check_permission(session, PermissionType.MANAGE_USERS, user.org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            api_key = manager.regenerate_api_key(user_id, session.user_id)
            return {
                "success": True,
                "api_key": api_key,
                "warning": "Store this API key securely. It will not be shown again."
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/users/{user_id}/disable")
    async def disable_user(
        user_id: str,
        session: TenantSession = Depends(get_session)
    ):
        """Disable a user account"""
        user = manager.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail=f"User not found: {user_id}")
        
        if not manager.check_permission(session, PermissionType.MANAGE_USERS, user.org_id):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        try:
            user = manager.disable_user(user_id, session.user_id)
            return {"success": True, "user": user.to_dict()}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/audit")
    async def get_audit_log(
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
        session: TenantSession = Depends(get_session)
    ):
        """Get audit log entries"""
        if not manager.check_permission(session, PermissionType.VIEW_AUDIT):
            raise HTTPException(status_code=403, detail="Permission denied")
        
        entries = manager.get_audit_log(
            org_id=org_id,
            user_id=user_id,
            action=action,
            limit=limit
        )
        
        return {
            "total": len(entries),
            "entries": [
                {
                    "audit_id": e.audit_id,
                    "org_id": e.org_id,
                    "user_id": e.user_id,
                    "action": e.action,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "timestamp": e.timestamp.isoformat(),
                    "success": e.success,
                }
                for e in entries
            ]
        }
    
    @router.post("/logout")
    async def logout(session: TenantSession = Depends(get_session)):
        """Logout current session"""
        manager.invalidate_session(session.session_id)
        return {"success": True, "message": "Logged out successfully"}
    
    return router


# ============================================================================
# Factory Functions
# ============================================================================

def create_multi_tenant_manager(config: Optional[MultiTenantConfig] = None) -> MultiTenantManager:
    """Create and initialize a multi-tenant manager"""
    return MultiTenantManager(config)


# ============================================================================
# Main (for testing)
# ============================================================================

if __name__ == "__main__":
    # Test the multi-tenant manager
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create manager
    manager = MultiTenantManager()
    
    # List organizations
    orgs = manager.list_organizations()
    print(f"\nOrganizations: {len(orgs)}")
    for org in orgs:
        print(f"  - {org.name}: {org.display_name}")
    
    # List users
    users = manager.list_users()
    print(f"\nUsers: {len(users)}")
    for user in users:
        print(f"  - {user.username} ({user.role.value}) in {user.org_id}")
    
    # Create a new organization
    new_org = manager.create_organization(
        name="brandenburg-rz",
        display_name="Brandenburg Rechenzentrum",
        isolation_level=IsolationLevel.COLLABORATIVE,
        contact_email="admin@brandenburg.de",
    )
    print(f"\nCreated organization: {new_org.name}")
    
    # Create a user
    user, api_key = manager.create_user(
        org_id="brandenburg-rz",
        username="testuser",
        email="test@brandenburg.de",
        role=TenantRole.CERT_MANAGER,
    )
    print(f"\nCreated user: {user.username}")
    print(f"API Key: {api_key[:8]}...")
    
    # Authenticate
    session = manager.authenticate_api_key(api_key)
    if session:
        print(f"\nAuthenticated! Session: {session.session_id[:8]}...")
        print(f"  Org: {session.org_id}")
        print(f"  Role: {session.role.value}")
        print(f"  Expires: {session.expires_at}")
    
    # Check statistics
    print(f"\nStatistics: {manager.statistics}")
