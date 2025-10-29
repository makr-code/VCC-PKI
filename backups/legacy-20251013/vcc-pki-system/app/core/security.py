# VCC PKI System - Security & Authentication Framework
# Comprehensive security layer with RBAC, JWT, and Keycloak integration

from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass
from pathlib import Path
import json
import httpx
import asyncio

from app.core.config import VCCPKIConfig

logger = logging.getLogger(__name__)

# Security Configuration
ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

class UserRole(str, Enum):
    """User roles for RBAC"""
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin" 
    PKI_ADMIN = "pki_admin"
    SERVICE_ADMIN = "service_admin"
    AUDITOR = "auditor"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"

class Permission(str, Enum):
    """Granular permissions for PKI operations"""
    # CA Operations
    CA_CREATE = "ca:create"
    CA_VIEW = "ca:view"
    CA_DELETE = "ca:delete"
    CA_MANAGE = "ca:manage"
    
    # Certificate Operations
    CERT_REQUEST = "cert:request"
    CERT_VIEW = "cert:view"
    CERT_REVOKE = "cert:revoke"
    CERT_MANAGE = "cert:manage"
    
    # Code Signing
    CODE_SIGN = "code:sign"
    CODE_VERIFY = "code:verify"
    CODE_AUDIT = "code:audit"
    
    # Organization Management
    ORG_CREATE = "org:create"
    ORG_VIEW = "org:view"
    ORG_MANAGE = "org:manage"
    
    # Service Management
    SERVICE_REGISTER = "service:register"
    SERVICE_VIEW = "service:view"
    SERVICE_MANAGE = "service:manage"
    
    # System Administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_HEALTH = "system:health"
    SYSTEM_BACKUP = "system:backup"
    
    # Audit & Compliance
    AUDIT_VIEW = "audit:view"
    AUDIT_EXPORT = "audit:export"
    COMPLIANCE_REPORT = "compliance:report"

@dataclass
class UserContext:
    """User context for authentication and authorization"""
    user_id: str
    username: str
    email: Optional[str]
    organization_id: str
    roles: List[UserRole]
    permissions: List[Permission]
    is_service_account: bool = False
    token_type: str = "Bearer"
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    
    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role"""
        return role in self.roles
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        return permission in self.permissions
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions"""
        return any(perm in self.permissions for perm in permissions)
    
    def can_access_organization(self, org_id: str) -> bool:
        """Check if user can access specific organization"""
        # Super admins can access all organizations
        if UserRole.SUPER_ADMIN in self.roles:
            return True
        # Users can only access their own organization
        return self.organization_id == org_id

# Role-based permission mapping
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.SUPER_ADMIN: [perm for perm in Permission],  # All permissions
    
    UserRole.ORG_ADMIN: [
        Permission.CA_VIEW, Permission.CA_CREATE, Permission.CA_MANAGE,
        Permission.CERT_REQUEST, Permission.CERT_VIEW, Permission.CERT_REVOKE, Permission.CERT_MANAGE,
        Permission.CODE_SIGN, Permission.CODE_VERIFY, Permission.CODE_AUDIT,
        Permission.ORG_VIEW, Permission.ORG_MANAGE,
        Permission.SERVICE_REGISTER, Permission.SERVICE_VIEW, Permission.SERVICE_MANAGE,
        Permission.SYSTEM_HEALTH,
        Permission.AUDIT_VIEW, Permission.COMPLIANCE_REPORT
    ],
    
    UserRole.PKI_ADMIN: [
        Permission.CA_VIEW, Permission.CA_CREATE, Permission.CA_MANAGE,
        Permission.CERT_REQUEST, Permission.CERT_VIEW, Permission.CERT_REVOKE, Permission.CERT_MANAGE,
        Permission.SYSTEM_HEALTH, Permission.SYSTEM_BACKUP,
        Permission.AUDIT_VIEW
    ],
    
    UserRole.SERVICE_ADMIN: [
        Permission.CERT_REQUEST, Permission.CERT_VIEW,
        Permission.CODE_SIGN, Permission.CODE_VERIFY,
        Permission.SERVICE_REGISTER, Permission.SERVICE_VIEW, Permission.SERVICE_MANAGE,
        Permission.SYSTEM_HEALTH,
        Permission.AUDIT_VIEW
    ],
    
    UserRole.AUDITOR: [
        Permission.CA_VIEW,
        Permission.CERT_VIEW,
        Permission.CODE_AUDIT,
        Permission.ORG_VIEW,
        Permission.SERVICE_VIEW,
        Permission.SYSTEM_HEALTH,
        Permission.AUDIT_VIEW, Permission.AUDIT_EXPORT, Permission.COMPLIANCE_REPORT
    ],
    
    UserRole.USER: [
        Permission.CERT_REQUEST, Permission.CERT_VIEW,
        Permission.CODE_VERIFY,
        Permission.SERVICE_VIEW,
        Permission.SYSTEM_HEALTH
    ],
    
    UserRole.SERVICE_ACCOUNT: [
        Permission.CERT_REQUEST, Permission.CERT_VIEW,
        Permission.CODE_SIGN, Permission.CODE_VERIFY,
        Permission.SERVICE_VIEW,
        Permission.SYSTEM_HEALTH
    ]
}

class SecurityManager:
    """Central security management for VCC PKI System"""
    
    def __init__(self, config: VCCPKIConfig):
        self.config = config
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.bearer_scheme = HTTPBearer(auto_error=False)
        
        # JWT Configuration
        self.secret_key = config.jwt_secret_key
        self.algorithm = ALGORITHM
        
        # Mock user database (in production, use real user store)
        self.mock_users = self._initialize_mock_users()
        
        # API Key management
        self.api_keys: Dict[str, UserContext] = {}
        
        logger.info(f"Security Manager initialized - Mock mode: {config.mock_mode}")
    
    def _initialize_mock_users(self) -> Dict[str, Dict[str, Any]]:
        """Initialize mock users for development"""
        mock_users = {
            "admin": {
                "user_id": "admin-001",
                "username": "admin",
                "email": "admin@brandenburg.de",
                "hashed_password": self.get_password_hash("admin123"),
                "organization_id": "brandenburg-gov",
                "roles": [UserRole.SUPER_ADMIN],
                "active": True
            },
            "pki-admin": {
                "user_id": "pki-admin-001", 
                "username": "pki-admin",
                "email": "pki-admin@brandenburg.de",
                "hashed_password": self.get_password_hash("pki123"),
                "organization_id": "brandenburg-gov",
                "roles": [UserRole.PKI_ADMIN],
                "active": True
            },
            "service-admin": {
                "user_id": "svc-admin-001",
                "username": "service-admin", 
                "email": "service-admin@brandenburg.de",
                "hashed_password": self.get_password_hash("service123"),
                "organization_id": "brandenburg-gov",
                "roles": [UserRole.SERVICE_ADMIN],
                "active": True
            },
            "auditor": {
                "user_id": "auditor-001",
                "username": "auditor",
                "email": "auditor@brandenburg.de", 
                "hashed_password": self.get_password_hash("audit123"),
                "organization_id": "brandenburg-gov",
                "roles": [UserRole.AUDITOR],
                "active": True
            },
            "test-user": {
                "user_id": "user-001",
                "username": "test-user",
                "email": "test-user@brandenburg.de",
                "hashed_password": self.get_password_hash("user123"),
                "organization_id": "brandenburg-gov", 
                "roles": [UserRole.USER],
                "active": True
            }
        }
        
        # Generate API keys for service accounts
        self._generate_service_account_api_keys()
        
        return mock_users
    
    def _generate_service_account_api_keys(self):
        """Generate API keys for VCC service accounts"""
        service_accounts = [
            ("argus-service", "Argus Analysis Engine"),
            ("covina-service", "Covina Document System"),
            ("clara-service", "Clara AI Platform"),
            ("veritas-service", "Veritas Verification"),
            ("vpb-service", "Virtual Private Blockchain")
        ]
        
        for service_id, service_name in service_accounts:
            api_key = self.generate_api_key()
            user_context = UserContext(
                user_id=f"{service_id}-001",
                username=service_id,
                email=f"{service_id}@vcc.internal",
                organization_id="brandenburg-gov",
                roles=[UserRole.SERVICE_ACCOUNT],
                permissions=ROLE_PERMISSIONS[UserRole.SERVICE_ACCOUNT],
                is_service_account=True
            )
            self.api_keys[api_key] = user_context
            
            logger.info(f"Generated API key for {service_name}: {api_key[:16]}...")
    
    def get_password_hash(self, password: str) -> str:
        """Hash password using bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def generate_api_key(self) -> str:
        """Generate secure API key"""
        return f"vcc-pki-{secrets.token_urlsafe(32)}"
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token"""
        data = {
            "sub": user_id,
            "type": "refresh",
            "exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "iat": datetime.utcnow()
        }
        
        encoded_jwt = jwt.encode(data, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != "access":
                return None
                
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.utcnow().timestamp() > exp:
                return None
                
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[UserContext]:
        """Authenticate user with username/password"""
        if not self.config.mock_mode:
            # In production, authenticate against Keycloak
            return self._keycloak_authenticate(username, password)
        
        # Mock authentication
        user_data = self.mock_users.get(username)
        if not user_data or not user_data.get("active"):
            return None
        
        if not self.verify_password(password, user_data["hashed_password"]):
            return None
        
        # Create user context
        permissions = []
        for role in user_data["roles"]:
            permissions.extend(ROLE_PERMISSIONS.get(role, []))
        
        return UserContext(
            user_id=user_data["user_id"],
            username=user_data["username"],
            email=user_data.get("email"),
            organization_id=user_data["organization_id"],
            roles=user_data["roles"],
            permissions=list(set(permissions)),  # Remove duplicates
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
    
    def authenticate_api_key(self, api_key: str) -> Optional[UserContext]:
        """Authenticate using API key"""
        return self.api_keys.get(api_key)
    
    def _keycloak_authenticate(self, username: str, password: str) -> Optional[UserContext]:
        """Authenticate against Keycloak (production implementation)"""
        # TODO: Implement real Keycloak authentication
        logger.info(f"Keycloak authentication for {username} - TODO: Implement")
        return None
    
    async def get_current_user(
        self, 
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> UserContext:
        """Get current authenticated user from request"""
        
        if self.config.mock_mode and not credentials:
            # In mock mode, return default admin user if no auth provided
            return UserContext(
                user_id="mock-admin",
                username="mock-admin",
                email="mock-admin@brandenburg.de",
                organization_id="brandenburg-gov",
                roles=[UserRole.SUPER_ADMIN],
                permissions=ROLE_PERMISSIONS[UserRole.SUPER_ADMIN],
                is_service_account=False
            )
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = credentials.credentials
        
        # Try API key authentication first
        if token.startswith("vcc-pki-"):
            user_context = self.authenticate_api_key(token)
            if user_context:
                return user_context
        
        # Try JWT token authentication
        payload = self.verify_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        
        # Get user data
        user_data = self.mock_users.get(username)
        if not user_data or not user_data.get("active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        
        # Create user context
        permissions = []
        for role in user_data["roles"]:
            permissions.extend(ROLE_PERMISSIONS.get(role, []))
        
        return UserContext(
            user_id=user_data["user_id"],
            username=user_data["username"],
            email=user_data.get("email"),
            organization_id=user_data["organization_id"],
            roles=user_data["roles"],
            permissions=list(set(permissions)),
            issued_at=datetime.fromtimestamp(payload.get("iat", datetime.utcnow().timestamp())),
            expires_at=datetime.fromtimestamp(payload.get("exp", datetime.utcnow().timestamp()))
        )

def create_permission_checker(*required_permissions: Permission):
    """Create a dependency that checks for specific permissions"""
    def permission_checker(current_user: UserContext = Depends(SecurityManager.get_current_user)) -> UserContext:
        if not current_user.has_any_permission(list(required_permissions)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[p.value for p in required_permissions]}"
            )
        return current_user
    return permission_checker

def create_role_checker(*required_roles: UserRole):
    """Create a dependency that checks for specific roles"""
    def role_checker(current_user: UserContext = Depends(SecurityManager.get_current_user)) -> UserContext:
        if not any(current_user.has_role(role) for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {[r.value for r in required_roles]}"
            )
        return current_user
    return role_checker

def create_organization_checker(org_id_param: str = None):
    """Create a dependency that checks organization access"""
    def org_checker(
        current_user: UserContext = Depends(SecurityManager.get_current_user),
        org_id: str = org_id_param
    ) -> UserContext:
        if org_id and not current_user.can_access_organization(org_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to organization: {org_id}"
            )
        return current_user
    return org_checker

# Security middleware for rate limiting
class RateLimiter:
    """Simple rate limiter for API endpoints"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed based on rate limit"""
        now = datetime.utcnow()
        minute_key = now.strftime("%Y-%m-%d-%H-%M")
        
        key = f"{identifier}:{minute_key}"
        
        if key not in self.requests:
            self.requests[key] = 0
        
        if self.requests[key] >= self.requests_per_minute:
            return False
        
        self.requests[key] += 1
        
        # Cleanup old entries
        self._cleanup_old_entries(now)
        
        return True
    
    def _cleanup_old_entries(self, now: datetime):
        """Remove old rate limit entries"""
        cutoff = now - timedelta(minutes=2)
        cutoff_key = cutoff.strftime("%Y-%m-%d-%H-%M")
        
        keys_to_remove = [key for key in self.requests.keys() 
                         if key.split(':')[1] < cutoff_key]
        
        for key in keys_to_remove:
            del self.requests[key]

# Rate limiter instances
general_limiter = RateLimiter(requests_per_minute=60)
auth_limiter = RateLimiter(requests_per_minute=10)
admin_limiter = RateLimiter(requests_per_minute=30)

def rate_limit(limiter: RateLimiter):
    """Rate limiting decorator"""
    def decorator(request: Request):
        client_ip = request.client.host
        
        if not limiter.is_allowed(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        return True
    
    return decorator

# Keycloak integration (TODO: Implement for production)
class KeycloakIntegration:
    """Keycloak integration for production authentication"""
    
    def __init__(self, config: VCCPKIConfig):
        self.config = config
        self.keycloak_url = config.keycloak_url
        self.realm = config.keycloak_realm
        self.client_id = config.keycloak_client_id
        self.client_secret = config.keycloak_client_secret
    
    async def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against Keycloak"""
        # TODO: Implement Keycloak authentication
        logger.info("Keycloak authentication - TODO: Implement for production")
        return None
    
    async def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token against Keycloak"""
        # TODO: Implement Keycloak token validation
        logger.info("Keycloak token validation - TODO: Implement for production")
        return None
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get user roles from Keycloak"""
        # TODO: Implement Keycloak role retrieval
        logger.info("Keycloak role retrieval - TODO: Implement for production") 
        return []
    
    async def refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh access token using refresh token"""
        # TODO: Implement Keycloak token refresh
        logger.info("Keycloak token refresh - TODO: Implement for production")
        return None

# Export main components
__all__ = [
    "SecurityManager",
    "UserContext", 
    "UserRole",
    "Permission",
    "create_permission_checker",
    "create_role_checker", 
    "create_organization_checker",
    "rate_limit",
    "general_limiter",
    "auth_limiter", 
    "admin_limiter",
    "KeycloakIntegration"
]