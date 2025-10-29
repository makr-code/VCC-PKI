# VCC PKI System - Authentication Endpoints
# JWT token management, user authentication, and API key handling

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import logging

from app.core.security import (
    SecurityManager, UserContext, UserRole, Permission,
    rate_limit, auth_limiter, general_limiter
)
from app.core.config import VCCPKIConfig, create_config
from app.models import APIResponse, create_success_response, create_error_response

logger = logging.getLogger(__name__)

# Pydantic models for authentication
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class APIKeyRequest(BaseModel):
    name: str
    description: Optional[str] = None
    roles: List[UserRole] = [UserRole.USER]
    expires_in_days: Optional[int] = None

class APIKeyResponse(BaseModel):
    api_key: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime]
    roles: List[UserRole]

class UserProfile(BaseModel):
    user_id: str
    username: str
    email: Optional[str]
    organization_id: str
    roles: List[UserRole]
    permissions: List[Permission]
    is_service_account: bool
    created_at: datetime
    last_login: Optional[datetime]

class PermissionCheck(BaseModel):
    permission: Permission
    resource_id: Optional[str] = None
    organization_id: Optional[str] = None

class PermissionResult(BaseModel):
    permission: Permission
    allowed: bool
    reason: Optional[str] = None

# Router setup
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# Initialize security manager
config = create_config()
security_manager = SecurityManager(config)

@router.post("/login", response_model=APIResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limit: bool = Depends(rate_limit(auth_limiter))
):
    """Authenticate user and return JWT tokens"""
    
    logger.info(f"Login attempt for user: {form_data.username}")
    
    try:
        # Authenticate user
        user_context = security_manager.authenticate_user(
            form_data.username, 
            form_data.password
        )
        
        if not user_context:
            # Log failed login attempt
            logger.warning(f"Failed login attempt for user: {form_data.username} from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Create JWT tokens
        token_data = {
            "sub": user_context.username,
            "user_id": user_context.user_id,
            "organization_id": user_context.organization_id,
            "roles": [role.value for role in user_context.roles]
        }
        
        access_token = security_manager.create_access_token(token_data)
        refresh_token = security_manager.create_refresh_token(user_context.user_id)
        
        # Log successful login
        logger.info(f"Successful login for user: {form_data.username}")
        
        response_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 30 * 60,  # 30 minutes
            "user": {
                "user_id": user_context.user_id,
                "username": user_context.username,
                "email": user_context.email,
                "organization_id": user_context.organization_id,
                "roles": [role.value for role in user_context.roles],
                "permissions": [perm.value for perm in user_context.permissions]
            }
        }
        
        return create_success_response(
            data=response_data,
            message="Login successful"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for user {form_data.username}: {e}")
        return create_error_response(
            "Authentication failed", 
            "AUTH_ERROR"
        )

@router.post("/refresh", response_model=APIResponse)
async def refresh_token(
    refresh_request: RefreshTokenRequest,
    _rate_limit: bool = Depends(rate_limit(auth_limiter))
):
    """Refresh access token using refresh token"""
    
    try:
        # Verify refresh token
        payload = security_manager.verify_token(refresh_request.refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload"
            )
        
        # Find user by ID (in production, query user database)
        user_data = None
        for username, data in security_manager.mock_users.items():
            if data["user_id"] == user_id:
                user_data = data
                break
        
        if not user_data or not user_data.get("active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Create new access token
        token_data = {
            "sub": user_data["username"],
            "user_id": user_data["user_id"],
            "organization_id": user_data["organization_id"],
            "roles": [role.value for role in user_data["roles"]]
        }
        
        new_access_token = security_manager.create_access_token(token_data)
        
        response_data = {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 30 * 60  # 30 minutes
        }
        
        return create_success_response(
            data=response_data,
            message="Token refreshed successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return create_error_response(
            "Token refresh failed",
            "REFRESH_ERROR"
        )

@router.get("/profile", response_model=APIResponse)
async def get_user_profile(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """Get current user profile"""
    
    profile_data = {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "email": current_user.email,
        "organization_id": current_user.organization_id,
        "roles": [role.value for role in current_user.roles],
        "permissions": [perm.value for perm in current_user.permissions],
        "is_service_account": current_user.is_service_account,
        "issued_at": current_user.issued_at.isoformat() if current_user.issued_at else None,
        "expires_at": current_user.expires_at.isoformat() if current_user.expires_at else None
    }
    
    return create_success_response(
        data=profile_data,
        message="User profile retrieved"
    )

@router.post("/check-permission", response_model=APIResponse)
async def check_permission(
    permission_check: PermissionCheck,
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """Check if current user has specific permission"""
    
    has_permission = current_user.has_permission(permission_check.permission)
    
    # Additional organization check if specified
    if permission_check.organization_id:
        has_org_access = current_user.can_access_organization(permission_check.organization_id)
        has_permission = has_permission and has_org_access
        reason = "Organization access denied" if not has_org_access else None
    else:
        reason = None
    
    result = {
        "permission": permission_check.permission.value,
        "allowed": has_permission,
        "reason": reason
    }
    
    return create_success_response(
        data=result,
        message=f"Permission check: {'Allowed' if has_permission else 'Denied'}"
    )

@router.post("/api-keys", response_model=APIResponse)
async def create_api_key(
    api_key_request: APIKeyRequest,
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """Create new API key"""
    
    # Check if user can create API keys
    if not current_user.has_permission(Permission.SYSTEM_CONFIG):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to create API keys"
        )
    
    # Generate API key
    api_key = security_manager.generate_api_key()
    
    # Create expiration date if specified
    expires_at = None
    if api_key_request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=api_key_request.expires_in_days)
    
    # Create user context for API key
    permissions = []
    for role in api_key_request.roles:
        permissions.extend(security_manager.ROLE_PERMISSIONS.get(role, []))
    
    api_key_context = UserContext(
        user_id=f"api-key-{len(security_manager.api_keys) + 1:03d}",
        username=f"api-key-{api_key_request.name}",
        email=None,
        organization_id=current_user.organization_id,
        roles=api_key_request.roles,
        permissions=list(set(permissions)),
        is_service_account=True,
        expires_at=expires_at
    )
    
    # Store API key
    security_manager.api_keys[api_key] = api_key_context
    
    logger.info(f"API key created by {current_user.username}: {api_key_request.name}")
    
    response_data = {
        "api_key": api_key,
        "name": api_key_request.name,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "roles": [role.value for role in api_key_request.roles]
    }
    
    return create_success_response(
        data=response_data,
        message="API key created successfully"
    )

@router.get("/api-keys", response_model=APIResponse)
async def list_api_keys(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """List API keys for current organization"""
    
    # Check permissions
    if not current_user.has_permission(Permission.SYSTEM_CONFIG):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view API keys"
        )
    
    api_keys_data = []
    for api_key, context in security_manager.api_keys.items():
        # Only show keys from same organization
        if context.organization_id == current_user.organization_id:
            api_keys_data.append({
                "api_key_preview": api_key[:16] + "...",
                "username": context.username,
                "roles": [role.value for role in context.roles],
                "created_at": context.issued_at.isoformat() if context.issued_at else "Unknown",
                "expires_at": context.expires_at.isoformat() if context.expires_at else None,
                "is_expired": context.expires_at and context.expires_at < datetime.utcnow() if context.expires_at else False
            })
    
    return create_success_response(
        data=api_keys_data,
        message=f"Found {len(api_keys_data)} API keys"
    )

@router.delete("/api-keys/{api_key_preview}", response_model=APIResponse)
async def revoke_api_key(
    api_key_preview: str,
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """Revoke API key"""
    
    # Check permissions
    if not current_user.has_permission(Permission.SYSTEM_CONFIG):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to revoke API keys"
        )
    
    # Find API key by preview
    api_key_to_revoke = None
    for api_key in list(security_manager.api_keys.keys()):
        if api_key.startswith(api_key_preview):
            context = security_manager.api_keys[api_key]
            # Only allow revoking keys from same organization
            if context.organization_id == current_user.organization_id:
                api_key_to_revoke = api_key
                break
    
    if not api_key_to_revoke:
        return create_error_response(
            "API key not found or access denied",
            "API_KEY_NOT_FOUND"
        )
    
    # Revoke the API key
    del security_manager.api_keys[api_key_to_revoke]
    
    logger.info(f"API key revoked by {current_user.username}: {api_key_preview}")
    
    return create_success_response(
        data={"revoked_key": api_key_preview},
        message="API key revoked successfully"
    )

@router.post("/logout", response_model=APIResponse)
async def logout(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """Logout user (in production, invalidate token)"""
    
    # TODO: In production, add token to blacklist/revocation list
    
    logger.info(f"User logged out: {current_user.username}")
    
    return create_success_response(
        data={"logout_time": datetime.utcnow().isoformat()},
        message="Logged out successfully"
    )

@router.get("/roles", response_model=APIResponse)
async def list_available_roles(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """List available user roles"""
    
    roles_data = []
    for role in UserRole:
        permissions = security_manager.ROLE_PERMISSIONS.get(role, [])
        roles_data.append({
            "role": role.value,
            "permissions_count": len(permissions),
            "permissions": [perm.value for perm in permissions]
        })
    
    return create_success_response(
        data=roles_data,
        message="Available roles retrieved"
    )

@router.get("/permissions", response_model=APIResponse)
async def list_available_permissions(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """List available permissions"""
    
    permissions_data = []
    for permission in Permission:
        permissions_data.append({
            "permission": permission.value,
            "description": f"Permission to {permission.value.replace(':', ' ')}"
        })
    
    return create_success_response(
        data=permissions_data,
        message="Available permissions retrieved"
    )

# Mock users endpoint for development
@router.get("/mock-users", response_model=APIResponse)
async def list_mock_users(
    current_user: UserContext = Depends(security_manager.get_current_user),
    _rate_limit: bool = Depends(rate_limit(general_limiter))
):
    """List mock users (development only)"""
    
    if not config.mock_mode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mock users only available in development mode"
        )
    
    if not current_user.has_permission(Permission.SYSTEM_CONFIG):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    mock_users_data = []
    for username, data in security_manager.mock_users.items():
        mock_users_data.append({
            "username": username,
            "user_id": data["user_id"],
            "email": data.get("email"),
            "organization_id": data["organization_id"],
            "roles": [role.value for role in data["roles"]],
            "active": data.get("active", False)
        })
    
    return create_success_response(
        data=mock_users_data,
        message=f"Mock users (development mode): {len(mock_users_data)} users"
    )