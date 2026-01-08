"""
Authentication API Router
Supports both static API key and database-backed authentication

Modes:
- Static API Key (no database): Simple, secure, no setup required
- Database mode: User management, multiple API keys, audit logs
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional

from ..config import settings
from ..auth import (
    AuthenticatedUser, get_current_user, require_admin,
    create_access_token, SCOPES
)


router = APIRouter(prefix="/auth", tags=["Authentication"])


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AuthInfo(BaseModel):
    """Authentication configuration info"""
    auth_enabled: bool
    mode: str  # "static" or "database"
    api_key_header: str
    available_scopes: dict


class APIKeyInfo(BaseModel):
    """API Key information"""
    configured: bool
    scopes: List[str]
    header_name: str


# =============================================================================
# Authentication Info
# =============================================================================

@router.get(
    "/info",
    response_model=AuthInfo,
    summary="Authentication info",
    description="Get authentication configuration info"
)
async def get_auth_info():
    """Get authentication info"""
    mode = "database" if settings.database_enabled else "static"
    if not settings.auth_enabled:
        mode = "disabled"
    
    return AuthInfo(
        auth_enabled=settings.auth_enabled,
        mode=mode,
        api_key_header=settings.auth_api_key_header,
        available_scopes=SCOPES,
    )


@router.get(
    "/api-key/info",
    response_model=APIKeyInfo,
    summary="API Key info",
    description="Get information about API key authentication"
)
async def get_api_key_info():
    """Get API key configuration info"""
    scopes = []
    configured = False
    
    if settings.auth_static_api_key:
        configured = True
        scopes = settings.auth_static_api_key_scopes.split(",")
    
    return APIKeyInfo(
        configured=configured,
        scopes=scopes,
        header_name=settings.auth_api_key_header,
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get access token",
    description="Exchange API key for a JWT token (optional, API key can be used directly)"
)
async def get_token_from_api_key(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Exchange API key for JWT token"""
    if current_user.auth_type == "none":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    # Create JWT token from authenticated user
    access_token = create_access_token(
        data={
            "sub": current_user.identifier,
            "scopes": current_user.scopes,
        }
    )
    
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.auth_access_token_expire_minutes * 60,
    )


# =============================================================================
# Current User
# =============================================================================

@router.get(
    "/me",
    summary="Get current user",
    description="Get information about the currently authenticated user"
)
async def get_current_user_info(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get current user info"""
    return {
        "identifier": current_user.identifier,
        "scopes": current_user.scopes,
        "auth_type": current_user.auth_type,
    }


@router.get(
    "/verify",
    summary="Verify authentication",
    description="Verify that authentication is working"
)
async def verify_auth(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Verify authentication"""
    return {
        "authenticated": True,
        "identifier": current_user.identifier,
        "auth_type": current_user.auth_type,
    }


# =============================================================================
# Database Mode Only - User & API Key Management
# =============================================================================

if settings.database_enabled:
    from fastapi.security import OAuth2PasswordRequestForm
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select
    from passlib.context import CryptContext
    from ..database import get_db, User, APIKey, log_audit
    from ..auth import generate_api_key
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    class UserCreate(BaseModel):
        username: str
        password: str
        email: Optional[str] = None
        scopes: List[str] = ["read"]
    
    class UserResponse(BaseModel):
        id: int
        username: str
        email: Optional[str]
        scopes: List[str]
        is_active: bool
    
    class APIKeyCreate(BaseModel):
        name: str
        scopes: List[str] = ["read"]
    
    class APIKeyCreatedResponse(BaseModel):
        name: str
        api_key: str
        scopes: List[str]
        message: str = "Save this API key - it won't be shown again!"
    
    
    @router.post(
        "/login",
        response_model=TokenResponse,
        summary="Login with username/password",
        description="[Database mode] Authenticate with username and password"
    )
    async def login(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: AsyncSession = Depends(get_db),
    ):
        """Login with username/password (database mode only)"""
        result = await db.execute(
            select(User).where(User.username == form_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user or not pwd_context.verify(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
        
        access_token = create_access_token(
            data={
                "sub": user.username,
                "scopes": user.scopes.split(",") if user.scopes else [],
            }
        )
        
        return TokenResponse(
            access_token=access_token,
            expires_in=settings.auth_access_token_expire_minutes * 60,
        )
    
    
    @router.post(
        "/users",
        response_model=UserResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Create user",
        description="[Database mode] Create a new user"
    )
    async def create_user(
        user_data: UserCreate,
        current_user: AuthenticatedUser = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ):
        """Create a new user (database mode only)"""
        user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=pwd_context.hash(user_data.password),
            scopes=",".join(user_data.scopes),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            scopes=user.scopes.split(",") if user.scopes else [],
            is_active=user.is_active,
        )
    
    
    @router.post(
        "/api-keys",
        response_model=APIKeyCreatedResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Create API key",
        description="[Database mode] Create a new API key"
    )
    async def create_api_key_endpoint(
        key_data: APIKeyCreate,
        current_user: AuthenticatedUser = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ):
        """Create a new API key (database mode only)"""
        raw_key, prefix, key_hash = generate_api_key()
        
        api_key = APIKey(
            name=key_data.name,
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=",".join(key_data.scopes),
            created_by=current_user.identifier,
        )
        db.add(api_key)
        await db.commit()
        
        return APIKeyCreatedResponse(
            name=key_data.name,
            api_key=raw_key,
            scopes=key_data.scopes,
        )
