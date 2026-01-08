"""
Authentication and Authorization for BIND9 REST API
Supports JWT tokens and API keys (static or database-backed)

Modes:
- Static API Key (no database): Set BIND9_API_AUTH_STATIC_API_KEY
- Database mode: Set BIND9_API_DATABASE_ENABLED=true
"""

from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import JWTError, jwt
from pydantic import BaseModel
import secrets
import hashlib

from .config import settings


# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name=settings.auth_api_key_header, auto_error=False)


# Conditionally import database if enabled
if settings.database_enabled:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select
    from .database import get_db, APIKey, User


class Token(BaseModel):
    """JWT Token response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Data extracted from JWT token"""
    username: Optional[str] = None
    scopes: List[str] = []


class UserCreate(BaseModel):
    """User creation model"""
    username: str
    password: str
    email: Optional[str] = None
    scopes: List[str] = ["read"]  # Default scope


class UserResponse(BaseModel):
    """User response model (no password)"""
    id: int
    username: str
    email: Optional[str]
    scopes: List[str]
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class APIKeyCreate(BaseModel):
    """API Key creation model"""
    name: str
    scopes: List[str] = ["read"]
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    """API Key response model"""
    id: int
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime
    last_used_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class APIKeyCreated(APIKeyResponse):
    """API Key creation response (includes full key)"""
    api_key: str  # Only shown once at creation


# Available scopes/permissions
SCOPES = {
    "read": "Read-only access to zones and records",
    "write": "Create, update, delete zones and records",
    "admin": "Full administrative access including server control",
    "dnssec": "DNSSEC key management",
    "stats": "Access to statistics and monitoring",
}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.auth_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(
            token, settings.auth_secret_key, algorithms=[settings.auth_algorithm]
        )
        username: str = payload.get("sub")
        scopes: List[str] = payload.get("scopes", [])
        if username is None:
            return None
        return TokenData(username=username, scopes=scopes)
    except JWTError:
        return None


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key and its hash"""
    # Generate a secure random key
    raw_key = secrets.token_urlsafe(32)
    # Create prefix for identification (first 8 chars)
    prefix = raw_key[:8]
    # Hash the full key for storage
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, prefix, key_hash


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Verify an API key against its stored hash"""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return secrets.compare_digest(key_hash, stored_hash)


def verify_static_api_key(provided_key: str) -> bool:
    """Verify API key against static key from environment"""
    if not settings.auth_static_api_key:
        return False
    return secrets.compare_digest(provided_key, settings.auth_static_api_key)


def generate_api_key() -> tuple:
    """Generate a new API key and its hash (for database mode)"""
    raw_key = secrets.token_urlsafe(32)
    prefix = raw_key[:8]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, prefix, key_hash


def verify_api_key_hash(api_key: str, stored_hash: str) -> bool:
    """Verify an API key against its stored hash"""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return secrets.compare_digest(key_hash, stored_hash)


class AuthenticatedUser(BaseModel):
    """Represents an authenticated user (from JWT or API key)"""
    identifier: str
    scopes: List[str]
    auth_type: str  # "jwt", "api_key", or "none"


async def get_current_user_from_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> Optional[AuthenticatedUser]:
    """Get current user from JWT token"""
    if not credentials:
        return None
    
    token_data = decode_token(credentials.credentials)
    if not token_data:
        return None
    
    return AuthenticatedUser(
        identifier=token_data.username,
        scopes=token_data.scopes,
        auth_type="jwt"
    )


async def get_current_user_from_api_key(
    api_key: Optional[str] = Security(api_key_header),
) -> Optional[AuthenticatedUser]:
    """Get current user/scopes from static API key"""
    if not api_key:
        return None
    
    # Check against static API key from environment
    if verify_static_api_key(api_key):
        scopes = settings.auth_static_api_key_scopes.split(",")
        return AuthenticatedUser(
            identifier="api_key:static",
            scopes=scopes,
            auth_type="api_key"
        )
    
    return None


async def get_current_user(
    token_user: Optional[AuthenticatedUser] = Depends(get_current_user_from_token),
    api_key_user: Optional[AuthenticatedUser] = Depends(get_current_user_from_api_key),
) -> AuthenticatedUser:
    """Get current authenticated user from either JWT or API key"""
    
    if not settings.auth_enabled:
        # Auth disabled, return admin user
        return AuthenticatedUser(
            identifier="anonymous",
            scopes=list(SCOPES.keys()),
            auth_type="none"
        )
    
    if token_user:
        return token_user
    
    if api_key_user:
        return api_key_user
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scopes(*required_scopes: str):
    """Dependency to require specific scopes"""
    async def scope_checker(
        current_user: AuthenticatedUser = Depends(get_current_user)
    ) -> AuthenticatedUser:
        # Admin scope grants access to everything
        if "admin" in current_user.scopes:
            return current_user
        
        for scope in required_scopes:
            if scope not in current_user.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scope: {scope}",
                )
        return current_user
    
    return scope_checker


# Convenience dependencies
require_read = require_scopes("read")
require_write = require_scopes("write")
require_admin = require_scopes("admin")
require_dnssec = require_scopes("dnssec")
require_stats = require_scopes("stats")

