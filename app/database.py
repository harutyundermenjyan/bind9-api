"""
Database models and session management for BIND9 REST API
Uses SQLAlchemy with async support for audit logs and API key storage

When database_enabled is False, audit logs go to the application log instead.
"""

import logging
from datetime import datetime
from typing import AsyncGenerator, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Index
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

from .config import settings


logger = logging.getLogger(__name__)

# Only create engine if database is enabled
engine = None
async_session = None

if settings.database_enabled:
    # Create async engine
    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        future=True,
    )

    # Session factory
    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

# Base class for models
Base = declarative_base()


class User(Base):
    """User model for JWT authentication"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    scopes = Column(String(500), default="read")  # Comma-separated scopes
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class APIKey(Base):
    """API Key model for key-based authentication"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    key_prefix = Column(String(8), nullable=False, index=True)  # For identification
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash
    scopes = Column(String(500), default="read")  # Comma-separated scopes
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), nullable=True)  # Username who created this key


class AuditLog(Base):
    """Audit log for tracking all API operations"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user = Column(String(100), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)  # CREATE, UPDATE, DELETE, etc.
    resource_type = Column(String(50), nullable=False)  # zone, record, server, etc.
    resource_id = Column(String(255), nullable=True)  # Zone name, record name, etc.
    details = Column(Text, nullable=True)  # JSON details of the operation
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    status = Column(String(20), default="success")  # success, failed
    error_message = Column(Text, nullable=True)
    
    __table_args__ = (
        Index('idx_audit_timestamp_action', 'timestamp', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )


class ZoneCache(Base):
    """Cache for zone metadata (optional, for faster lookups)"""
    __tablename__ = "zone_cache"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_name = Column(String(255), unique=True, nullable=False, index=True)
    zone_type = Column(String(20), nullable=False)  # master, slave, forward, stub
    zone_file = Column(String(500), nullable=True)
    serial = Column(Integer, nullable=True)
    last_reload = Column(DateTime, nullable=True)
    record_count = Column(Integer, nullable=True)
    dnssec_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


async def init_db():
    """Initialize database tables"""
    if not settings.database_enabled or engine is None:
        logger.info("Database disabled, skipping table creation")
        return
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class DummySession:
    """Dummy session when database is disabled"""
    async def execute(self, *args, **kwargs):
        pass
    async def commit(self):
        pass
    async def close(self):
        pass
    def add(self, *args, **kwargs):
        pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    if not settings.database_enabled or async_session is None:
        # Return a dummy session that does nothing
        yield DummySession()
        return
    
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def log_audit(
    db,  # Can be AsyncSession or DummySession
    user: str,
    action: str,
    resource_type: str,
    resource_id: str = None,
    details: str = None,
    ip_address: str = None,
    user_agent: str = None,
    status: str = "success",
    error_message: str = None,
):
    """
    Log an audit entry.
    
    If database is enabled, logs to the database.
    If database is disabled, logs to the application log.
    """
    if not settings.audit_log_enabled:
        return
    
    # Build log message
    log_msg = f"AUDIT: user={user} action={action} resource={resource_type}"
    if resource_id:
        log_msg += f"/{resource_id}"
    if details:
        log_msg += f" details={details}"
    if status != "success":
        log_msg += f" status={status}"
    if error_message:
        log_msg += f" error={error_message}"
    
    # If database is disabled, log to application log
    if not settings.database_enabled or isinstance(db, DummySession):
        if status == "success":
            logger.info(log_msg)
        else:
            logger.warning(log_msg)
        return
    
    # Log to database
    try:
        audit = AuditLog(
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            error_message=error_message,
        )
        db.add(audit)
        await db.commit()
    except Exception as e:
        # If database write fails, fall back to application log
        logger.warning(f"{log_msg} (db_error: {e})")

