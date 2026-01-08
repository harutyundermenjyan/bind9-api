"""
Common models and types used across the API
"""

from datetime import datetime
from typing import Optional, List, Any, Generic, TypeVar
from pydantic import BaseModel, Field, field_validator
from enum import Enum


# Generic type for paginated responses
T = TypeVar("T")


class ResponseStatus(str, Enum):
    """API response status"""
    SUCCESS = "success"
    ERROR = "error"
    PARTIAL = "partial"


class APIResponse(BaseModel, Generic[T]):
    """Standard API response wrapper"""
    status: ResponseStatus = ResponseStatus.SUCCESS
    message: Optional[str] = None
    data: Optional[T] = None
    errors: Optional[List[str]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper"""
    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int
    has_next: bool
    has_prev: bool


class PaginationParams(BaseModel):
    """Pagination parameters"""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=1000)


class HealthStatus(str, Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class HealthCheck(BaseModel):
    """Health check response"""
    status: HealthStatus
    version: str
    uptime: float
    bind9_status: str
    rndc_available: bool
    nsupdate_available: bool
    stats_channel_available: bool
    database_connected: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checks: dict = {}


class ErrorDetail(BaseModel):
    """Detailed error information"""
    code: str
    message: str
    field: Optional[str] = None
    details: Optional[dict] = None


class ValidationError(BaseModel):
    """Validation error response"""
    status: ResponseStatus = ResponseStatus.ERROR
    message: str = "Validation failed"
    errors: List[ErrorDetail]


class OperationResult(BaseModel):
    """Result of a server operation"""
    success: bool
    operation: str
    message: str
    output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BulkOperationResult(BaseModel):
    """Result of a bulk operation"""
    total: int
    successful: int
    failed: int
    results: List[OperationResult]


class TTLValue(BaseModel):
    """TTL value with optional unit"""
    value: int = Field(..., ge=0, le=2147483647)
    
    @field_validator("value")
    @classmethod
    def validate_ttl(cls, v):
        if v < 0:
            raise ValueError("TTL cannot be negative")
        if v > 2147483647:
            raise ValueError("TTL exceeds maximum value")
        return v

