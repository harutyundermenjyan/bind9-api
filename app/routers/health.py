"""
Health Check API Router
Readiness and liveness probes with BIND9 validation
"""

import shutil
from datetime import datetime
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, Body
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models.common import HealthCheck, HealthStatus
from ..database import get_db
from ..services.rndc import RNDCService
from ..services.nsupdate import NSUpdateService
from ..services.stats import StatisticsService
from ..services.validation import ValidationService, get_validation_service


router = APIRouter(tags=["Health"])


# Track startup time
_startup_time = datetime.utcnow()


def get_rndc_service() -> RNDCService:
    return RNDCService()


def get_nsupdate_service() -> NSUpdateService:
    return NSUpdateService()


def get_stats_service() -> StatisticsService:
    return StatisticsService()


def get_validator() -> ValidationService:
    return get_validation_service()


# =============================================================================
# Validation Request/Response Models
# =============================================================================

class ValidateZoneRequest(BaseModel):
    """Request to validate zone configuration"""
    name: str
    zone_type: str = "master"
    soa_mname: Optional[str] = None
    soa_rname: Optional[str] = None
    nameservers: List[str] = []
    ns_addresses: Dict[str, str] = {}


class ValidateRecordRequest(BaseModel):
    """Request to validate record configuration"""
    zone: str
    name: str
    record_type: str
    data: str
    ttl: int = 3600


class ValidationResponse(BaseModel):
    """Validation result"""
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []


@router.get(
    "/health",
    response_model=HealthCheck,
    summary="Health check",
    description="Comprehensive health check of the API and BIND9"
)
async def health_check(
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Comprehensive health check"""
    checks = {}
    overall_status = HealthStatus.HEALTHY
    bind9_status = "unknown"
    
    # Check rndc availability
    rndc_available = rndc_service.is_available()
    checks["rndc_binary"] = "ok" if rndc_available else "not found"
    
    # Check nsupdate availability
    nsupdate_available = nsupdate_service.is_available()
    checks["nsupdate_binary"] = "ok" if nsupdate_available else "not found"
    
    # Check rndc connection to BIND9
    rndc_connected = False
    if rndc_available:
        try:
            rndc_connected = await rndc_service.check_connection()
            checks["rndc_connection"] = "ok" if rndc_connected else "failed"
            if rndc_connected:
                bind9_status = "running"
            else:
                bind9_status = "not responding"
                overall_status = HealthStatus.DEGRADED
        except Exception as e:
            checks["rndc_connection"] = str(e)
            bind9_status = "error"
            overall_status = HealthStatus.DEGRADED
    else:
        checks["rndc_connection"] = "skipped (rndc not found)"
        overall_status = HealthStatus.DEGRADED
    
    # Check statistics channel
    stats_available = False
    try:
        stats_available = await stats_service.is_available()
        checks["statistics_channel"] = "ok" if stats_available else "not available"
    except Exception as e:
        checks["statistics_channel"] = str(e)
    
    # Check database connection
    db_connected = False
    if not settings.database_enabled:
        checks["database"] = "disabled"
        db_connected = True  # Not a failure if intentionally disabled
    else:
        try:
            await db.execute("SELECT 1")
            db_connected = True
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = str(e)
            overall_status = HealthStatus.DEGRADED
    
    # Calculate uptime
    uptime = (datetime.utcnow() - _startup_time).total_seconds()
    
    # Determine overall status
    if not rndc_connected or not db_connected:
        if overall_status != HealthStatus.UNHEALTHY:
            overall_status = HealthStatus.DEGRADED
    
    return HealthCheck(
        status=overall_status,
        version=settings.api_version,
        uptime=uptime,
        bind9_status=bind9_status,
        rndc_available=rndc_available,
        nsupdate_available=nsupdate_available,
        stats_channel_available=stats_available,
        database_connected=db_connected,
        checks=checks,
    )


@router.get(
    "/health/live",
    summary="Liveness probe",
    description="Simple liveness check for Kubernetes"
)
async def liveness():
    """Liveness probe - just check if the API is running"""
    return {"status": "alive"}


@router.get(
    "/health/ready",
    summary="Readiness probe",
    description="Readiness check for Kubernetes"
)
async def readiness(
    rndc_service: RNDCService = Depends(get_rndc_service),
    db: AsyncSession = Depends(get_db),
):
    """Readiness probe - check if dependencies are available"""
    errors = []
    
    # Check database (skip if disabled)
    if settings.database_enabled:
        try:
            await db.execute("SELECT 1")
        except Exception as e:
            errors.append(f"database: {e}")
    
    # Check rndc
    if not rndc_service.is_available():
        errors.append("rndc: not found")
    else:
        try:
            connected = await rndc_service.check_connection()
            if not connected:
                errors.append("rndc: cannot connect to BIND9")
        except Exception as e:
            errors.append(f"rndc: {e}")
    
    if errors:
        return {"status": "not ready", "errors": errors}
    
    return {"status": "ready"}


@router.get(
    "/version",
    summary="API version",
    description="Get API version information"
)
async def version():
    """Get API version"""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "description": settings.api_description,
    }


# =============================================================================
# Validation Endpoints
# =============================================================================

@router.get(
    "/validate/preflight",
    response_model=ValidationResponse,
    summary="Pre-flight validation",
    description="Run pre-flight checks to verify BIND9 is ready for changes"
)
async def preflight_validation(
    validator: ValidationService = Depends(get_validator),
):
    """
    Run pre-flight validation to ensure BIND9 is ready for changes.
    
    Checks:
    - BIND9 is running and responding
    - named-checkzone is available
    - named-checkconf is available
    - Current configuration is valid
    """
    passed, issues = await validator.preflight_check()
    
    return ValidationResponse(
        valid=passed,
        errors=issues if not passed else [],
        warnings=[]
    )


@router.post(
    "/validate/zone",
    response_model=ValidationResponse,
    summary="Validate zone configuration",
    description="Validate a zone configuration before creating it"
)
async def validate_zone(
    request: ValidateZoneRequest = Body(...),
    validator: ValidationService = Depends(get_validator),
):
    """
    Validate zone configuration before creating.
    
    This performs all validations that would be done during zone creation,
    without actually making any changes. Use this to verify configurations
    are valid before applying them.
    """
    can_proceed, errors = await validator.validate_before_zone_create(
        zone_name=request.name,
        zone_type=request.zone_type,
        soa_mname=request.soa_mname,
        soa_rname=request.soa_rname,
        nameservers=request.nameservers,
        ns_addresses=request.ns_addresses
    )
    
    return ValidationResponse(
        valid=can_proceed,
        errors=errors if not can_proceed else [],
        warnings=[]
    )


@router.post(
    "/validate/record",
    response_model=ValidationResponse,
    summary="Validate record configuration",
    description="Validate a DNS record before creating it"
)
async def validate_record(
    request: ValidateRecordRequest = Body(...),
    validator: ValidationService = Depends(get_validator),
):
    """
    Validate record configuration before creating.
    
    This performs all validations that would be done during record creation,
    without actually making any changes.
    """
    can_proceed, errors = await validator.validate_before_record_create(
        zone=request.zone,
        name=request.name,
        record_type=request.record_type,
        data=request.data,
        ttl=request.ttl
    )
    
    return ValidationResponse(
        valid=can_proceed,
        errors=errors if not can_proceed else [],
        warnings=[]
    )


@router.get(
    "/validate/config",
    response_model=ValidationResponse,
    summary="Validate BIND9 configuration",
    description="Validate the current BIND9 configuration using named-checkconf"
)
async def validate_bind9_config(
    validator: ValidationService = Depends(get_validator),
):
    """
    Validate the current BIND9 configuration.
    
    Runs named-checkconf to verify the configuration is valid.
    """
    is_valid, output = await validator.check_config()
    
    return ValidationResponse(
        valid=is_valid,
        errors=[output] if not is_valid and output else [],
        warnings=[]
    )

