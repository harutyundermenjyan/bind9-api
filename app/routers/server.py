"""
Server Control API Router
All RNDC commands and server management operations
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import AuthenticatedUser, require_read, require_write, require_admin
from ..database import get_db, log_audit
from ..models.server import (
    ServerStatus, ServerCommand, ServerCommandResult, RNDCCommand,
    View, ViewResponse, ACL, ACLResponse
)
from ..models.common import OperationResult
from ..services.rndc import RNDCService, RNDCError


router = APIRouter(prefix="/server", tags=["Server Control"])


def get_rndc_service() -> RNDCService:
    return RNDCService()


# =============================================================================
# Server Status
# =============================================================================

@router.get(
    "/status",
    response_model=ServerStatus,
    summary="Get server status",
    description="Get BIND9 server status and information"
)
async def get_server_status(
    current_user: AuthenticatedUser = Depends(require_read),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Get server status"""
    try:
        return await rndc_service.status()
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot connect to BIND9: {e.message}"
        )


@router.get(
    "/version",
    summary="Get BIND9 version",
    description="Get the BIND9 server version"
)
async def get_server_version(
    current_user: AuthenticatedUser = Depends(require_read),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Get BIND9 version"""
    try:
        version = await rndc_service.version()
        return {"version": version}
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Configuration Operations
# =============================================================================

@router.post(
    "/reload",
    response_model=OperationResult,
    summary="Reload server",
    description="Reload all zones and configuration"
)
async def reload_server(
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Reload server configuration and all zones"""
    result = await rndc_service.reload()
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="RELOAD",
        resource_type="server",
    )
    
    return OperationResult(
        success=result.success,
        operation="reload",
        message="Server reloaded" if result.success else result.error,
        output=result.output,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/reconfig",
    response_model=OperationResult,
    summary="Reload configuration",
    description="Reload named.conf configuration only"
)
async def reconfig_server(
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Reload configuration file only"""
    result = await rndc_service.reconfig()
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="RECONFIG",
        resource_type="server",
    )
    
    return OperationResult(
        success=result.success,
        operation="reconfig",
        message="Configuration reloaded" if result.success else result.error,
        output=result.output,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# Cache Operations
# =============================================================================

@router.post(
    "/cache/flush",
    response_model=OperationResult,
    summary="Flush cache",
    description="Flush all cached DNS data"
)
async def flush_cache(
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Flush all cache"""
    result = await rndc_service.flush(view)
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="FLUSH_CACHE",
        resource_type="server",
        details=f"view={view}" if view else None,
    )
    
    return OperationResult(
        success=result.success,
        operation="flush",
        message="Cache flushed" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/cache/flush/name",
    response_model=OperationResult,
    summary="Flush cached name",
    description="Flush a specific name from cache"
)
async def flush_cache_name(
    name: str = Query(..., description="Name to flush"),
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Flush specific name from cache"""
    result = await rndc_service.flushname(name, view)
    
    return OperationResult(
        success=result.success,
        operation="flushname",
        message=f"Name {name} flushed" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/cache/flush/tree",
    response_model=OperationResult,
    summary="Flush cached tree",
    description="Flush entire tree under a name from cache"
)
async def flush_cache_tree(
    name: str = Query(..., description="Root name of tree to flush"),
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Flush entire tree from cache"""
    result = await rndc_service.flushtree(name, view)
    
    return OperationResult(
        success=result.success,
        operation="flushtree",
        message=f"Tree under {name} flushed" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# Debug Operations
# =============================================================================

@router.post(
    "/querylog",
    response_model=OperationResult,
    summary="Toggle query logging",
    description="Enable or disable query logging"
)
async def toggle_querylog(
    enable: Optional[bool] = Query(None, description="Enable (true) or disable (false), toggle if not specified"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Toggle or set query logging"""
    result = await rndc_service.querylog(enable)
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="QUERYLOG",
        resource_type="server",
        details=f"enable={enable}" if enable is not None else "toggle",
    )
    
    return OperationResult(
        success=result.success,
        operation="querylog",
        message=result.output if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/trace",
    response_model=OperationResult,
    summary="Set debug level",
    description="Set server debug/trace level"
)
async def set_trace_level(
    level: int = Query(1, ge=0, le=99, description="Debug level (0 to disable)"),
    current_user: AuthenticatedUser = Depends(require_admin),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Set debug trace level"""
    if level == 0:
        result = await rndc_service.notrace()
    else:
        result = await rndc_service.trace(level)
    
    return OperationResult(
        success=result.success,
        operation="trace",
        message=f"Debug level set to {level}" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/dumpdb",
    response_model=OperationResult,
    summary="Dump database",
    description="Dump cache database to file"
)
async def dump_database(
    dump_type: str = Query("-all", description="Dump type: -all, -cache, -zones, -adb, -bad, -fail"),
    current_user: AuthenticatedUser = Depends(require_admin),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Dump database to file"""
    result = await rndc_service.dumpdb(dump_type)
    
    return OperationResult(
        success=result.success,
        operation="dumpdb",
        message="Database dumped" if result.success else result.error,
        output=result.output,
        duration_ms=result.duration_ms,
    )


@router.get(
    "/recursing",
    response_model=OperationResult,
    summary="Dump recursive queries",
    description="Get list of current recursive queries"
)
async def dump_recursing(
    current_user: AuthenticatedUser = Depends(require_admin),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Dump current recursive queries"""
    result = await rndc_service.recursing()
    
    return OperationResult(
        success=result.success,
        operation="recursing",
        message="Recursive queries dumped" if result.success else result.error,
        output=result.output,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# DNSSEC Validation
# =============================================================================

@router.post(
    "/validation",
    response_model=OperationResult,
    summary="Set DNSSEC validation",
    description="Enable or disable DNSSEC validation"
)
async def set_validation(
    enable: bool = Query(..., description="Enable or disable validation"),
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Enable or disable DNSSEC validation"""
    result = await rndc_service.validation(enable, view)
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="VALIDATION",
        resource_type="server",
        details=f"enable={enable}, view={view}",
    )
    
    return OperationResult(
        success=result.success,
        operation="validation",
        message=f"Validation {'enabled' if enable else 'disabled'}" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# Stale Cache
# =============================================================================

@router.post(
    "/serve-stale",
    response_model=OperationResult,
    summary="Set serve-stale",
    description="Enable or disable serving stale cache data"
)
async def set_serve_stale(
    enable: bool = Query(..., description="Enable or disable serve-stale"),
    current_user: AuthenticatedUser = Depends(require_admin),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Enable or disable serve-stale"""
    result = await rndc_service.serve_stale(enable)
    
    return OperationResult(
        success=result.success,
        operation="serve-stale",
        message=f"Serve-stale {'enabled' if enable else 'disabled'}" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# TCP Timeouts
# =============================================================================

@router.get(
    "/tcp-timeouts",
    response_model=OperationResult,
    summary="Get TCP timeouts",
    description="Get current TCP timeout values"
)
async def get_tcp_timeouts(
    current_user: AuthenticatedUser = Depends(require_read),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Get TCP timeout values"""
    result = await rndc_service.tcp_timeouts()
    
    return OperationResult(
        success=result.success,
        operation="tcp-timeouts",
        message=result.output if result.success else result.error,
        output=result.output,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/tcp-timeouts",
    response_model=OperationResult,
    summary="Set TCP timeouts",
    description="Set TCP timeout values"
)
async def set_tcp_timeouts(
    initial: int = Query(..., description="Initial timeout"),
    idle: int = Query(..., description="Idle timeout"),
    keepalive: int = Query(..., description="Keepalive timeout"),
    advertised: int = Query(..., description="Advertised timeout"),
    current_user: AuthenticatedUser = Depends(require_admin),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Set TCP timeout values"""
    result = await rndc_service.tcp_timeouts(initial, idle, keepalive, advertised)
    
    return OperationResult(
        success=result.success,
        operation="tcp-timeouts",
        message="TCP timeouts updated" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


# =============================================================================
# Raw Command Execution
# =============================================================================

@router.post(
    "/command",
    response_model=ServerCommandResult,
    summary="Execute RNDC command",
    description="Execute any RNDC command directly"
)
async def execute_command(
    command: ServerCommand = Body(...),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Execute raw RNDC command"""
    result = await rndc_service.execute(command)
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action=f"RNDC_{command.command.value.upper()}",
        resource_type="server",
        resource_id=command.zone,
        details=f"args={command.args}",
    )
    
    return result


# =============================================================================
# Server Shutdown (Dangerous!)
# =============================================================================

@router.post(
    "/stop",
    response_model=OperationResult,
    summary="Stop server",
    description="Stop BIND9 server gracefully (DANGEROUS!)"
)
async def stop_server(
    confirm: bool = Query(False, description="Confirm server stop"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Stop BIND9 server gracefully"""
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server stop requires confirmation. Set confirm=true to proceed."
        )
    
    result = await rndc_service.stop()
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="STOP",
        resource_type="server",
        status="success" if result.success else "failed",
    )
    
    return OperationResult(
        success=result.success,
        operation="stop",
        message="Server stopped" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/halt",
    response_model=OperationResult,
    summary="Halt server",
    description="Halt BIND9 server immediately (DANGEROUS!)"
)
async def halt_server(
    confirm: bool = Query(False, description="Confirm server halt"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Halt BIND9 server immediately"""
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server halt requires confirmation. Set confirm=true to proceed."
        )
    
    result = await rndc_service.halt()
    
    await log_audit(
        db=db,
        user=current_user.identifier,
        action="HALT",
        resource_type="server",
        status="success" if result.success else "failed",
    )
    
    return OperationResult(
        success=result.success,
        operation="halt",
        message="Server halted" if result.success else result.error,
        duration_ms=result.duration_ms,
    )

