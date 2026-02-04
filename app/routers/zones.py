"""
Zone Management API Router
Full CRUD operations for DNS zones
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import AuthenticatedUser, require_read, require_write, require_admin
from ..database import get_db, log_audit
from ..models.zones import (
    ZoneCreate, ZoneUpdate, ZoneResponse, ZoneListResponse,
    ZoneStatus_Detail, ZoneType, ZoneExport, ZoneImport,
    ZoneTransferRequest
)
from ..models.common import APIResponse, OperationResult
from ..services.rndc import RNDCService, RNDCError
from ..services.zonefile import ZoneFileService, ZoneFileError
from ..services.validation import ValidationService, get_validation_service


router = APIRouter(prefix="/zones", tags=["Zones"])


# Initialize services
def get_rndc_service() -> RNDCService:
    return RNDCService()


def get_zonefile_service() -> ZoneFileService:
    return ZoneFileService()


def get_validator() -> ValidationService:
    return get_validation_service()


# =============================================================================
# Zone CRUD Operations
# =============================================================================

@router.get(
    "",
    response_model=ZoneListResponse,
    summary="List all zones",
    description="Get a list of all configured zones"
)
async def list_zones(
    zone_type: Optional[ZoneType] = Query(None, description="Filter by zone type"),
    search: Optional[str] = Query(None, description="Search zone names"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(require_read),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """List all configured DNS zones"""
    try:
        zones_config = await zonefile_service.list_configured_zones()
        
        # Convert to ZoneResponse objects
        zones = []
        for zone_conf in zones_config:
            zone = ZoneResponse(
                name=zone_conf.get("name", ""),
                zone_type=ZoneType(zone_conf.get("type", "master")),
                file=zone_conf.get("file"),
            )
            zones.append(zone)
        
        # Apply filters
        if zone_type:
            zones = [z for z in zones if z.zone_type == zone_type]
        
        if search:
            zones = [z for z in zones if search.lower() in z.name.lower()]
        
        # Pagination
        total = len(zones)
        start = (page - 1) * page_size
        end = start + page_size
        zones = zones[start:end]
        
        return ZoneListResponse(zones=zones, total=total)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list zones: {str(e)}"
        )


@router.get(
    "/{zone_name}",
    response_model=ZoneResponse,
    summary="Get zone details",
    description="Get detailed information about a specific zone"
)
async def get_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_read),
    rndc_service: RNDCService = Depends(get_rndc_service),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """Get zone details including status and records"""
    try:
        # Get zone status from rndc
        zone_status = await rndc_service.zonestatus(zone_name)
        
        # Get zone file path
        zone_file = await zonefile_service.get_zone_file_path(zone_name)
        
        # Get serial from zone file if available
        serial = None
        if zone_file:
            try:
                serial = await zonefile_service.get_serial(zone_name, zone_file)
            except:
                pass
        
        return ZoneResponse(
            name=zone_name,
            zone_type=ZoneType(zone_status.type) if zone_status.type else ZoneType.MASTER,
            file=zone_file,
            serial=zone_status.serial or serial,
            loaded=zone_status.loaded,
            dnssec_enabled=zone_status.secure,
        )
        
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone not found: {e.message}"
        )


@router.post(
    "",
    response_model=ZoneResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new zone",
    description="Create a new DNS zone with comprehensive validation"
)
async def create_zone(
    zone: ZoneCreate,
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
    validator: ValidationService = Depends(get_validator),
):
    """
    Create a new DNS zone with comprehensive validation.
    
    All inputs are validated before any changes are made to ensure
    the BIND9 server never receives invalid configuration.
    """
    try:
        # =====================================================================
        # Phase 1: Pre-flight validation (before any changes)
        # =====================================================================
        can_proceed, errors = await validator.validate_before_zone_create(
            zone_name=zone.name,
            zone_type=zone.zone_type.value,
            soa_mname=zone.soa_mname,
            soa_rname=zone.soa_rname,
            nameservers=zone.nameservers,
            ns_addresses=zone.ns_addresses
        )
        
        if not can_proceed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Validation failed",
                    "errors": errors
                }
            )
        
        # =====================================================================
        # Phase 2: Create zone file for master zones
        # =====================================================================
        zone_file = zone.file
        if zone.zone_type in [ZoneType.MASTER, ZoneType.PRIMARY]:
            if not zone_file:
                zone_file = await zonefile_service.create_zone_file(
                    zone_name=zone.name,
                    soa_mname=zone.soa_mname or "ns1",
                    soa_rname=zone.soa_rname or "hostmaster",
                    soa_refresh=zone.soa_refresh,
                    soa_retry=zone.soa_retry,
                    soa_expire=zone.soa_expire,
                    soa_minimum=zone.soa_minimum,
                    default_ttl=zone.default_ttl,
                    nameservers=zone.nameservers,
                    ns_addresses=zone.ns_addresses,
                )
            
            # =====================================================================
            # Phase 3: Validate zone file with named-checkzone
            # =====================================================================
            is_valid, validation_msg = await zonefile_service.check_zone(zone.name, zone_file)
            if not is_valid:
                # Clean up the zone file we created
                try:
                    from pathlib import Path
                    Path(zone_file).unlink(missing_ok=True)
                except:
                    pass
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zone file validation failed: {validation_msg}"
                )
        
        # Clean up any orphaned zone files before creating
        # This prevents "out of range" errors from stale journal files
        cleanup_result = await rndc_service.cleanup_zone_files(zone.name)
        
        # Add zone via rndc
        masters = None
        if zone.zone_type in [ZoneType.SLAVE, ZoneType.SECONDARY]:
            masters = [f"{s.address}" for s in zone.options.masters]
        
        # Get allow-update settings
        allow_update = None
        if zone.options and zone.options.allow_update:
            allow_update = zone.options.allow_update
        
        # Get allow-transfer settings
        allow_transfer = None
        if zone.options and zone.options.allow_transfer:
            allow_transfer = zone.options.allow_transfer
        
        result = await rndc_service.addzone(
            zone=zone.name,
            zone_type=zone.zone_type.value,
            file=zone_file,
            masters=masters,
            allow_update=allow_update,
            allow_transfer=allow_transfer,
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to add zone: {result.error}"
            )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="zone",
            resource_id=zone.name,
            details=f"Created zone type={zone.zone_type.value}",
        )
        
        return ZoneResponse(
            name=zone.name,
            zone_type=zone.zone_type,
            file=zone_file,
            loaded=True,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create zone: {str(e)}"
        )


@router.put(
    "/{zone_name}",
    response_model=ZoneResponse,
    summary="Update zone configuration",
    description="Update zone settings"
)
async def update_zone(
    zone_name: str = Path(..., description="Zone name"),
    zone_update: ZoneUpdate = None,
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Update zone configuration"""
    try:
        # Get current zone status
        zone_status = await rndc_service.zonestatus(zone_name)
        
        # Modify zone via rndc
        result = await rndc_service.modzone(
            zone=zone_name,
            zone_type=zone_status.type,
            file=zone_update.file if zone_update and zone_update.file else None,
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to update zone: {result.error}"
            )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="UPDATE",
            resource_type="zone",
            resource_id=zone_name,
        )
        
        return ZoneResponse(
            name=zone_name,
            zone_type=ZoneType(zone_status.type),
            loaded=True,
        )
        
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone not found: {e.message}"
        )


@router.delete(
    "/{zone_name}",
    response_model=OperationResult,
    summary="Delete a zone",
    description="Delete a DNS zone"
)
async def delete_zone(
    zone_name: str = Path(..., description="Zone name"),
    delete_file: bool = Query(False, description="Also delete zone file"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    rndc_service: RNDCService = Depends(get_rndc_service),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """Delete a DNS zone"""
    from pathlib import Path as FilePath
    
    try:
        # Get zone file before deletion
        zone_file = None
        try:
            zone_file = await zonefile_service.get_zone_file_path(zone_name)
        except:
            pass
        
        # Delete zone via rndc
        result = await rndc_service.delzone(zone_name)
        
        # Even if rndc fails, try to clean up files if requested
        # This handles orphaned zones that exist in files but not in named
        cleanup_messages = []
        
        if delete_file:
            # Try to find and delete zone file and related files
            zone_dirs = ["/var/lib/bind", "/var/cache/bind"]
            zone_file_patterns = [
                f"db.{zone_name}",
                f"{zone_name}.db",
                f"db.{zone_name}.jnl",
                f"{zone_name}.db.jnl",
                f"{zone_name}.jnl",
            ]
            
            for zone_dir in zone_dirs:
                dir_path = FilePath(zone_dir)
                if dir_path.exists():
                    for pattern in zone_file_patterns:
                        file_path = dir_path / pattern
                        if file_path.exists():
                            try:
                                file_path.unlink()
                                cleanup_messages.append(f"Deleted {file_path}")
                            except Exception as e:
                                cleanup_messages.append(f"Failed to delete {file_path}: {e}")
            
            # Also delete by exact path if we found it
            if zone_file:
                zone_path = FilePath(zone_file)
                if zone_path.exists():
                    zone_path.unlink(missing_ok=True)
                    cleanup_messages.append(f"Deleted {zone_file}")
                # Delete journal file
                journal_path = FilePath(str(zone_file) + ".jnl")
                if journal_path.exists():
                    journal_path.unlink(missing_ok=True)
                    cleanup_messages.append(f"Deleted {journal_path}")
        
        if not result.success and not cleanup_messages:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete zone: {result.error}"
            )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="zone",
            resource_id=zone_name,
        )
        
        message = f"Zone {zone_name} deleted successfully"
        if cleanup_messages:
            message += f". Cleanup: {'; '.join(cleanup_messages)}"
        
        return OperationResult(
            success=True,
            operation="delete_zone",
            message=message,
        )
        
    except HTTPException:
        raise
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone not found: {e.message}"
        )


# =============================================================================
# Zone Operations
# =============================================================================

@router.post(
    "/{zone_name}/reload",
    response_model=OperationResult,
    summary="Reload zone",
    description="Reload a zone from disk"
)
async def reload_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Reload zone from disk"""
    result = await rndc_service.reload(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="reload_zone",
        message=result.output if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/freeze",
    response_model=OperationResult,
    summary="Freeze zone",
    description="Freeze zone for manual editing"
)
async def freeze_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Freeze zone to allow manual editing"""
    result = await rndc_service.freeze(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="freeze_zone",
        message="Zone frozen" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/thaw",
    response_model=OperationResult,
    summary="Thaw zone",
    description="Thaw a frozen zone"
)
async def thaw_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Thaw a frozen zone"""
    result = await rndc_service.thaw(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="thaw_zone",
        message="Zone thawed" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/sync",
    response_model=OperationResult,
    summary="Sync zone to disk",
    description="Write zone changes to disk"
)
async def sync_zone(
    zone_name: str = Path(..., description="Zone name"),
    clean: bool = Query(False, description="Remove journal after sync"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Sync zone journal to disk"""
    result = await rndc_service.sync(zone_name, clean)
    
    return OperationResult(
        success=result.success,
        operation="sync_zone",
        message="Zone synced" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/notify",
    response_model=OperationResult,
    summary="Send NOTIFY",
    description="Send NOTIFY to slave servers"
)
async def notify_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Send NOTIFY to slave servers"""
    result = await rndc_service.notify(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="notify_zone",
        message="NOTIFY sent" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/retransfer",
    response_model=OperationResult,
    summary="Force zone transfer",
    description="Force zone transfer for slave zones"
)
async def retransfer_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Force zone transfer (for slave zones)"""
    result = await rndc_service.retransfer(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="retransfer_zone",
        message="Zone transfer initiated" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.post(
    "/{zone_name}/refresh",
    response_model=OperationResult,
    summary="Refresh zone",
    description="Schedule zone refresh"
)
async def refresh_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_write),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Schedule zone refresh"""
    result = await rndc_service.refresh(zone_name)
    
    return OperationResult(
        success=result.success,
        operation="refresh_zone",
        message="Zone refresh scheduled" if result.success else result.error,
        duration_ms=result.duration_ms,
    )


@router.get(
    "/{zone_name}/status",
    response_model=ZoneStatus_Detail,
    summary="Get zone status",
    description="Get detailed zone status"
)
async def get_zone_status(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_read),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Get detailed zone status"""
    try:
        return await rndc_service.zonestatus(zone_name)
    except RNDCError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone not found: {e.message}"
        )


# =============================================================================
# Zone Import/Export
# =============================================================================

@router.get(
    "/{zone_name}/export",
    response_model=ZoneExport,
    summary="Export zone",
    description="Export zone to BIND zone file format"
)
async def export_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_read),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """Export zone data"""
    try:
        zone_file = await zonefile_service.get_zone_file_path(zone_name)
        if not zone_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Zone file not found"
            )
        
        zone_data = await zonefile_service.read_zone(zone_name, zone_file)
        zone_content = await zonefile_service.export_zone(zone_name, zone_file)
        
        return ZoneExport(
            name=zone_name,
            zone_type=ZoneType.MASTER,
            serial=zone_data.get("soa", {}).get("serial", 0),
            records=zone_data.get("records", []),
            zone_file_content=zone_content,
        )
        
    except ZoneFileError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/{zone_name}/import",
    response_model=ZoneResponse,
    summary="Import zone",
    description="Import zone from zone file content"
)
async def import_zone(
    zone_name: str = Path(..., description="Zone name"),
    zone_import: ZoneImport = None,
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
    rndc_service: RNDCService = Depends(get_rndc_service),
):
    """Import zone from zone file content"""
    try:
        if not zone_import or not zone_import.zone_file_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Zone file content is required"
            )
        
        # Import zone file
        zone_data = await zonefile_service.import_zone(
            zone_name,
            zone_import.zone_file_content,
        )
        
        # Reload zone
        await rndc_service.reload(zone_name)
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="IMPORT",
            resource_type="zone",
            resource_id=zone_name,
        )
        
        return ZoneResponse(
            name=zone_name,
            zone_type=zone_import.zone_type,
            file=zone_data.get("file"),
            serial=zone_data.get("soa", {}).get("serial"),
            record_count=zone_data.get("record_count"),
            loaded=True,
        )
        
    except ZoneFileError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

