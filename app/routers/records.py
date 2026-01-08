"""
DNS Records API Router
Full CRUD operations for all DNS record types
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, Body
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import AuthenticatedUser, require_read, require_write
from ..database import get_db, log_audit
from ..models.records import (
    RecordType, RecordClass, RecordResponse, RecordCreate, RecordUpdate,
    RecordDelete, RecordQuery, BulkRecordOperation
)
from ..models.common import APIResponse, OperationResult, BulkOperationResult
from ..services.nsupdate import NSUpdateService, NSUpdateError
from ..services.zonefile import ZoneFileService, ZoneFileError
from ..services.rndc import RNDCService
from ..services.validation import ValidationService, get_validation_service


router = APIRouter(prefix="/zones/{zone_name}/records", tags=["Records"])


# Initialize services
def get_nsupdate_service() -> NSUpdateService:
    return NSUpdateService()


def get_zonefile_service() -> ZoneFileService:
    return ZoneFileService()


def get_rndc_service() -> RNDCService:
    return RNDCService()


def get_validator() -> ValidationService:
    return get_validation_service()


# =============================================================================
# Record CRUD Operations
# =============================================================================

@router.get(
    "",
    response_model=List[RecordResponse],
    summary="List all records in zone",
    description="Get all DNS records in a zone with optional filtering"
)
async def list_records(
    zone_name: str = Path(..., description="Zone name"),
    record_type: Optional[RecordType] = Query(None, description="Filter by record type"),
    name: Optional[str] = Query(None, description="Filter by record name"),
    search: Optional[str] = Query(None, description="Search in record data"),
    current_user: AuthenticatedUser = Depends(require_read),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """List all records in a zone"""
    try:
        zone_file = await zonefile_service.get_zone_file_path(zone_name)
        if not zone_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Zone {zone_name} not found"
            )
        
        records = await zonefile_service.get_records(
            zone_name,
            zone_file,
            record_type=record_type.value if record_type else None,
            name=name,
        )
        
        # Apply search filter
        if search:
            records = [r for r in records if search.lower() in str(r).lower()]
        
        # Convert to response model
        return [
            RecordResponse(
                name=r["name"],
                ttl=r.get("ttl", 3600),
                record_class=RecordClass(r.get("class", "IN")),
                record_type=RecordType(r["type"]),
                zone=zone_name,
                rdata=r["rdata"],
            )
            for r in records
        ]
        
    except ZoneFileError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/{record_name}",
    response_model=List[RecordResponse],
    summary="Get records by name",
    description="Get all records for a specific name"
)
async def get_records_by_name(
    zone_name: str = Path(..., description="Zone name"),
    record_name: str = Path(..., description="Record name"),
    record_type: Optional[RecordType] = Query(None, description="Filter by record type"),
    current_user: AuthenticatedUser = Depends(require_read),
    zonefile_service: ZoneFileService = Depends(get_zonefile_service),
):
    """Get all records for a specific name"""
    try:
        zone_file = await zonefile_service.get_zone_file_path(zone_name)
        if not zone_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Zone {zone_name} not found"
            )
        
        records = await zonefile_service.get_records(
            zone_name,
            zone_file,
            record_type=record_type.value if record_type else None,
            name=record_name,
        )
        
        if not records:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No records found for {record_name}"
            )
        
        return [
            RecordResponse(
                name=r["name"],
                ttl=r.get("ttl", 3600),
                record_class=RecordClass(r.get("class", "IN")),
                record_type=RecordType(r["type"]),
                zone=zone_name,
                rdata=r["rdata"],
            )
            for r in records
        ]
        
    except ZoneFileError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a DNS record",
    description="Create a new DNS record with comprehensive validation"
)
async def create_record(
    zone_name: str = Path(..., description="Zone name"),
    record: RecordCreate = Body(...),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
    validator: ValidationService = Depends(get_validator),
):
    """
    Create a new DNS record with comprehensive validation.
    
    All inputs are validated before any changes are made to ensure
    the BIND9 server never receives invalid data.
    """
    try:
        # Format RDATA based on record type
        rdata = nsupdate_service.format_rdata(record.record_type.value, record.data)
        
        # =====================================================================
        # Validate record before creating
        # =====================================================================
        can_proceed, errors = await validator.validate_before_record_create(
            zone=zone_name,
            name=record.name,
            record_type=record.record_type.value,
            data=rdata,
            ttl=record.ttl
        )
        
        if not can_proceed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Validation failed",
                    "errors": errors
                }
            )
        
        # Add record via nsupdate
        await nsupdate_service.add_record(
            zone=zone_name,
            name=record.name,
            record_type=record.record_type.value,
            rdata=rdata,
            ttl=record.ttl,
            record_class=record.record_class.value,
        )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{record.name}/{record.record_type.value}",
            details=f"rdata={rdata}",
        )
        
        return RecordResponse(
            name=record.name,
            ttl=record.ttl,
            record_class=record.record_class,
            record_type=record.record_type,
            zone=zone_name,
            rdata=rdata,
        )
        
    except NSUpdateError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create record: {e.message}"
        )


@router.put(
    "/{record_name}/{record_type}",
    response_model=RecordResponse,
    summary="Update a DNS record",
    description="Update an existing DNS record"
)
async def update_record(
    zone_name: str = Path(..., description="Zone name"),
    record_name: str = Path(..., description="Record name"),
    record_type: RecordType = Path(..., description="Record type"),
    old_rdata: str = Query(..., description="Current record data to replace"),
    record_update: RecordUpdate = Body(...),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Update an existing DNS record"""
    try:
        new_rdata = nsupdate_service.format_rdata(record_type.value, record_update.data) if record_update.data else old_rdata
        new_ttl = record_update.ttl or 3600
        
        # Update record via nsupdate
        await nsupdate_service.update_record(
            zone=zone_name,
            name=record_name,
            record_type=record_type.value,
            old_rdata=old_rdata,
            new_rdata=new_rdata,
            ttl=new_ttl,
        )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="UPDATE",
            resource_type="record",
            resource_id=f"{zone_name}/{record_name}/{record_type.value}",
            details=f"old={old_rdata}, new={new_rdata}",
        )
        
        return RecordResponse(
            name=record_name,
            ttl=new_ttl,
            record_class=RecordClass.IN,
            record_type=record_type,
            zone=zone_name,
            rdata=new_rdata,
        )
        
    except NSUpdateError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update record: {e.message}"
        )


@router.delete(
    "/{record_name}/{record_type}",
    response_model=OperationResult,
    summary="Delete a DNS record",
    description="Delete a DNS record"
)
async def delete_record(
    zone_name: str = Path(..., description="Zone name"),
    record_name: str = Path(..., description="Record name"),
    record_type: RecordType = Path(..., description="Record type"),
    rdata: Optional[str] = Query(None, description="Specific record data to delete"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Delete a DNS record"""
    try:
        await nsupdate_service.delete_record(
            zone=zone_name,
            name=record_name,
            record_type=record_type.value,
            rdata=rdata,
        )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="record",
            resource_id=f"{zone_name}/{record_name}/{record_type.value}",
        )
        
        return OperationResult(
            success=True,
            operation="delete_record",
            message=f"Record {record_name} {record_type.value} deleted",
        )
        
    except NSUpdateError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete record: {e.message}"
        )


@router.delete(
    "/{record_name}",
    response_model=OperationResult,
    summary="Delete all records for a name",
    description="Delete all DNS records for a specific name"
)
async def delete_all_records_by_name(
    zone_name: str = Path(..., description="Zone name"),
    record_name: str = Path(..., description="Record name"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Delete all records for a name"""
    try:
        await nsupdate_service.delete_record(
            zone=zone_name,
            name=record_name,
        )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="record",
            resource_id=f"{zone_name}/{record_name}/*",
        )
        
        return OperationResult(
            success=True,
            operation="delete_records",
            message=f"All records for {record_name} deleted",
        )
        
    except NSUpdateError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete records: {e.message}"
        )


# =============================================================================
# Bulk Operations
# =============================================================================

@router.post(
    "/bulk",
    response_model=BulkOperationResult,
    summary="Bulk record operations",
    description="Perform multiple record operations in one request"
)
async def bulk_operations(
    zone_name: str = Path(..., description="Zone name"),
    bulk_op: BulkRecordOperation = Body(...),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Perform bulk record operations"""
    try:
        # Convert records to nsupdate operations
        operations = []
        for record in bulk_op.records:
            op = {
                "action": bulk_op.operation,
                "name": record.get("name"),
                "type": record.get("record_type") or record.get("type"),
                "ttl": record.get("ttl", 3600),
                "class": record.get("record_class", "IN"),
            }
            
            if bulk_op.operation in ["create", "add"]:
                op["action"] = "add"
                op["rdata"] = nsupdate_service.format_rdata(
                    op["type"],
                    record.get("data", record)
                )
            elif bulk_op.operation == "delete":
                op["rdata"] = record.get("rdata")
            
            operations.append(op)
        
        successful, failed, errors = await nsupdate_service.bulk_update(
            zone=zone_name,
            operations=operations,
        )
        
        # Log audit
        await log_audit(
            db=db,
            user=current_user.identifier,
            action=f"BULK_{bulk_op.operation.upper()}",
            resource_type="record",
            resource_id=zone_name,
            details=f"total={len(operations)}, success={successful}, failed={failed}",
        )
        
        results = [
            OperationResult(
                success=True,
                operation=bulk_op.operation,
                message=f"Operation completed",
            )
            for _ in range(successful)
        ]
        
        for error in errors:
            results.append(OperationResult(
                success=False,
                operation=bulk_op.operation,
                message=error,
            ))
        
        return BulkOperationResult(
            total=len(operations),
            successful=successful,
            failed=failed,
            results=results,
        )
        
    except NSUpdateError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk operation failed: {e.message}"
        )


# =============================================================================
# Convenience Endpoints for Specific Record Types
# =============================================================================

@router.post(
    "/a",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create A record",
    description="Create a new A (IPv4) record"
)
async def create_a_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    address: str = Body(..., embed=True, description="IPv4 address"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create an A record"""
    try:
        await nsupdate_service.add_a_record(zone_name, name, address, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/A",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.A,
            zone=zone_name,
            rdata=address,
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/aaaa",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create AAAA record",
    description="Create a new AAAA (IPv6) record"
)
async def create_aaaa_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    address: str = Body(..., embed=True, description="IPv6 address"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create an AAAA record"""
    try:
        await nsupdate_service.add_aaaa_record(zone_name, name, address, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/AAAA",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.AAAA,
            zone=zone_name,
            rdata=address,
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/cname",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create CNAME record",
    description="Create a new CNAME (alias) record"
)
async def create_cname_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    target: str = Body(..., embed=True, description="Target hostname"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create a CNAME record"""
    try:
        await nsupdate_service.add_cname_record(zone_name, name, target, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/CNAME",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.CNAME,
            zone=zone_name,
            rdata=target,
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/mx",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create MX record",
    description="Create a new MX (mail exchanger) record"
)
async def create_mx_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    preference: int = Body(..., embed=True, description="Priority (lower = higher priority)"),
    exchange: str = Body(..., embed=True, description="Mail server hostname"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create an MX record"""
    try:
        await nsupdate_service.add_mx_record(zone_name, name, preference, exchange, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/MX",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.MX,
            zone=zone_name,
            rdata=f"{preference} {exchange}",
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/txt",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create TXT record",
    description="Create a new TXT record"
)
async def create_txt_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    text: str = Body(..., embed=True, description="Text content"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create a TXT record"""
    try:
        await nsupdate_service.add_txt_record(zone_name, name, text, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/TXT",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.TXT,
            zone=zone_name,
            rdata=f'"{text}"',
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/srv",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create SRV record",
    description="Create a new SRV (service) record"
)
async def create_srv_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name (e.g., _sip._tcp)"),
    priority: int = Body(..., embed=True, description="Priority"),
    weight: int = Body(..., embed=True, description="Weight"),
    port: int = Body(..., embed=True, description="Port number"),
    target: str = Body(..., embed=True, description="Target hostname"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create an SRV record"""
    try:
        await nsupdate_service.add_srv_record(zone_name, name, priority, weight, port, target, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/SRV",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.SRV,
            zone=zone_name,
            rdata=f"{priority} {weight} {port} {target}",
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/caa",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create CAA record",
    description="Create a new CAA (Certificate Authority Authorization) record"
)
async def create_caa_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    flags: int = Body(0, embed=True, description="Flags (0 or 128)"),
    tag: str = Body(..., embed=True, description="Tag (issue, issuewild, iodef)"),
    value: str = Body(..., embed=True, description="CA domain or URL"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create a CAA record"""
    try:
        await nsupdate_service.add_caa_record(zone_name, name, flags, tag, value, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/CAA",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.CAA,
            zone=zone_name,
            rdata=f'{flags} {tag} "{value}"',
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/ns",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create NS record",
    description="Create a new NS (nameserver) record"
)
async def create_ns_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    nameserver: str = Body(..., embed=True, description="Nameserver hostname"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create an NS record"""
    try:
        await nsupdate_service.add_ns_record(zone_name, name, nameserver, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/NS",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.NS,
            zone=zone_name,
            rdata=nameserver,
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/ptr",
    response_model=RecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create PTR record",
    description="Create a new PTR (pointer/reverse DNS) record"
)
async def create_ptr_record(
    zone_name: str = Path(..., description="Zone name"),
    name: str = Body(..., embed=True, description="Record name"),
    ptrdname: str = Body(..., embed=True, description="Pointer domain name"),
    ttl: int = Body(3600, embed=True, description="TTL"),
    current_user: AuthenticatedUser = Depends(require_write),
    db: AsyncSession = Depends(get_db),
    nsupdate_service: NSUpdateService = Depends(get_nsupdate_service),
):
    """Create a PTR record"""
    try:
        await nsupdate_service.add_ptr_record(zone_name, name, ptrdname, ttl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="record",
            resource_id=f"{zone_name}/{name}/PTR",
        )
        
        return RecordResponse(
            name=name,
            ttl=ttl,
            record_class=RecordClass.IN,
            record_type=RecordType.PTR,
            zone=zone_name,
            rdata=ptrdname,
        )
    except NSUpdateError as e:
        raise HTTPException(status_code=500, detail=str(e))

