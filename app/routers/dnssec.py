"""
DNSSEC API Router
DNSSEC key management and signing operations
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, Body
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import AuthenticatedUser, require_dnssec, require_admin
from ..database import get_db, log_audit
from ..models.dnssec import (
    DNSSECAlgorithm, DNSSECDigestType, KeyType,
    DNSSECKeyCreate, DNSSECKeyResponse, SigningStatus,
    DSRecordResponse, NegativeTrustAnchor, NTACreate,
    KeyRolloverRequest, KeyRolloverStatus
)
from ..models.common import OperationResult
from ..services.dnssec import DNSSECService, DNSSECError


router = APIRouter(prefix="/dnssec", tags=["DNSSEC"])


def get_dnssec_service() -> DNSSECService:
    return DNSSECService()


# =============================================================================
# Key Management
# =============================================================================

@router.get(
    "/zones/{zone_name}/keys",
    response_model=List[DNSSECKeyResponse],
    summary="List DNSSEC keys",
    description="List all DNSSEC keys for a zone"
)
async def list_keys(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """List all DNSSEC keys for a zone"""
    try:
        return await dnssec_service.list_keys(zone_name)
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/zones/{zone_name}/keys",
    response_model=DNSSECKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate DNSSEC key",
    description="Generate a new DNSSEC key for a zone"
)
async def generate_key(
    zone_name: str = Path(..., description="Zone name"),
    key_create: DNSSECKeyCreate = Body(...),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Generate a new DNSSEC key"""
    try:
        key = await dnssec_service.generate_key(
            zone=zone_name,
            key_type=key_create.key_type,
            algorithm=key_create.algorithm,
            bits=key_create.bits,
            ttl=key_create.ttl,
            publish=key_create.publish,
            activate=key_create.activate,
            inactive=key_create.inactive,
            delete=key_create.delete,
        )
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="dnssec_key",
            resource_id=f"{zone_name}/{key.key_tag}",
            details=f"type={key_create.key_type}, algorithm={key_create.algorithm}",
        )
        
        return key
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete(
    "/zones/{zone_name}/keys/{key_tag}",
    response_model=OperationResult,
    summary="Delete DNSSEC key",
    description="Delete a DNSSEC key"
)
async def delete_key(
    zone_name: str = Path(..., description="Zone name"),
    key_tag: int = Path(..., description="Key tag"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Delete a DNSSEC key"""
    try:
        await dnssec_service.delete_key(zone_name, key_tag)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="dnssec_key",
            resource_id=f"{zone_name}/{key_tag}",
        )
        
        return OperationResult(
            success=True,
            operation="delete_key",
            message=f"Key {key_tag} deleted from zone {zone_name}",
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# Zone Signing
# =============================================================================

@router.get(
    "/zones/{zone_name}/status",
    response_model=SigningStatus,
    summary="Get signing status",
    description="Get DNSSEC signing status for a zone"
)
async def get_signing_status(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Get zone signing status"""
    try:
        return await dnssec_service.get_signing_status(zone_name)
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/zones/{zone_name}/sign",
    response_model=OperationResult,
    summary="Sign zone",
    description="Sign or re-sign a zone"
)
async def sign_zone(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Sign a zone"""
    try:
        await dnssec_service.sign_zone(zone_name)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="SIGN",
            resource_type="zone",
            resource_id=zone_name,
        )
        
        return OperationResult(
            success=True,
            operation="sign_zone",
            message=f"Zone {zone_name} signing initiated",
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/zones/{zone_name}/loadkeys",
    response_model=OperationResult,
    summary="Load DNSSEC keys",
    description="Load DNSSEC keys for a zone"
)
async def load_keys(
    zone_name: str = Path(..., description="Zone name"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Load DNSSEC keys for a zone"""
    try:
        await dnssec_service.loadkeys(zone_name)
        
        return OperationResult(
            success=True,
            operation="loadkeys",
            message=f"Keys loaded for zone {zone_name}",
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# DS Records
# =============================================================================

@router.get(
    "/zones/{zone_name}/ds",
    response_model=List[DSRecordResponse],
    summary="Get DS records",
    description="Generate DS records for registrar"
)
async def get_ds_records(
    zone_name: str = Path(..., description="Zone name"),
    digest_types: Optional[str] = Query(
        None,
        description="Comma-separated digest types (1=SHA-1, 2=SHA-256, 4=SHA-384)"
    ),
    key_tag: Optional[int] = Query(None, description="Specific key tag"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Generate DS records for registrar"""
    try:
        # Parse digest types
        digest_type_list = None
        if digest_types:
            digest_type_list = [
                DNSSECDigestType(int(d.strip()))
                for d in digest_types.split(",")
            ]
        
        return await dnssec_service.generate_ds_records(
            zone=zone_name,
            digest_types=digest_type_list,
            key_tag=key_tag,
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# Key Rollover
# =============================================================================

@router.post(
    "/zones/{zone_name}/rollover",
    response_model=OperationResult,
    summary="Initiate key rollover",
    description="Start a key rollover process"
)
async def initiate_rollover(
    zone_name: str = Path(..., description="Zone name"),
    rollover: KeyRolloverRequest = Body(...),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Initiate key rollover"""
    try:
        # Generate new key
        key = await dnssec_service.generate_key(
            zone=zone_name,
            key_type=rollover.key_type,
            algorithm=rollover.new_algorithm or DNSSECAlgorithm.ECDSAP256SHA256,
            bits=rollover.new_bits,
        )
        
        # Load new keys
        await dnssec_service.loadkeys(zone_name)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="ROLLOVER",
            resource_type="dnssec_key",
            resource_id=zone_name,
            details=f"type={rollover.key_type}, new_key={key.key_tag}",
        )
        
        return OperationResult(
            success=True,
            operation="key_rollover",
            message=f"Key rollover initiated. New key tag: {key.key_tag}",
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# Negative Trust Anchors
# =============================================================================

@router.get(
    "/nta",
    response_model=List[NegativeTrustAnchor],
    summary="List NTAs",
    description="List all Negative Trust Anchors"
)
async def list_ntas(
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_dnssec),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """List all Negative Trust Anchors"""
    try:
        return await dnssec_service.list_ntas(view)
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post(
    "/nta",
    response_model=NegativeTrustAnchor,
    status_code=status.HTTP_201_CREATED,
    summary="Add NTA",
    description="Add a Negative Trust Anchor"
)
async def add_nta(
    nta: NTACreate = Body(...),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Add a Negative Trust Anchor"""
    try:
        result = await dnssec_service.add_nta(
            domain=nta.zone,
            lifetime=nta.lifetime,
            force=nta.force,
        )
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="nta",
            resource_id=nta.zone,
            details=f"lifetime={nta.lifetime}, reason={nta.reason}",
        )
        
        return result
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete(
    "/nta/{domain}",
    response_model=OperationResult,
    summary="Remove NTA",
    description="Remove a Negative Trust Anchor"
)
async def remove_nta(
    domain: str = Path(..., description="Domain name"),
    view: Optional[str] = Query(None, description="View name"),
    current_user: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    dnssec_service: DNSSECService = Depends(get_dnssec_service),
):
    """Remove a Negative Trust Anchor"""
    try:
        await dnssec_service.remove_nta(domain, view)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="nta",
            resource_id=domain,
        )
        
        return OperationResult(
            success=True,
            operation="remove_nta",
            message=f"NTA for {domain} removed",
        )
        
    except DNSSECError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

