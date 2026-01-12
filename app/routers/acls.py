"""
ACL Router - API endpoints for managing BIND9 Access Control Lists
"""

from typing import List
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.acls import (
    ACLCreate, ACLUpdate, ACLResponse, ACLListResponse
)
from ..services.acls import ACLService, ACLError
from ..auth import require_read, require_write, require_admin, AuthenticatedUser
from ..database import log_audit, get_db

router = APIRouter(prefix="/api/v1/acls", tags=["ACLs"])


def get_acl_service() -> ACLService:
    """Dependency to get ACL service"""
    return ACLService()


# =============================================================================
# List / Read Operations
# =============================================================================

@router.get(
    "",
    response_model=ACLListResponse,
    summary="List all ACLs",
    description="Get a list of all defined Access Control Lists"
)
async def list_acls(
    current_user: AuthenticatedUser = Depends(require_read),
    acl_service: ACLService = Depends(get_acl_service)
):
    """List all ACLs"""
    try:
        acls = await acl_service.list_acls()
        return ACLListResponse(acls=acls, count=len(acls))
    except ACLError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/{name}",
    response_model=ACLResponse,
    summary="Get ACL",
    description="Get a specific ACL by name"
)
async def get_acl(
    name: str,
    current_user: AuthenticatedUser = Depends(require_read),
    acl_service: ACLService = Depends(get_acl_service)
):
    """Get a specific ACL"""
    try:
        acl = await acl_service.get_acl(name)
        if not acl:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ACL '{name}' not found"
            )
        return acl
    except ACLError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# Create / Update / Delete Operations
# =============================================================================

@router.post(
    "",
    response_model=ACLResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create ACL",
    description="Create a new Access Control List"
)
async def create_acl(
    acl: ACLCreate,
    current_user: AuthenticatedUser = Depends(require_write),
    acl_service: ACLService = Depends(get_acl_service),
    db: AsyncSession = Depends(get_db)
):
    """Create a new ACL"""
    try:
        # Validate first
        is_valid, message = await acl_service.validate_acl(acl)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid ACL: {message}"
            )
        
        result = await acl_service.create_acl(acl)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="CREATE",
            resource_type="acl",
            resource_id=acl.name,
            details=f"Created ACL with {len(acl.entries)} entries"
        )
        
        return result
        
    except ACLError as e:
        if "already exists" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put(
    "/{name}",
    response_model=ACLResponse,
    summary="Update ACL",
    description="Update an existing Access Control List"
)
async def update_acl(
    name: str,
    update: ACLUpdate,
    current_user: AuthenticatedUser = Depends(require_write),
    acl_service: ACLService = Depends(get_acl_service),
    db: AsyncSession = Depends(get_db)
):
    """Update an existing ACL"""
    try:
        # Validate entries if provided
        if update.entries is not None:
            temp_acl = ACLCreate(name=name, entries=update.entries)
            is_valid, message = await acl_service.validate_acl(temp_acl)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid ACL entries: {message}"
                )
        
        result = await acl_service.update_acl(name, update)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="UPDATE",
            resource_type="acl",
            resource_id=name,
            details=f"Updated ACL"
        )
        
        return result
        
    except ACLError as e:
        if "not found" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete(
    "/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete ACL",
    description="Delete an Access Control List"
)
async def delete_acl(
    name: str,
    current_user: AuthenticatedUser = Depends(require_admin),
    acl_service: ACLService = Depends(get_acl_service),
    db: AsyncSession = Depends(get_db)
):
    """Delete an ACL"""
    try:
        await acl_service.delete_acl(name)
        
        await log_audit(
            db=db,
            user=current_user.identifier,
            action="DELETE",
            resource_type="acl",
            resource_id=name,
            details=f"Deleted ACL"
        )
        
    except ACLError as e:
        if "not found" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# =============================================================================
# Administrative Operations
# =============================================================================

@router.post(
    "/ensure-included",
    summary="Ensure ACL file is included",
    description="Ensure the ACL file is included in named.conf"
)
async def ensure_included(
    current_user: AuthenticatedUser = Depends(require_admin),
    acl_service: ACLService = Depends(get_acl_service)
):
    """Ensure the ACL file is included in named.conf"""
    try:
        result = await acl_service.ensure_included()
        return {"included": result, "file": str(acl_service.acl_file)}
    except ACLError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get(
    "/status/included",
    summary="Check if ACL file is included",
    description="Check if the ACL file is included in named.conf"
)
async def check_included(
    current_user: AuthenticatedUser = Depends(require_read),
    acl_service: ACLService = Depends(get_acl_service)
):
    """Check if ACL file is included in named.conf"""
    try:
        included = await acl_service.check_included()
        return {
            "included": included,
            "file": str(acl_service.acl_file),
            "named_conf": str(acl_service.named_conf)
        }
    except ACLError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
