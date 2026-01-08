"""
Statistics API Router
BIND9 statistics channel integration
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import AuthenticatedUser, require_stats
from ..models.server import (
    ServerStatistics, QueryStats, ResolverStats, CacheStats,
    MemoryStats, TrafficStats, ZoneStats, SocketStats
)
from ..services.stats import StatisticsService, StatisticsError


router = APIRouter(prefix="/stats", tags=["Statistics"])


def get_stats_service() -> StatisticsService:
    return StatisticsService()


# =============================================================================
# Full Statistics
# =============================================================================

@router.get(
    "",
    response_model=ServerStatistics,
    summary="Get all statistics",
    description="Get complete server statistics from statistics channel"
)
async def get_all_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get complete server statistics"""
    try:
        return await stats_service.get_full_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Query Statistics
# =============================================================================

@router.get(
    "/queries",
    response_model=QueryStats,
    summary="Get query statistics",
    description="Get statistics by query type"
)
async def get_query_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get query type statistics"""
    try:
        return await stats_service.get_query_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Resolver Statistics
# =============================================================================

@router.get(
    "/resolver",
    response_model=ResolverStats,
    summary="Get resolver statistics",
    description="Get resolver/recursion statistics"
)
async def get_resolver_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get resolver statistics"""
    try:
        return await stats_service.get_resolver_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Cache Statistics
# =============================================================================

@router.get(
    "/cache",
    response_model=CacheStats,
    summary="Get cache statistics",
    description="Get cache hit/miss statistics"
)
async def get_cache_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get cache statistics"""
    try:
        return await stats_service.get_cache_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Memory Statistics
# =============================================================================

@router.get(
    "/memory",
    response_model=MemoryStats,
    summary="Get memory statistics",
    description="Get memory usage statistics"
)
async def get_memory_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get memory statistics"""
    try:
        return await stats_service.get_memory_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Traffic Statistics
# =============================================================================

@router.get(
    "/traffic",
    response_model=TrafficStats,
    summary="Get traffic statistics",
    description="Get network traffic statistics"
)
async def get_traffic_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get traffic statistics"""
    try:
        return await stats_service.get_traffic_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Zone Statistics
# =============================================================================

@router.get(
    "/zones",
    response_model=List[ZoneStats],
    summary="Get zone statistics",
    description="Get per-zone statistics"
)
async def get_zone_statistics(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get per-zone statistics"""
    try:
        return await stats_service.get_zone_stats()
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )


# =============================================================================
# Uptime
# =============================================================================

@router.get(
    "/uptime",
    summary="Get server uptime",
    description="Get server uptime in seconds"
)
async def get_uptime(
    current_user: AuthenticatedUser = Depends(require_stats),
    stats_service: StatisticsService = Depends(get_stats_service),
):
    """Get server uptime"""
    try:
        uptime = await stats_service.get_uptime()
        server_time = await stats_service.get_server_time()
        
        return {
            "uptime_seconds": uptime,
            "server_time": server_time.isoformat() if server_time else None,
        }
    except StatisticsError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )

