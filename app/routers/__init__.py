"""
API Routers for BIND9 REST API
"""

from .zones import router as zones_router
from .records import router as records_router
from .server import router as server_router
from .stats import router as stats_router
from .dnssec import router as dnssec_router
from .auth import router as auth_router
from .health import router as health_router
from .acls import router as acls_router

__all__ = [
    "zones_router",
    "records_router", 
    "server_router",
    "stats_router",
    "dnssec_router",
    "auth_router",
    "health_router",
    "acls_router",
]

