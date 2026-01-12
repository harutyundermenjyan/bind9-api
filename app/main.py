"""
BIND9 REST API - Main Application
Complete REST API for BIND9 DNS Server Management
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import make_asgi_app

from .config import settings
from .routers import (
    zones_router,
    records_router,
    server_router,
    stats_router,
    dnssec_router,
    auth_router,
    health_router,
    acls_router,
)


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format=settings.log_format,
)
logger = logging.getLogger(__name__)


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    logger.info("Starting BIND9 REST API...")
    logger.info(f"Auth enabled: {settings.auth_enabled}")
    logger.info(f"Database enabled: {settings.database_enabled}")
    logger.info(f"Static API key configured: {bool(settings.auth_static_api_key)}")
    
    # Initialize database if enabled
    if settings.database_enabled:
        from .database import init_db
        await init_db()
        logger.info("Database initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down BIND9 REST API...")


# Create FastAPI application
app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version=settings.api_version,
    docs_url=None,  # Custom docs
    redoc_url=None,  # Custom redoc
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)


# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


# Mount Prometheus metrics
if settings.metrics_enabled:
    metrics_app = make_asgi_app()
    app.mount(settings.metrics_path, metrics_app)


# Include routers
app.include_router(health_router)
app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(zones_router, prefix=settings.api_prefix)
app.include_router(records_router, prefix=settings.api_prefix)
app.include_router(server_router, prefix=settings.api_prefix)
app.include_router(stats_router, prefix=settings.api_prefix)
app.include_router(dnssec_router, prefix=settings.api_prefix)
app.include_router(acls_router)


# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=settings.api_title,
        version=settings.api_version,
        description=settings.api_description,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
        "apiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": settings.auth_api_key_header,
        },
    }
    
    # Apply security globally
    openapi_schema["security"] = [
        {"bearerAuth": []},
        {"apiKeyAuth": []},
    ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Custom documentation endpoints
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=f"{settings.api_prefix}/openapi.json",
        title=f"{settings.api_title} - Swagger UI",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url=f"{settings.api_prefix}/openapi.json",
        title=f"{settings.api_title} - ReDoc",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": f"{settings.api_prefix}/openapi.json",
        "health": "/health",
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": "Internal server error",
            "detail": str(exc) if settings.debug else None,
        },
    )


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.workers,
    )

