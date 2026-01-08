"""
Configuration management for BIND9 REST API
Supports environment variables and .env files
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List
from functools import lru_cache
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Settings
    api_title: str = "BIND9 REST API"
    api_description: str = "Complete REST API for BIND9 DNS Server Management"
    api_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    debug: bool = False
    
    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    
    # BIND9 Configuration
    bind9_config_path: str = "/etc/bind/named.conf"
    bind9_zones_path: str = "/etc/bind/zones"
    bind9_keys_path: str = "/etc/bind/keys"
    bind9_rndc_path: str = "/usr/sbin/rndc"
    bind9_rndc_key: str = "/etc/bind/rndc.key"
    bind9_nsupdate_path: str = "/usr/bin/nsupdate"
    bind9_named_checkzone: str = "/usr/sbin/named-checkzone"
    bind9_named_checkconf: str = "/usr/sbin/named-checkconf"
    bind9_dnssec_keygen: str = "/usr/sbin/dnssec-keygen"
    bind9_dnssec_signzone: str = "/usr/sbin/dnssec-signzone"
    
    # Statistics Channel
    bind9_stats_url: str = "http://127.0.0.1:8053"
    bind9_stats_format: str = "json"  # json or xml
    
    # Authentication
    auth_enabled: bool = True
    auth_algorithm: str = "HS256"
    auth_secret_key: str = Field(default="change-me-in-production-use-openssl-rand-hex-32")
    auth_access_token_expire_minutes: int = 60
    auth_api_key_header: str = "X-API-Key"
    
    # Static API Key (no database needed) - set via environment
    auth_static_api_key: Optional[str] = Field(default=None, description="Static API key for authentication without database")
    auth_static_api_key_scopes: str = Field(default="read,write,admin,dnssec,stats", description="Comma-separated scopes for static API key")
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_period: int = 60  # seconds
    
    # Database (for audit logs, API keys) - optional
    database_enabled: bool = Field(default=False, description="Enable database for audit logs and dynamic API keys")
    database_url: str = "sqlite+aiosqlite:///./bind9_api.db"
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    audit_log_enabled: bool = True
    
    # CORS
    cors_origins: List[str] = ["*"]
    cors_allow_credentials: bool = True
    cors_allow_methods: List[str] = ["*"]
    cors_allow_headers: List[str] = ["*"]
    
    # Timeouts
    rndc_timeout: int = 30
    nsupdate_timeout: int = 30
    zone_transfer_timeout: int = 300
    
    # TSIG Key for nsupdate (optional)
    # Option 1: Use key file (recommended)
    tsig_key_file: Optional[str] = Field(default=None, description="Path to TSIG key file (e.g., /etc/bind/keys/ddns-key.key)")
    # Option 2: Inline key configuration
    tsig_key_name: Optional[str] = None
    tsig_key_secret: Optional[str] = None
    tsig_key_algorithm: str = "hmac-sha256"
    
    # Prometheus Metrics
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        env_prefix = "BIND9_API_"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Convenience function
settings = get_settings()

