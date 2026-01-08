"""
Zone Management Models for BIND9 REST API
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class ZoneType(str, Enum):
    """BIND9 zone types"""
    MASTER = "master"           # Primary authoritative zone
    PRIMARY = "primary"         # Alias for master (BIND 9.14+)
    SLAVE = "slave"             # Secondary authoritative zone
    SECONDARY = "secondary"     # Alias for slave (BIND 9.14+)
    STUB = "stub"               # Stub zone (NS records only)
    FORWARD = "forward"         # Forward zone
    STATIC_STUB = "static-stub" # Static stub zone
    REDIRECT = "redirect"       # Redirect zone
    DELEGATION_ONLY = "delegation-only"  # Delegation-only zone
    IN_VIEW = "in-view"         # Reference to zone in another view


class ZoneClass(str, Enum):
    """Zone classes"""
    IN = "IN"       # Internet
    CH = "CH"       # Chaos
    HS = "HS"       # Hesiod


class UpdatePolicy(str, Enum):
    """Dynamic update policy types"""
    GRANT = "grant"
    DENY = "deny"


class ZoneStatus(str, Enum):
    """Zone operational status"""
    ACTIVE = "active"
    LOADING = "loading"
    EXPIRED = "expired"
    REFRESH = "refresh"
    FROZEN = "frozen"
    UNKNOWN = "unknown"


# =============================================================================
# Zone Configuration Models
# =============================================================================

class ZoneKey(BaseModel):
    """TSIG key reference for zone transfers"""
    name: str
    algorithm: str = "hmac-sha256"
    secret: Optional[str] = None


class ZoneServer(BaseModel):
    """Server configuration for masters/also-notify"""
    address: str = Field(..., description="IP address")
    port: int = Field(default=53, ge=1, le=65535)
    key: Optional[str] = Field(default=None, description="TSIG key name")


class UpdatePolicyRule(BaseModel):
    """Dynamic update policy rule"""
    permission: UpdatePolicy
    identity: str = Field(..., description="Identity (key name, wildcard, etc.)")
    matchtype: str = Field(default="name", description="Match type (name, subdomain, wildcard, self)")
    name: str = Field(default="*", description="Name to match")
    types: List[str] = Field(default=["ANY"], description="Record types to allow")


class ZoneOptions(BaseModel):
    """Zone-specific options"""
    # Transfer options
    allow_transfer: List[str] = Field(default=["none"], description="ACL for zone transfers")
    also_notify: List[ZoneServer] = Field(default=[], description="Additional servers to notify")
    masters: List[ZoneServer] = Field(default=[], description="Master servers (for slave zones)")
    
    # Update options
    allow_update: List[str] = Field(default=["none"], description="ACL for dynamic updates")
    update_policy: List[UpdatePolicyRule] = Field(default=[], description="Update policy rules")
    
    # Query options
    allow_query: List[str] = Field(default=["any"], description="ACL for queries")
    
    # DNSSEC options
    dnssec_policy: Optional[str] = Field(default=None, description="DNSSEC policy name")
    inline_signing: bool = Field(default=False, description="Enable inline signing")
    auto_dnssec: Optional[str] = Field(default=None, description="Auto DNSSEC mode (maintain/off)")
    
    # Other options
    notify: bool = Field(default=True, description="Send NOTIFY on zone changes")
    notify_source: Optional[str] = Field(default=None, description="Source address for NOTIFY")
    check_names: str = Field(default="warn", description="Name checking (fail/warn/ignore)")
    max_zone_ttl: Optional[int] = Field(default=None, description="Maximum TTL for zone")
    max_records: Optional[int] = Field(default=None, description="Maximum records in zone")
    
    # Forward zone options
    forward: Optional[str] = Field(default=None, description="Forward mode (first/only)")
    forwarders: List[str] = Field(default=[], description="Forwarder addresses")


# =============================================================================
# Zone CRUD Models
# =============================================================================

class ZoneBase(BaseModel):
    """Base zone model"""
    name: str = Field(..., description="Zone name (e.g., example.com)")
    zone_type: ZoneType = Field(..., description="Zone type")
    zone_class: ZoneClass = Field(default=ZoneClass.IN, description="Zone class")
    
    @field_validator("name")
    @classmethod
    def validate_zone_name(cls, v):
        # Remove trailing dot if present for consistency
        v = v.rstrip(".")
        # Basic validation
        if not v or len(v) > 253:
            raise ValueError("Invalid zone name length")
        return v


class ZoneCreate(ZoneBase):
    """Create a new zone"""
    file: Optional[str] = Field(default=None, description="Zone file path (auto-generated if not specified)")
    options: ZoneOptions = Field(default_factory=ZoneOptions, description="Zone options")
    
    # Initial SOA parameters (for master zones)
    soa_mname: Optional[str] = Field(default=None, description="Primary nameserver for SOA")
    soa_rname: Optional[str] = Field(default=None, description="Responsible person email for SOA")
    soa_serial: Optional[int] = Field(default=None, description="Initial serial (auto if not specified)")
    soa_refresh: int = Field(default=86400, description="SOA refresh interval")
    soa_retry: int = Field(default=7200, description="SOA retry interval")
    soa_expire: int = Field(default=3600000, description="SOA expire time")
    soa_minimum: int = Field(default=3600, description="SOA minimum/negative TTL")
    default_ttl: int = Field(default=3600, description="Default TTL for records")
    
    # Initial NS records
    nameservers: List[str] = Field(default=[], description="Initial NS records")
    
    # Glue records for in-zone nameservers (required for validation to pass)
    ns_addresses: Dict[str, str] = Field(default={}, description="Nameserver IP addresses for glue records (e.g., {'ns1.example.com': '10.0.0.1'})")


class ZoneUpdate(BaseModel):
    """Update zone configuration"""
    options: Optional[ZoneOptions] = None
    file: Optional[str] = None


class ZoneResponse(ZoneBase):
    """Zone response with full details"""
    file: Optional[str] = None
    options: ZoneOptions = Field(default_factory=ZoneOptions)
    status: ZoneStatus = ZoneStatus.UNKNOWN
    serial: Optional[int] = None
    record_count: Optional[int] = None
    dnssec_enabled: bool = False
    loaded: bool = False
    expires: Optional[datetime] = None
    refresh: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ZoneListResponse(BaseModel):
    """List of zones"""
    zones: List[ZoneResponse]
    total: int


class ZoneStatus_Detail(BaseModel):
    """Detailed zone status from rndc zonestatus"""
    name: str
    type: str
    serial: Optional[int] = None
    loaded: bool = False
    expires: Optional[str] = None
    refresh: Optional[str] = None
    up_to_date: bool = True
    dynamic: bool = False
    frozen: bool = False
    secure: bool = False
    inline_signing: bool = False
    key_maintenance: bool = False
    next_refresh: Optional[str] = None
    next_key_event: Optional[str] = None
    raw_output: Optional[str] = None


# =============================================================================
# Zone Transfer Models
# =============================================================================

class ZoneTransferRequest(BaseModel):
    """Request zone transfer (AXFR/IXFR)"""
    master: str = Field(..., description="Master server address")
    port: int = Field(default=53, description="Master server port")
    key: Optional[str] = Field(default=None, description="TSIG key name")
    transfer_type: str = Field(default="axfr", description="Transfer type (axfr/ixfr)")


class ZoneExport(BaseModel):
    """Exported zone data"""
    name: str
    zone_type: ZoneType
    serial: int
    records: List[dict]
    zone_file_content: Optional[str] = None


class ZoneImport(BaseModel):
    """Import zone data"""
    name: str
    zone_type: ZoneType = ZoneType.MASTER
    records: Optional[List[dict]] = None
    zone_file_content: Optional[str] = None
    replace_existing: bool = False


# =============================================================================
# Catalog Zone Models (BIND 9.11+)
# =============================================================================

class CatalogZone(BaseModel):
    """Catalog zone configuration"""
    name: str = Field(..., description="Catalog zone name")
    default_masters: List[ZoneServer] = Field(default=[], description="Default master servers")
    in_memory: bool = Field(default=False, description="Store in memory only")
    zone_directory: Optional[str] = Field(default=None, description="Zone file directory")
    min_update_interval: int = Field(default=5, description="Minimum update interval (seconds)")


class CatalogZoneMember(BaseModel):
    """Member zone in a catalog zone"""
    zone_name: str
    group: Optional[str] = None
    masters: Optional[List[ZoneServer]] = None


# =============================================================================
# Response Policy Zone (RPZ) Models
# =============================================================================

class RPZAction(str, Enum):
    """RPZ actions"""
    NXDOMAIN = "nxdomain"       # Return NXDOMAIN
    NODATA = "nodata"          # Return NODATA
    PASSTHRU = "passthru"      # Allow query through
    DROP = "drop"              # Drop the query
    DISABLED = "disabled"      # Disable policy
    TCP_ONLY = "tcp-only"      # Force TCP
    LOCAL = "local"            # Return local data


class RPZTrigger(str, Enum):
    """RPZ trigger types"""
    QNAME = "qname"            # Query name
    CLIENT_IP = "client-ip"    # Client IP address
    IP = "ip"                  # Response IP address
    NSDNAME = "nsdname"        # Nameserver name
    NSIP = "nsip"              # Nameserver IP


class RPZRule(BaseModel):
    """RPZ rule"""
    trigger: RPZTrigger
    trigger_value: str = Field(..., description="Domain, IP, or CIDR")
    action: RPZAction
    action_data: Optional[str] = Field(default=None, description="Data for local action")


class RPZZone(BaseModel):
    """Response Policy Zone configuration"""
    name: str = Field(..., description="RPZ zone name")
    policy: RPZAction = Field(default=RPZAction.NXDOMAIN, description="Default policy")
    recursive_only: bool = Field(default=True, description="Apply to recursive queries only")
    max_policy_ttl: int = Field(default=86400, description="Maximum policy TTL")
    break_dnssec: bool = Field(default=True, description="Break DNSSEC validation")
    min_update_interval: int = Field(default=0, description="Minimum update interval")
    min_ns_dots: int = Field(default=1, description="Minimum dots in NS names")

