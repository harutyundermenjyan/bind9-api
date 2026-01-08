"""
Server Control and Statistics Models for BIND9 REST API
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


# =============================================================================
# Server Control Models (RNDC Commands)
# =============================================================================

class RNDCCommand(str, Enum):
    """All available RNDC commands"""
    # Server Status
    STATUS = "status"
    VERSION = "version"
    
    # Configuration
    RELOAD = "reload"
    RECONFIG = "reconfig"
    
    # Cache Management
    FLUSH = "flush"
    FLUSHNAME = "flushname"
    FLUSHTREE = "flushtree"
    
    # Zone Management
    FREEZE = "freeze"
    THAW = "thaw"
    SYNC = "sync"
    NOTIFY = "notify"
    RETRANSFER = "retransfer"
    REFRESH = "refresh"
    ZONESTATUS = "zonestatus"
    ADDZONE = "addzone"
    DELZONE = "delzone"
    MODZONE = "modzone"
    SHOWZONE = "showzone"
    
    # DNSSEC
    SIGN = "sign"
    LOADKEYS = "loadkeys"
    SIGNING = "signing"
    DNSSEC = "dnssec"
    MANAGED_KEYS = "managed-keys"
    
    # Trust Anchors
    NTA = "nta"
    SECROOTS = "secroots"
    
    # Debugging
    DUMPDB = "dumpdb"
    TRACE = "trace"
    NOTRACE = "notrace"
    QUERYLOG = "querylog"
    RECURSING = "recursing"
    
    # Validation
    VALIDATION = "validation"
    
    # Timeouts
    TCP_TIMEOUTS = "tcp-timeouts"
    
    # Stale Cache
    SERVE_STALE = "serve-stale"
    
    # Shutdown
    STOP = "stop"
    HALT = "halt"


class ServerCommand(BaseModel):
    """Server command request"""
    command: RNDCCommand
    args: List[str] = Field(default=[], description="Command arguments")
    zone: Optional[str] = Field(default=None, description="Zone name (for zone-specific commands)")
    view: Optional[str] = Field(default=None, description="View name")


class ServerCommandResult(BaseModel):
    """Server command result"""
    command: str
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# Server Status Models
# =============================================================================

class ServerInfo(BaseModel):
    """Basic server information"""
    version: str
    running: bool
    uptime: Optional[float] = None
    boot_time: Optional[datetime] = None
    config_time: Optional[datetime] = None
    current_serial: Optional[int] = None
    named_pid: Optional[int] = None


class ServerStatus(BaseModel):
    """Comprehensive server status"""
    info: ServerInfo
    zones_loaded: int = 0
    zones_total: int = 0
    recursive_clients: int = 0
    tcp_clients: int = 0
    requests_received: int = 0
    responses_sent: int = 0
    queries_in_progress: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    raw_status: Optional[str] = None


# =============================================================================
# Cache Models
# =============================================================================

class CacheFlushRequest(BaseModel):
    """Request to flush cache"""
    name: Optional[str] = Field(default=None, description="Name to flush (all if not specified)")
    tree: bool = Field(default=False, description="Flush entire tree under name")
    view: Optional[str] = Field(default=None, description="View name")


class CacheStats(BaseModel):
    """Cache statistics"""
    cache_hits: int = 0
    cache_misses: int = 0
    query_hits: int = 0
    query_misses: int = 0
    delete_lru: int = 0
    delete_ttl: int = 0
    cache_nodes: int = 0
    cache_buckets: int = 0
    tree_memory: int = 0
    heap_memory: int = 0


# =============================================================================
# Statistics Models (Statistics Channel)
# =============================================================================

class QueryStats(BaseModel):
    """Query statistics by type"""
    A: int = 0
    AAAA: int = 0
    CNAME: int = 0
    MX: int = 0
    NS: int = 0
    PTR: int = 0
    SOA: int = 0
    TXT: int = 0
    SRV: int = 0
    CAA: int = 0
    DNSKEY: int = 0
    DS: int = 0
    HTTPS: int = 0
    ANY: int = 0
    OTHER: int = 0


class OpcodeStats(BaseModel):
    """Statistics by opcode"""
    QUERY: int = 0
    IQUERY: int = 0
    STATUS: int = 0
    NOTIFY: int = 0
    UPDATE: int = 0


class RcodeStats(BaseModel):
    """Statistics by response code"""
    NOERROR: int = 0
    FORMERR: int = 0
    SERVFAIL: int = 0
    NXDOMAIN: int = 0
    NOTIMP: int = 0
    REFUSED: int = 0
    YXDOMAIN: int = 0
    YXRRSET: int = 0
    NXRRSET: int = 0
    NOTAUTH: int = 0
    NOTZONE: int = 0


class ZoneStats(BaseModel):
    """Zone-specific statistics"""
    zone_name: str
    serial: int
    notify_sent: int = 0
    notify_received: int = 0
    axfr_sent: int = 0
    axfr_received: int = 0
    ixfr_sent: int = 0
    ixfr_received: int = 0
    updates_received: int = 0
    updates_rejected: int = 0
    updates_completed: int = 0


class ResolverStats(BaseModel):
    """Resolver statistics"""
    queries_sent: int = 0
    queries_in_progress: int = 0
    queries_timeout: int = 0
    lame_delegations: int = 0
    nxdomain: int = 0
    servfail: int = 0
    formerr: int = 0
    other_errors: int = 0
    edns0_failures: int = 0
    truncated: int = 0
    retries: int = 0
    gluefetch: int = 0
    dns64: int = 0
    rpz_rewrites: int = 0


class SocketStats(BaseModel):
    """Socket statistics"""
    udp4_open: int = 0
    udp6_open: int = 0
    tcp4_open: int = 0
    tcp6_open: int = 0
    raw_open: int = 0
    udp4_active: int = 0
    udp6_active: int = 0
    tcp4_active: int = 0
    tcp6_active: int = 0
    raw_active: int = 0
    udp4_bindfail: int = 0
    udp6_bindfail: int = 0
    tcp4_connectfail: int = 0
    tcp6_connectfail: int = 0


class MemoryStats(BaseModel):
    """Memory usage statistics"""
    total_use: int = 0
    in_use: int = 0
    block_size: int = 0
    context_size: int = 0
    lost: int = 0
    contexts: Dict[str, int] = {}


class TrafficStats(BaseModel):
    """Network traffic statistics"""
    dns_udp_requests_received_ipv4: int = 0
    dns_udp_requests_received_ipv6: int = 0
    dns_udp_responses_sent_ipv4: int = 0
    dns_udp_responses_sent_ipv6: int = 0
    dns_tcp_requests_received_ipv4: int = 0
    dns_tcp_requests_received_ipv6: int = 0
    dns_tcp_responses_sent_ipv4: int = 0
    dns_tcp_responses_sent_ipv6: int = 0
    queries_resulted_in_successful_answer: int = 0
    queries_resulted_in_authoritative_answer: int = 0
    queries_resulted_in_non_authoritative_answer: int = 0
    queries_resulted_in_referral_answer: int = 0
    queries_resulted_in_nxrrset: int = 0
    queries_resulted_in_servfail: int = 0
    queries_resulted_in_nxdomain: int = 0
    queries_caused_recursion: int = 0
    duplicate_queries_received: int = 0
    queries_dropped: int = 0


class ServerStatistics(BaseModel):
    """Complete server statistics"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    boot_time: Optional[datetime] = None
    config_time: Optional[datetime] = None
    current_time: Optional[datetime] = None
    
    # Core stats
    queries: QueryStats = Field(default_factory=QueryStats)
    opcodes: OpcodeStats = Field(default_factory=OpcodeStats)
    rcodes: RcodeStats = Field(default_factory=RcodeStats)
    
    # Detailed stats
    resolver: ResolverStats = Field(default_factory=ResolverStats)
    cache: CacheStats = Field(default_factory=CacheStats)
    sockets: SocketStats = Field(default_factory=SocketStats)
    memory: MemoryStats = Field(default_factory=MemoryStats)
    traffic: TrafficStats = Field(default_factory=TrafficStats)
    
    # Zone stats
    zones: List[ZoneStats] = []
    
    # Raw data
    raw_json: Optional[Dict[str, Any]] = None
    raw_xml: Optional[str] = None


# =============================================================================
# View Models
# =============================================================================

class View(BaseModel):
    """DNS View configuration"""
    name: str
    match_clients: List[str] = Field(default=["any"], description="ACL for client matching")
    match_destinations: List[str] = Field(default=["any"], description="ACL for destination matching")
    recursion: bool = True
    allow_query: List[str] = Field(default=["any"])
    allow_recursion: List[str] = Field(default=["any"])
    allow_query_cache: List[str] = Field(default=["any"])


class ViewResponse(View):
    """View with additional details"""
    zones: List[str] = []
    zone_count: int = 0


# =============================================================================
# ACL Models
# =============================================================================

class ACLEntry(BaseModel):
    """ACL entry"""
    value: str = Field(..., description="IP, CIDR, key name, or nested ACL")
    negated: bool = Field(default=False, description="Negate this entry")


class ACL(BaseModel):
    """Access Control List"""
    name: str
    entries: List[ACLEntry]


class ACLResponse(ACL):
    """ACL with usage information"""
    used_by: List[str] = []  # List of zones/views using this ACL


# =============================================================================
# Logging Models
# =============================================================================

class LogCategory(str, Enum):
    """BIND9 log categories"""
    CLIENT = "client"
    CONFIG = "config"
    DATABASE = "database"
    DEFAULT = "default"
    DELEGATION_ONLY = "delegation-only"
    DISPATCH = "dispatch"
    DNSSEC = "dnssec"
    DNSTAP = "dnstap"
    EDNS_DISABLED = "edns-disabled"
    GENERAL = "general"
    LAME_SERVERS = "lame-servers"
    NETWORK = "network"
    NOTIFY = "notify"
    QUERIES = "queries"
    QUERY_ERRORS = "query-errors"
    RATE_LIMIT = "rate-limit"
    RESOLVER = "resolver"
    RPZ = "rpz"
    SECURITY = "security"
    SPILL = "spill"
    TRUST_ANCHOR_TELEMETRY = "trust-anchor-telemetry"
    UNMATCHED = "unmatched"
    UPDATE = "update"
    UPDATE_SECURITY = "update-security"
    XFER_IN = "xfer-in"
    XFER_OUT = "xfer-out"
    ZONELOAD = "zoneload"


class LogSeverity(str, Enum):
    """Log severity levels"""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"
    DYNAMIC = "dynamic"


class QueryLogEntry(BaseModel):
    """Query log entry"""
    timestamp: datetime
    client_ip: str
    client_port: int
    query_name: str
    query_type: str
    query_class: str
    flags: Optional[str] = None
    view: Optional[str] = None
    response_code: Optional[str] = None
    response_time_ms: Optional[float] = None


# =============================================================================
# Zone Status Detail Model (for RNDC zonestatus)
# =============================================================================

class ZoneStatus_Detail(BaseModel):
    """Detailed zone status from rndc zonestatus"""
    name: str
    type: str = Field(default="master", description="Zone type")
    serial: Optional[int] = None
    loaded: bool = True
    expires: Optional[datetime] = None
    refresh: Optional[datetime] = None
    files: List[str] = Field(default=[], description="Zone files")
    
    # Dynamic update info
    dynamic: bool = False
    frozen: bool = False
    
    # Transfer info
    next_refresh: Optional[datetime] = None
    transfer_source: Optional[str] = None
    
    # DNSSEC info
    secure: bool = False
    inline_signing: bool = False
    key_maintenance: bool = False
    
    # Statistics
    nodes: int = 0
    
    # Raw output
    raw_output: Optional[str] = None

