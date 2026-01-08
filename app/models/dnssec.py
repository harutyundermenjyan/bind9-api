"""
DNSSEC Management Models for BIND9 REST API
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


class DNSSECAlgorithm(int, Enum):
    """DNSSEC Algorithm numbers (RFC 8624)"""
    DELETE = 0
    RSAMD5 = 1              # Deprecated
    DH = 2                  # Deprecated
    DSA = 3                 # Deprecated
    RSASHA1 = 5             # Not recommended
    DSA_NSEC3_SHA1 = 6      # Deprecated
    RSASHA1_NSEC3_SHA1 = 7  # Not recommended
    RSASHA256 = 8           # Recommended
    RSASHA512 = 10          # Recommended
    ECC_GOST = 12           # Not recommended
    ECDSAP256SHA256 = 13    # Recommended
    ECDSAP384SHA384 = 14    # Recommended
    ED25519 = 15            # Recommended
    ED448 = 16              # Recommended


class DNSSECDigestType(int, Enum):
    """DNSSEC Digest types"""
    SHA1 = 1        # Not recommended
    SHA256 = 2      # Recommended
    GOST = 3        # Not recommended
    SHA384 = 4      # Recommended


class KeyType(str, Enum):
    """DNSSEC key types"""
    KSK = "KSK"     # Key Signing Key
    ZSK = "ZSK"     # Zone Signing Key
    CSK = "CSK"     # Combined Signing Key


class KeyState(str, Enum):
    """DNSSEC key states (RFC 7583)"""
    HIDDEN = "hidden"
    RUMOURED = "rumoured"
    OMNIPRESENT = "omnipresent"
    UNRETENTIVE = "unretentive"
    GENERATED = "generated"
    PUBLISHED = "published"
    READY = "ready"
    ACTIVE = "active"
    RETIRED = "retired"
    REMOVED = "removed"


# =============================================================================
# Key Models
# =============================================================================

class DNSSECKey(BaseModel):
    """DNSSEC key information"""
    key_tag: int = Field(..., description="Key tag (ID)")
    algorithm: DNSSECAlgorithm
    key_type: KeyType
    bits: int = Field(..., description="Key size in bits")
    state: KeyState
    
    # Timing information
    created: Optional[datetime] = None
    publish: Optional[datetime] = None
    activate: Optional[datetime] = None
    inactive: Optional[datetime] = None
    delete: Optional[datetime] = None
    
    # Files
    private_key_file: Optional[str] = None
    public_key_file: Optional[str] = None
    
    # Additional info
    flags: int = Field(..., description="DNSKEY flags (256=ZSK, 257=KSK)")
    protocol: int = Field(default=3, description="Protocol (always 3)")
    public_key: Optional[str] = Field(default=None, description="Base64-encoded public key")


class DNSSECKeyCreate(BaseModel):
    """Create a new DNSSEC key"""
    zone: str = Field(..., description="Zone name")
    key_type: KeyType = Field(..., description="Key type (KSK, ZSK, CSK)")
    algorithm: DNSSECAlgorithm = Field(
        default=DNSSECAlgorithm.ECDSAP256SHA256,
        description="Algorithm"
    )
    bits: Optional[int] = Field(
        default=None, 
        description="Key size (auto-selected based on algorithm if not specified)"
    )
    
    # Timing
    publish: Optional[datetime] = Field(default=None, description="Publish time")
    activate: Optional[datetime] = Field(default=None, description="Activation time")
    inactive: Optional[datetime] = Field(default=None, description="Inactivation time")
    delete: Optional[datetime] = Field(default=None, description="Deletion time")
    
    # Options
    ttl: int = Field(default=3600, description="DNSKEY record TTL")
    ksk: bool = Field(default=False, description="Generate as KSK (sets SEP flag)")
    successor: Optional[int] = Field(default=None, description="Key tag of predecessor (for rollover)")


class DNSSECKeyResponse(DNSSECKey):
    """DNSSEC key response with zone info"""
    zone: str
    ds_records: List[str] = Field(default=[], description="Generated DS records")


# =============================================================================
# Key Rollover Models
# =============================================================================

class RolloverType(str, Enum):
    """Key rollover types"""
    DOUBLE_SIGNATURE = "double-signature"   # RFC 7583 Double-Signature
    PRE_PUBLICATION = "pre-publication"     # RFC 7583 Pre-Publication
    DOUBLE_DS = "double-ds"                 # RFC 7583 Double-DS
    DOUBLE_RR = "double-rr"                 # Double-RRSET (for ZSK)


class KeyRolloverRequest(BaseModel):
    """Request key rollover"""
    zone: str
    key_type: KeyType
    rollover_type: RolloverType = Field(
        default=RolloverType.PRE_PUBLICATION,
        description="Rollover method"
    )
    new_algorithm: Optional[DNSSECAlgorithm] = Field(
        default=None,
        description="New algorithm (for algorithm rollover)"
    )
    new_bits: Optional[int] = Field(
        default=None,
        description="New key size"
    )
    timing: Optional[dict] = Field(
        default=None,
        description="Custom timing parameters"
    )


class KeyRolloverStatus(BaseModel):
    """Key rollover status"""
    zone: str
    in_progress: bool
    rollover_type: Optional[RolloverType] = None
    old_key_tag: Optional[int] = None
    new_key_tag: Optional[int] = None
    state: Optional[str] = None
    next_action: Optional[str] = None
    next_action_time: Optional[datetime] = None
    completion_estimate: Optional[datetime] = None


# =============================================================================
# Signing Models
# =============================================================================

class SigningRequest(BaseModel):
    """Request zone signing"""
    zone: str
    inline_signing: bool = Field(
        default=True,
        description="Use inline signing (recommended)"
    )
    nsec3: bool = Field(
        default=True,
        description="Use NSEC3 instead of NSEC"
    )
    nsec3_iterations: int = Field(
        default=0,
        description="NSEC3 iterations (0 recommended per RFC 9276)"
    )
    nsec3_salt_length: int = Field(
        default=0,
        description="NSEC3 salt length in bytes (0 recommended per RFC 9276)"
    )
    nsec3_optout: bool = Field(
        default=False,
        description="Enable NSEC3 opt-out"
    )
    
    # Key options
    generate_keys: bool = Field(
        default=True,
        description="Auto-generate keys if none exist"
    )
    ksk_algorithm: DNSSECAlgorithm = Field(
        default=DNSSECAlgorithm.ECDSAP256SHA256
    )
    zsk_algorithm: DNSSECAlgorithm = Field(
        default=DNSSECAlgorithm.ECDSAP256SHA256
    )


class SigningStatus(BaseModel):
    """Zone signing status"""
    zone: str
    signed: bool
    inline_signing: bool = False
    nsec3: bool = False
    nsec3_iterations: Optional[int] = None
    nsec3_salt: Optional[str] = None
    
    # Keys
    ksk_count: int = 0
    zsk_count: int = 0
    active_keys: List[int] = Field(default=[], description="Active key tags")
    
    # Timing
    last_signed: Optional[datetime] = None
    signatures_expiring: Optional[datetime] = None
    next_key_event: Optional[datetime] = None


# =============================================================================
# DNSSEC Policy Models (BIND 9.16+)
# =============================================================================

class DNSSECPolicy(BaseModel):
    """DNSSEC policy configuration (dnssec-policy)"""
    name: str
    
    # Key parameters
    keys: List[dict] = Field(
        default=[
            {"key_type": "csk", "algorithm": "ecdsap256sha256", "lifetime": "unlimited"}
        ],
        description="Key definitions"
    )
    
    # Timing parameters
    dnskey_ttl: str = Field(default="1h", description="DNSKEY TTL")
    publish_safety: str = Field(default="1h", description="Safety margin for publication")
    retire_safety: str = Field(default="1h", description="Safety margin for retirement")
    purge_keys: str = Field(default="P90D", description="Time to purge removed keys")
    
    # NSEC/NSEC3
    nsec3: bool = Field(default=False, description="Use NSEC3")
    nsec3param_iterations: int = Field(default=0)
    nsec3param_salt_length: int = Field(default=0)
    nsec3param_optout: bool = Field(default=False)
    
    # Signature parameters
    signatures_refresh: str = Field(default="P5D", description="Signature refresh period")
    signatures_validity: str = Field(default="P14D", description="Signature validity period")
    signatures_validity_dnskey: str = Field(default="P14D", description="DNSKEY signature validity")
    
    # Zone parameters
    max_zone_ttl: str = Field(default="P1D", description="Maximum zone TTL")
    zone_propagation_delay: str = Field(default="PT5M", description="Zone propagation delay")
    parent_ds_ttl: str = Field(default="P1D", description="Parent DS TTL")
    parent_propagation_delay: str = Field(default="PT1H", description="Parent propagation delay")


class DNSSECPolicyResponse(DNSSECPolicy):
    """DNSSEC policy with usage information"""
    zones_using: List[str] = []


# =============================================================================
# DS Record Models
# =============================================================================

class DSRecordRequest(BaseModel):
    """Request DS record generation"""
    zone: str
    digest_types: List[DNSSECDigestType] = Field(
        default=[DNSSECDigestType.SHA256, DNSSECDigestType.SHA384],
        description="Digest types to generate"
    )
    key_tag: Optional[int] = Field(
        default=None,
        description="Specific key tag (all KSKs if not specified)"
    )


class DSRecordResponse(BaseModel):
    """Generated DS records"""
    zone: str
    ds_records: List[str]
    key_tag: int
    algorithm: DNSSECAlgorithm
    digest_type: DNSSECDigestType
    digest: str
    
    # For registrar
    bind_format: str
    generic_format: str


# =============================================================================
# Trust Anchor Models
# =============================================================================

class TrustAnchor(BaseModel):
    """Trust anchor (managed-keys / trust-anchors)"""
    zone: str
    key_tag: int
    algorithm: DNSSECAlgorithm
    digest_type: Optional[DNSSECDigestType] = None
    digest: Optional[str] = None
    public_key: Optional[str] = None
    state: str
    last_validated: Optional[datetime] = None


class NegativeTrustAnchor(BaseModel):
    """Negative Trust Anchor (NTA)"""
    zone: str
    reason: Optional[str] = None
    expires: Optional[datetime] = None
    forced: bool = False


class NTACreate(BaseModel):
    """Create Negative Trust Anchor"""
    zone: str
    lifetime: str = Field(
        default="1h",
        description="NTA lifetime (e.g., '1h', '1d', 'forever')"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for creating NTA"
    )
    force: bool = Field(
        default=False,
        description="Force NTA even for secure zones"
    )

