"""
Comprehensive DNS Record Type Models
Supports all standard DNS record types as per IANA registry
"""

from datetime import datetime
from typing import Optional, List, Union, Literal, Annotated
from pydantic import BaseModel, Field, field_validator, model_validator, IPvAnyAddress
from enum import Enum
import re
import ipaddress


class RecordType(str, Enum):
    """All supported DNS record types"""
    # Standard Records
    A = "A"                     # IPv4 address
    AAAA = "AAAA"               # IPv6 address
    CNAME = "CNAME"             # Canonical name
    MX = "MX"                   # Mail exchanger
    NS = "NS"                   # Name server
    PTR = "PTR"                 # Pointer (reverse DNS)
    SOA = "SOA"                 # Start of authority
    TXT = "TXT"                 # Text record
    SRV = "SRV"                 # Service locator
    CAA = "CAA"                 # Certification Authority Authorization
    
    # Security Records
    DNSKEY = "DNSKEY"           # DNSSEC public key
    DS = "DS"                   # Delegation signer
    RRSIG = "RRSIG"             # DNSSEC signature
    NSEC = "NSEC"               # Next secure record
    NSEC3 = "NSEC3"             # NSEC version 3
    NSEC3PARAM = "NSEC3PARAM"   # NSEC3 parameters
    TLSA = "TLSA"               # TLS Authentication
    SSHFP = "SSHFP"             # SSH fingerprint
    IPSECKEY = "IPSECKEY"       # IPsec key
    
    # Service Discovery
    NAPTR = "NAPTR"             # Naming authority pointer
    HTTPS = "HTTPS"             # HTTPS service binding
    SVCB = "SVCB"               # Service binding
    
    # Location & Info
    LOC = "LOC"                 # Location
    HINFO = "HINFO"             # Host information
    RP = "RP"                   # Responsible person
    
    # Mail Related
    SPF = "SPF"                 # Sender Policy Framework (deprecated, use TXT)
    DKIM = "DKIM"               # DomainKeys (via TXT)
    DMARC = "DMARC"             # DMARC (via TXT)
    
    # Database & Services
    AFSDB = "AFSDB"             # AFS database
    
    # Aliases & Delegation
    DNAME = "DNAME"             # Delegation name
    
    # Certificates
    CERT = "CERT"               # Certificate record
    
    # Other
    APL = "APL"                 # Address prefix list
    CDNSKEY = "CDNSKEY"         # Child DNSKEY
    CDS = "CDS"                 # Child DS
    CSYNC = "CSYNC"             # Child-to-parent sync
    DHCID = "DHCID"             # DHCP identifier
    DLV = "DLV"                 # DNSSEC lookaside validation
    EUI48 = "EUI48"             # MAC address (EUI-48)
    EUI64 = "EUI64"             # MAC address (EUI-64)
    HIP = "HIP"                 # Host identity protocol
    KX = "KX"                   # Key exchanger
    OPENPGPKEY = "OPENPGPKEY"   # OpenPGP public key
    SMIMEA = "SMIMEA"           # S/MIME certificate association
    URI = "URI"                 # URI record
    ZONEMD = "ZONEMD"           # Zone message digest


class RecordClass(str, Enum):
    """DNS record classes"""
    IN = "IN"       # Internet
    CH = "CH"       # Chaos
    HS = "HS"       # Hesiod
    ANY = "ANY"     # Any class


# =============================================================================
# Base Record Models
# =============================================================================

class BaseRecord(BaseModel):
    """Base model for all DNS records"""
    name: str = Field(..., description="Record name (hostname or @)")
    ttl: int = Field(default=3600, ge=0, le=2147483647, description="Time to live in seconds")
    record_class: RecordClass = Field(default=RecordClass.IN, description="Record class")
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        # Allow @ for zone apex, * for wildcards
        if v in ["@", "*"]:
            return v
        # Validate hostname
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-_.]*[a-zA-Z0-9])?$|^\*\.[a-zA-Z0-9]", v):
            if not v.endswith("."):  # FQDN
                raise ValueError(f"Invalid record name: {v}")
        return v


class RecordResponse(BaseRecord):
    """Record response with additional metadata"""
    record_type: RecordType
    zone: str
    rdata: str  # Raw record data
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# =============================================================================
# Address Records (A, AAAA)
# =============================================================================

class ARecord(BaseRecord):
    """A Record - IPv4 address"""
    record_type: Literal[RecordType.A] = RecordType.A
    address: str = Field(..., description="IPv4 address")
    
    @field_validator("address")
    @classmethod
    def validate_ipv4(cls, v):
        try:
            ipaddress.IPv4Address(v)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address: {v}")
        return v


class AAAARecord(BaseRecord):
    """AAAA Record - IPv6 address"""
    record_type: Literal[RecordType.AAAA] = RecordType.AAAA
    address: str = Field(..., description="IPv6 address")
    
    @field_validator("address")
    @classmethod
    def validate_ipv6(cls, v):
        try:
            ipaddress.IPv6Address(v)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv6 address: {v}")
        return v


# =============================================================================
# Name Records (CNAME, NS, PTR, DNAME)
# =============================================================================

class CNAMERecord(BaseRecord):
    """CNAME Record - Canonical name (alias)"""
    record_type: Literal[RecordType.CNAME] = RecordType.CNAME
    target: str = Field(..., description="Target hostname")


class NSRecord(BaseRecord):
    """NS Record - Name server"""
    record_type: Literal[RecordType.NS] = RecordType.NS
    nameserver: str = Field(..., description="Name server hostname")


class PTRRecord(BaseRecord):
    """PTR Record - Pointer (reverse DNS)"""
    record_type: Literal[RecordType.PTR] = RecordType.PTR
    ptrdname: str = Field(..., description="Pointer domain name")


class DNAMERecord(BaseRecord):
    """DNAME Record - Delegation name"""
    record_type: Literal[RecordType.DNAME] = RecordType.DNAME
    target: str = Field(..., description="Target domain name")


# =============================================================================
# SOA Record
# =============================================================================

class SOARecord(BaseRecord):
    """SOA Record - Start of Authority"""
    record_type: Literal[RecordType.SOA] = RecordType.SOA
    mname: str = Field(..., description="Primary nameserver")
    rname: str = Field(..., description="Responsible person email (use . instead of @)")
    serial: int = Field(..., ge=0, description="Serial number (usually YYYYMMDDNN)")
    refresh: int = Field(default=86400, ge=0, description="Refresh interval (seconds)")
    retry: int = Field(default=7200, ge=0, description="Retry interval (seconds)")
    expire: int = Field(default=3600000, ge=0, description="Expire time (seconds)")
    minimum: int = Field(default=3600, ge=0, description="Minimum/negative TTL (seconds)")
    
    @field_validator("rname")
    @classmethod
    def validate_rname(cls, v):
        # rname should use . instead of @
        if "@" in v:
            v = v.replace("@", ".", 1)
        return v


# =============================================================================
# Mail Records (MX)
# =============================================================================

class MXRecord(BaseRecord):
    """MX Record - Mail exchanger"""
    record_type: Literal[RecordType.MX] = RecordType.MX
    preference: int = Field(..., ge=0, le=65535, description="Priority (lower = higher priority)")
    exchange: str = Field(..., description="Mail server hostname")


# =============================================================================
# Text Records (TXT, SPF)
# =============================================================================

class TXTRecord(BaseRecord):
    """TXT Record - Text record"""
    record_type: Literal[RecordType.TXT] = RecordType.TXT
    text: Union[str, List[str]] = Field(..., description="Text data (string or list of strings)")
    
    @field_validator("text")
    @classmethod
    def validate_text(cls, v):
        if isinstance(v, list):
            # Join multiple strings
            for s in v:
                if len(s) > 255:
                    # Individual strings must be <= 255 chars
                    pass  # Will be chunked
        return v


# =============================================================================
# Service Records (SRV, NAPTR, HTTPS, SVCB)
# =============================================================================

class SRVRecord(BaseRecord):
    """SRV Record - Service locator"""
    record_type: Literal[RecordType.SRV] = RecordType.SRV
    priority: int = Field(..., ge=0, le=65535, description="Priority")
    weight: int = Field(..., ge=0, le=65535, description="Weight")
    port: int = Field(..., ge=0, le=65535, description="Port number")
    target: str = Field(..., description="Target hostname")


class NAPTRRecord(BaseRecord):
    """NAPTR Record - Naming Authority Pointer"""
    record_type: Literal[RecordType.NAPTR] = RecordType.NAPTR
    order: int = Field(..., ge=0, le=65535, description="Order")
    preference: int = Field(..., ge=0, le=65535, description="Preference")
    flags: str = Field(..., max_length=255, description="Flags (e.g., 'U', 'S', 'A', 'P')")
    service: str = Field(..., max_length=255, description="Service (e.g., 'E2U+sip')")
    regexp: str = Field(default="", description="Regular expression")
    replacement: str = Field(default=".", description="Replacement domain")


class HTTPSRecord(BaseRecord):
    """HTTPS Record - HTTPS service binding (RFC 9460)"""
    record_type: Literal[RecordType.HTTPS] = RecordType.HTTPS
    priority: int = Field(..., ge=0, le=65535, description="Priority (0 = alias mode)")
    target: str = Field(..., description="Target name")
    params: Optional[dict] = Field(default=None, description="Service parameters")


class SVCBRecord(BaseRecord):
    """SVCB Record - Service Binding (RFC 9460)"""
    record_type: Literal[RecordType.SVCB] = RecordType.SVCB
    priority: int = Field(..., ge=0, le=65535, description="Priority")
    target: str = Field(..., description="Target name")
    params: Optional[dict] = Field(default=None, description="Service parameters")


# =============================================================================
# Security Records (CAA, TLSA, SSHFP)
# =============================================================================

class CAARecord(BaseRecord):
    """CAA Record - Certification Authority Authorization"""
    record_type: Literal[RecordType.CAA] = RecordType.CAA
    flags: int = Field(default=0, ge=0, le=255, description="Flags (0 or 128)")
    tag: str = Field(..., description="Tag (issue, issuewild, iodef)")
    value: str = Field(..., description="CA domain or mailto/https URL")
    
    @field_validator("tag")
    @classmethod
    def validate_tag(cls, v):
        valid_tags = ["issue", "issuewild", "iodef", "contactemail", "contactphone"]
        if v.lower() not in valid_tags:
            raise ValueError(f"Invalid CAA tag: {v}. Must be one of {valid_tags}")
        return v.lower()


class TLSARecord(BaseRecord):
    """TLSA Record - TLS Authentication (DANE)"""
    record_type: Literal[RecordType.TLSA] = RecordType.TLSA
    usage: int = Field(..., ge=0, le=3, description="Certificate usage (0-3)")
    selector: int = Field(..., ge=0, le=1, description="Selector (0=full cert, 1=public key)")
    matching_type: int = Field(..., ge=0, le=2, description="Matching type (0=exact, 1=SHA-256, 2=SHA-512)")
    certificate_data: str = Field(..., description="Certificate association data (hex)")


class SSHFPRecord(BaseRecord):
    """SSHFP Record - SSH Fingerprint"""
    record_type: Literal[RecordType.SSHFP] = RecordType.SSHFP
    algorithm: int = Field(..., ge=1, le=4, description="Algorithm (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519)")
    fingerprint_type: int = Field(..., ge=1, le=2, description="Fingerprint type (1=SHA-1, 2=SHA-256)")
    fingerprint: str = Field(..., description="Fingerprint (hex)")


# =============================================================================
# DNSSEC Records
# =============================================================================

class DNSKEYRecord(BaseRecord):
    """DNSKEY Record - DNSSEC public key"""
    record_type: Literal[RecordType.DNSKEY] = RecordType.DNSKEY
    flags: int = Field(..., description="Flags (256=ZSK, 257=KSK)")
    protocol: int = Field(default=3, description="Protocol (always 3)")
    algorithm: int = Field(..., description="Algorithm number")
    public_key: str = Field(..., description="Base64-encoded public key")


class DSRecord(BaseRecord):
    """DS Record - Delegation Signer"""
    record_type: Literal[RecordType.DS] = RecordType.DS
    key_tag: int = Field(..., ge=0, le=65535, description="Key tag")
    algorithm: int = Field(..., description="Algorithm number")
    digest_type: int = Field(..., ge=1, le=4, description="Digest type (1=SHA-1, 2=SHA-256, 4=SHA-384)")
    digest: str = Field(..., description="Digest (hex)")


class RRSIGRecord(BaseRecord):
    """RRSIG Record - DNSSEC Signature"""
    record_type: Literal[RecordType.RRSIG] = RecordType.RRSIG
    type_covered: str = Field(..., description="RR type covered")
    algorithm: int = Field(..., description="Algorithm number")
    labels: int = Field(..., description="Number of labels")
    original_ttl: int = Field(..., description="Original TTL")
    signature_expiration: int = Field(..., description="Signature expiration (Unix timestamp)")
    signature_inception: int = Field(..., description="Signature inception (Unix timestamp)")
    key_tag: int = Field(..., description="Key tag")
    signer_name: str = Field(..., description="Signer's name")
    signature: str = Field(..., description="Base64-encoded signature")


class NSECRecord(BaseRecord):
    """NSEC Record - Next Secure"""
    record_type: Literal[RecordType.NSEC] = RecordType.NSEC
    next_domain: str = Field(..., description="Next domain name")
    types: List[str] = Field(..., description="List of RR types")


class NSEC3Record(BaseRecord):
    """NSEC3 Record - NSEC version 3"""
    record_type: Literal[RecordType.NSEC3] = RecordType.NSEC3
    algorithm: int = Field(default=1, description="Hash algorithm (1=SHA-1)")
    flags: int = Field(default=0, description="Flags")
    iterations: int = Field(..., description="Hash iterations")
    salt: str = Field(..., description="Salt (hex, or - for none)")
    next_hashed: str = Field(..., description="Next hashed owner name")
    types: List[str] = Field(..., description="List of RR types")


class NSEC3PARAMRecord(BaseRecord):
    """NSEC3PARAM Record - NSEC3 Parameters"""
    record_type: Literal[RecordType.NSEC3PARAM] = RecordType.NSEC3PARAM
    algorithm: int = Field(default=1, description="Hash algorithm")
    flags: int = Field(default=0, description="Flags")
    iterations: int = Field(..., description="Hash iterations")
    salt: str = Field(..., description="Salt (hex, or - for none)")


# =============================================================================
# Location & Info Records
# =============================================================================

class LOCRecord(BaseRecord):
    """LOC Record - Geographic location"""
    record_type: Literal[RecordType.LOC] = RecordType.LOC
    latitude: str = Field(..., description="Latitude (e.g., '37 46 30.000 N')")
    longitude: str = Field(..., description="Longitude (e.g., '122 23 30.000 W')")
    altitude: float = Field(default=0, description="Altitude in meters")
    size: float = Field(default=1, description="Size/diameter in meters")
    horizontal_precision: float = Field(default=10000, description="Horizontal precision in meters")
    vertical_precision: float = Field(default=10, description="Vertical precision in meters")


class HINFORecord(BaseRecord):
    """HINFO Record - Host information"""
    record_type: Literal[RecordType.HINFO] = RecordType.HINFO
    cpu: str = Field(..., description="CPU type")
    os: str = Field(..., description="Operating system")


class RPRecord(BaseRecord):
    """RP Record - Responsible Person"""
    record_type: Literal[RecordType.RP] = RecordType.RP
    mbox: str = Field(..., description="Mailbox (email with . instead of @)")
    txtdname: str = Field(default=".", description="TXT record domain name")


# =============================================================================
# Certificate Records
# =============================================================================

class CERTRecord(BaseRecord):
    """CERT Record - Certificate"""
    record_type: Literal[RecordType.CERT] = RecordType.CERT
    cert_type: int = Field(..., description="Certificate type")
    key_tag: int = Field(..., description="Key tag")
    algorithm: int = Field(..., description="Algorithm")
    certificate: str = Field(..., description="Base64-encoded certificate")


# =============================================================================
# Other Records
# =============================================================================

class AFSDBRecord(BaseRecord):
    """AFSDB Record - AFS Database"""
    record_type: Literal[RecordType.AFSDB] = RecordType.AFSDB
    subtype: int = Field(..., ge=1, le=2, description="Subtype (1=AFS, 2=DCE)")
    hostname: str = Field(..., description="Server hostname")


class URIRecord(BaseRecord):
    """URI Record"""
    record_type: Literal[RecordType.URI] = RecordType.URI
    priority: int = Field(..., ge=0, le=65535, description="Priority")
    weight: int = Field(..., ge=0, le=65535, description="Weight")
    target: str = Field(..., description="URI target")


class IPSECKEYRecord(BaseRecord):
    """IPSECKEY Record - IPsec Key"""
    record_type: Literal[RecordType.IPSECKEY] = RecordType.IPSECKEY
    precedence: int = Field(..., ge=0, le=255, description="Precedence")
    gateway_type: int = Field(..., ge=0, le=3, description="Gateway type")
    algorithm: int = Field(..., description="Algorithm")
    gateway: str = Field(..., description="Gateway")
    public_key: str = Field(..., description="Base64-encoded public key")


class OPENPGPKEYRecord(BaseRecord):
    """OPENPGPKEY Record - OpenPGP Public Key"""
    record_type: Literal[RecordType.OPENPGPKEY] = RecordType.OPENPGPKEY
    public_key: str = Field(..., description="Base64-encoded OpenPGP public key")


class SMIMEARecord(BaseRecord):
    """SMIMEA Record - S/MIME Certificate Association"""
    record_type: Literal[RecordType.SMIMEA] = RecordType.SMIMEA
    usage: int = Field(..., ge=0, le=3, description="Certificate usage")
    selector: int = Field(..., ge=0, le=1, description="Selector")
    matching_type: int = Field(..., ge=0, le=2, description="Matching type")
    certificate_data: str = Field(..., description="Certificate data (hex)")


class KXRecord(BaseRecord):
    """KX Record - Key Exchanger"""
    record_type: Literal[RecordType.KX] = RecordType.KX
    preference: int = Field(..., ge=0, le=65535, description="Preference")
    exchanger: str = Field(..., description="Key exchanger hostname")


class DHCIDRecord(BaseRecord):
    """DHCID Record - DHCP Identifier"""
    record_type: Literal[RecordType.DHCID] = RecordType.DHCID
    digest: str = Field(..., description="Base64-encoded DHCID")


class EUI48Record(BaseRecord):
    """EUI48 Record - 48-bit MAC address"""
    record_type: Literal[RecordType.EUI48] = RecordType.EUI48
    address: str = Field(..., description="EUI-48 address (e.g., 00-00-5e-00-53-2a)")
    
    @field_validator("address")
    @classmethod
    def validate_eui48(cls, v):
        # Accept various formats and normalize
        v = v.replace(":", "-").upper()
        if not re.match(r"^([0-9A-F]{2}-){5}[0-9A-F]{2}$", v):
            raise ValueError(f"Invalid EUI-48 address: {v}")
        return v


class EUI64Record(BaseRecord):
    """EUI64 Record - 64-bit MAC address"""
    record_type: Literal[RecordType.EUI64] = RecordType.EUI64
    address: str = Field(..., description="EUI-64 address")
    
    @field_validator("address")
    @classmethod
    def validate_eui64(cls, v):
        v = v.replace(":", "-").upper()
        if not re.match(r"^([0-9A-F]{2}-){7}[0-9A-F]{2}$", v):
            raise ValueError(f"Invalid EUI-64 address: {v}")
        return v


class ZONEMDRecord(BaseRecord):
    """ZONEMD Record - Zone Message Digest"""
    record_type: Literal[RecordType.ZONEMD] = RecordType.ZONEMD
    serial: int = Field(..., description="SOA serial")
    scheme: int = Field(..., ge=1, le=1, description="Scheme (1=SIMPLE)")
    algorithm: int = Field(..., description="Hash algorithm (1=SHA-384, 2=SHA-512)")
    digest: str = Field(..., description="Digest (hex)")


# =============================================================================
# Generic Record for arbitrary types
# =============================================================================

class GenericRecord(BaseRecord):
    """Generic record for any type (raw RDATA)"""
    record_type: RecordType
    rdata: str = Field(..., description="Raw record data")


# =============================================================================
# Request/Response Models
# =============================================================================

class RecordCreate(BaseModel):
    """Create a new DNS record"""
    record_type: RecordType
    name: str
    ttl: int = 3600
    record_class: RecordClass = RecordClass.IN
    # Type-specific fields are validated based on record_type
    data: dict = Field(..., description="Record-specific data")


class RecordUpdate(BaseModel):
    """Update an existing DNS record"""
    ttl: Optional[int] = None
    data: Optional[dict] = None


class RecordDelete(BaseModel):
    """Delete a DNS record"""
    name: str
    record_type: RecordType
    rdata: Optional[str] = None  # If specified, only delete matching record


class RecordQuery(BaseModel):
    """Query parameters for listing records"""
    name: Optional[str] = None
    record_type: Optional[RecordType] = None
    search: Optional[str] = None


class BulkRecordOperation(BaseModel):
    """Bulk record operation"""
    operation: Literal["create", "update", "delete"]
    records: List[dict]


# Type alias for all record types
AnyRecord = Union[
    ARecord, AAAARecord, CNAMERecord, MXRecord, NSRecord, PTRRecord,
    SOARecord, TXTRecord, SRVRecord, CAARecord, TLSARecord, SSHFPRecord,
    DNSKEYRecord, DSRecord, RRSIGRecord, NSECRecord, NSEC3Record, NSEC3PARAMRecord,
    NAPTRRecord, HTTPSRecord, SVCBRecord, LOCRecord, HINFORecord, RPRecord,
    CERTRecord, AFSDBRecord, DNAMERecord, URIRecord, IPSECKEYRecord,
    OPENPGPKEYRecord, SMIMEARecord, KXRecord, DHCIDRecord, EUI48Record,
    EUI64Record, ZONEMDRecord, GenericRecord
]

