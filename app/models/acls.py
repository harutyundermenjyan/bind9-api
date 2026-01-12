"""
ACL (Access Control List) Models for BIND9
Manages named ACLs that can be referenced in zone configurations
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum
import re


class ACLEntryType(str, Enum):
    """Types of ACL entries"""
    IP = "ip"           # Single IP: 192.168.1.1
    NETWORK = "network" # CIDR: 192.168.1.0/24
    KEY = "key"         # TSIG key: key "ddns-key"
    ACL = "acl"         # Reference another ACL: internal
    BUILTIN = "builtin" # Built-in: localhost, localnets, any, none


class ACLEntry(BaseModel):
    """Single ACL entry"""
    value: str = Field(..., description="ACL entry value")
    negated: bool = Field(default=False, description="Negate this entry (! prefix)")
    comment: Optional[str] = Field(default=None, description="Optional comment")
    
    @field_validator("value")
    @classmethod
    def validate_value(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("ACL entry value cannot be empty")
        return v
    
    def to_bind_format(self) -> str:
        """Convert to BIND9 configuration format"""
        prefix = "!" if self.negated else ""
        
        # Check if it's a TSIG key reference
        if self.value.startswith("key ") or self.value.startswith("key \""):
            # Normalize key format
            key_name = self.value.replace("key ", "").replace('"', '').strip()
            return f'{prefix}key "{key_name}"'
        
        # Check if it's a built-in ACL
        builtins = ["localhost", "localnets", "any", "none"]
        if self.value.lower() in builtins:
            return f"{prefix}{self.value.lower()}"
        
        # IP or network - return as-is
        return f"{prefix}{self.value}"


class ACLBase(BaseModel):
    """Base ACL model"""
    name: str = Field(..., min_length=1, max_length=64, description="ACL name")
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        v = v.strip()
        # ACL names should be valid identifiers
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', v):
            raise ValueError("ACL name must start with a letter and contain only letters, numbers, hyphens, and underscores")
        # Reserved names
        reserved = ["any", "none", "localhost", "localnets"]
        if v.lower() in reserved:
            raise ValueError(f"'{v}' is a reserved ACL name")
        return v


class ACLCreate(ACLBase):
    """Create a new ACL"""
    entries: List[str] = Field(
        default=[],
        description="List of ACL entries (IPs, networks, keys, or ACL references)"
    )
    comment: Optional[str] = Field(default=None, description="ACL description/comment")
    
    @field_validator("entries")
    @classmethod
    def validate_entries(cls, v):
        validated = []
        for entry in v:
            entry = entry.strip()
            if entry:
                validated.append(entry)
        return validated


class ACLUpdate(BaseModel):
    """Update an existing ACL"""
    entries: Optional[List[str]] = Field(
        default=None,
        description="List of ACL entries"
    )
    comment: Optional[str] = Field(default=None, description="ACL description/comment")


class ACLResponse(ACLBase):
    """ACL response model"""
    entries: List[str] = Field(default=[], description="ACL entries")
    comment: Optional[str] = Field(default=None, description="ACL comment")
    
    class Config:
        from_attributes = True


class ACLListResponse(BaseModel):
    """List of ACLs response"""
    acls: List[ACLResponse] = Field(default=[], description="List of ACLs")
    count: int = Field(default=0, description="Total count")


class ACLFileConfig(BaseModel):
    """Configuration for the ACL file"""
    file_path: str = Field(
        default="/etc/bind/named.conf.acls",
        description="Path to the ACL configuration file"
    )
    include_in_named_conf: bool = Field(
        default=True,
        description="Whether to ensure the file is included in named.conf"
    )
