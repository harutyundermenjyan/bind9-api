"""
Comprehensive Validation Service for BIND9 REST API
Ensures all changes are validated before being applied to prevent server failures
"""

import re
import asyncio
import ipaddress
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
import dns.name
import dns.rdatatype

from ..config import settings


class ValidationError(Exception):
    """Validation failed"""
    def __init__(self, message: str, errors: List[str] = None):
        super().__init__(message)
        self.errors = errors or [message]


class ValidationService:
    """
    Comprehensive validation service for BIND9 operations
    All validations are performed BEFORE any changes are applied
    """
    
    def __init__(self):
        self.checkzone_path = settings.bind9_named_checkzone
        self.checkconf_path = settings.bind9_named_checkconf
        self.rndc_path = settings.bind9_rndc_path
    
    # =========================================================================
    # DNS Name Validation
    # =========================================================================
    
    def validate_hostname(self, hostname: str, allow_wildcard: bool = True) -> Tuple[bool, str]:
        """
        Validate DNS hostname/label
        Returns: (is_valid, error_message)
        """
        if not hostname:
            return False, "Hostname cannot be empty"
        
        # Handle special cases
        if hostname == "@":
            return True, ""
        
        if hostname == "*" and allow_wildcard:
            return True, ""
        
        if hostname.startswith("*.") and allow_wildcard:
            hostname = hostname[2:]  # Validate rest of name
        
        # Remove trailing dot if present
        hostname = hostname.rstrip(".")
        
        # Check total length
        if len(hostname) > 253:
            return False, f"Hostname too long: {len(hostname)} > 253 characters"
        
        # Validate each label
        labels = hostname.split(".")
        for label in labels:
            if not label:
                return False, "Empty label in hostname"
            
            if len(label) > 63:
                return False, f"Label too long: '{label}' ({len(label)} > 63)"
            
            # Check for valid characters
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$', label):
                # Allow underscore for special records like _dmarc, _dkim
                if not re.match(r'^_?[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$|^_?[a-zA-Z0-9]$', label):
                    return False, f"Invalid characters in label: '{label}'"
        
        return True, ""
    
    def validate_zone_name(self, zone_name: str) -> Tuple[bool, str]:
        """Validate zone name"""
        if not zone_name:
            return False, "Zone name cannot be empty"
        
        zone_name = zone_name.rstrip(".")
        
        # Check for valid TLD or internal zone
        valid, error = self.validate_hostname(zone_name, allow_wildcard=False)
        if not valid:
            return False, f"Invalid zone name: {error}"
        
        return True, ""
    
    def validate_fqdn(self, fqdn: str) -> Tuple[bool, str]:
        """Validate fully qualified domain name"""
        if not fqdn:
            return False, "FQDN cannot be empty"
        
        # FQDN should end with a dot
        if not fqdn.endswith("."):
            return False, f"FQDN must end with a dot: '{fqdn}'"
        
        return self.validate_hostname(fqdn.rstrip("."), allow_wildcard=False)
    
    # =========================================================================
    # IP Address Validation
    # =========================================================================
    
    def validate_ipv4(self, ip: str) -> Tuple[bool, str]:
        """Validate IPv4 address"""
        try:
            addr = ipaddress.IPv4Address(ip)
            return True, ""
        except ipaddress.AddressValueError as e:
            return False, f"Invalid IPv4 address '{ip}': {e}"
    
    def validate_ipv6(self, ip: str) -> Tuple[bool, str]:
        """Validate IPv6 address"""
        try:
            addr = ipaddress.IPv6Address(ip)
            return True, ""
        except ipaddress.AddressValueError as e:
            return False, f"Invalid IPv6 address '{ip}': {e}"
    
    def validate_ip(self, ip: str) -> Tuple[bool, str]:
        """Validate IPv4 or IPv6 address"""
        try:
            addr = ipaddress.ip_address(ip)
            return True, ""
        except ValueError as e:
            return False, f"Invalid IP address '{ip}': {e}"
    
    def validate_network(self, network: str) -> Tuple[bool, str]:
        """Validate IP network (CIDR notation)"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return True, ""
        except ValueError as e:
            return False, f"Invalid network '{network}': {e}"
    
    # =========================================================================
    # DNS Record Validation
    # =========================================================================
    
    def validate_record_type(self, record_type: str) -> Tuple[bool, str]:
        """Validate DNS record type"""
        valid_types = [
            "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
            "CAA", "DNSKEY", "DS", "NAPTR", "SSHFP", "TLSA", "HINFO",
            "RP", "AFSDB", "LOC", "SPF", "CERT", "DNAME", "HTTPS", "SVCB"
        ]
        
        if record_type.upper() not in valid_types:
            return False, f"Unknown record type: '{record_type}'. Valid types: {', '.join(valid_types)}"
        
        return True, ""
    
    def validate_ttl(self, ttl: int) -> Tuple[bool, str]:
        """Validate TTL value"""
        if ttl < 0:
            return False, f"TTL cannot be negative: {ttl}"
        if ttl > 2147483647:  # Max signed 32-bit int
            return False, f"TTL too large: {ttl} > 2147483647"
        if ttl < 60:
            # Warning but not error
            pass
        return True, ""
    
    def validate_record_data(
        self,
        record_type: str,
        data: str,
        zone_name: str = None
    ) -> Tuple[bool, str]:
        """
        Validate record data based on record type
        """
        record_type = record_type.upper()
        
        if record_type == "A":
            return self.validate_ipv4(data)
        
        elif record_type == "AAAA":
            return self.validate_ipv6(data)
        
        elif record_type in ["CNAME", "NS", "PTR", "DNAME"]:
            # Must be a valid hostname
            if not data.endswith("."):
                # Relative name, that's OK
                return self.validate_hostname(data)
            return self.validate_fqdn(data)
        
        elif record_type == "MX":
            # Format: priority target
            parts = data.split(None, 1)
            if len(parts) != 2:
                return False, f"MX record must have priority and target: '{data}'"
            try:
                priority = int(parts[0])
                if priority < 0 or priority > 65535:
                    return False, f"MX priority must be 0-65535: {priority}"
            except ValueError:
                return False, f"Invalid MX priority: '{parts[0]}'"
            return self.validate_hostname(parts[1].rstrip("."))
        
        elif record_type == "SRV":
            # Format: priority weight port target
            parts = data.split()
            if len(parts) != 4:
                return False, f"SRV record must have priority, weight, port, and target: '{data}'"
            try:
                priority = int(parts[0])
                weight = int(parts[1])
                port = int(parts[2])
                if priority < 0 or priority > 65535:
                    return False, f"SRV priority must be 0-65535: {priority}"
                if weight < 0 or weight > 65535:
                    return False, f"SRV weight must be 0-65535: {weight}"
                if port < 0 or port > 65535:
                    return False, f"SRV port must be 0-65535: {port}"
            except ValueError:
                return False, "Invalid SRV numeric fields"
            return self.validate_hostname(parts[3].rstrip("."))
        
        elif record_type == "TXT":
            # TXT records can contain almost anything
            if len(data) > 65535:
                return False, f"TXT record too long: {len(data)} > 65535"
            return True, ""
        
        elif record_type == "CAA":
            # Format: flags tag value
            parts = data.split(None, 2)
            if len(parts) != 3:
                return False, f"CAA record must have flags, tag, and value: '{data}'"
            try:
                flags = int(parts[0])
                if flags < 0 or flags > 255:
                    return False, f"CAA flags must be 0-255: {flags}"
            except ValueError:
                return False, f"Invalid CAA flags: '{parts[0]}'"
            valid_tags = ["issue", "issuewild", "iodef"]
            if parts[1].lower() not in valid_tags:
                return False, f"Invalid CAA tag: '{parts[1]}'. Valid tags: {', '.join(valid_tags)}"
            return True, ""
        
        elif record_type == "SOA":
            # SOA has complex format, basic check
            parts = data.split()
            if len(parts) < 7:
                return False, "SOA record requires mname, rname, serial, refresh, retry, expire, minimum"
            return True, ""
        
        # For other types, accept any non-empty data
        if not data or not data.strip():
            return False, f"Record data cannot be empty for type {record_type}"
        
        return True, ""
    
    def validate_record(
        self,
        zone: str,
        name: str,
        record_type: str,
        data: str,
        ttl: int = 3600
    ) -> Tuple[bool, List[str]]:
        """
        Comprehensive record validation
        Returns: (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate zone
        valid, error = self.validate_zone_name(zone)
        if not valid:
            errors.append(f"Zone: {error}")
        
        # Validate name
        valid, error = self.validate_hostname(name)
        if not valid:
            errors.append(f"Name: {error}")
        
        # Validate type
        valid, error = self.validate_record_type(record_type)
        if not valid:
            errors.append(f"Type: {error}")
        
        # Validate TTL
        valid, error = self.validate_ttl(ttl)
        if not valid:
            errors.append(f"TTL: {error}")
        
        # Validate data
        valid, error = self.validate_record_data(record_type, data, zone)
        if not valid:
            errors.append(f"Data: {error}")
        
        # CNAME conflict check
        if record_type.upper() == "CNAME" and name == "@":
            errors.append("CNAME record cannot be at zone apex (@)")
        
        return len(errors) == 0, errors
    
    # =========================================================================
    # Zone Validation
    # =========================================================================
    
    def validate_zone_config(
        self,
        zone_name: str,
        zone_type: str,
        soa_mname: str = None,
        soa_rname: str = None,
        nameservers: List[str] = None,
        ns_addresses: Dict[str, str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate zone configuration before creation
        Returns: (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate zone name
        valid, error = self.validate_zone_name(zone_name)
        if not valid:
            errors.append(error)
        
        # Validate zone type
        valid_types = ["master", "primary", "slave", "secondary", "stub", "forward", "hint", "redirect"]
        if zone_type.lower() not in valid_types:
            errors.append(f"Invalid zone type: '{zone_type}'. Valid types: {', '.join(valid_types)}")
        
        # For master/primary zones, validate SOA
        if zone_type.lower() in ["master", "primary"]:
            if soa_mname:
                # Check if it's a valid hostname
                mname = soa_mname.rstrip(".")
                if "." in mname or soa_mname.endswith("."):
                    valid, error = self.validate_hostname(mname)
                    if not valid:
                        errors.append(f"SOA MNAME: {error}")
            
            if soa_rname:
                rname = soa_rname.rstrip(".")
                if "." in rname or soa_rname.endswith("."):
                    valid, error = self.validate_hostname(rname.replace("@", "."))
                    if not valid:
                        errors.append(f"SOA RNAME: {error}")
            
            # Validate nameservers
            if nameservers:
                for ns in nameservers:
                    ns_clean = ns.rstrip(".")
                    valid, error = self.validate_hostname(ns_clean)
                    if not valid:
                        errors.append(f"Nameserver '{ns}': {error}")
            
            # Validate ns_addresses
            if ns_addresses:
                for ns_name, ip in ns_addresses.items():
                    valid, error = self.validate_hostname(ns_name.rstrip("."))
                    if not valid:
                        errors.append(f"NS address key '{ns_name}': {error}")
                    
                    valid, error = self.validate_ip(ip)
                    if not valid:
                        errors.append(f"NS address value for '{ns_name}': {error}")
            
            # Check that in-zone nameservers have addresses
            if nameservers:
                zone_suffix = f".{zone_name.rstrip('.')}."
                for ns in nameservers:
                    ns_fqdn = ns if ns.endswith(".") else f"{ns}.{zone_name.rstrip('.')}."
                    
                    # Check if NS is in-zone
                    if ns_fqdn.endswith(zone_suffix) or ns_fqdn.rstrip(".") == zone_name.rstrip("."):
                        # Need glue record
                        has_address = False
                        if ns_addresses:
                            # Check various name formats
                            ns_base = ns.rstrip(".")
                            if ns_base.endswith(f".{zone_name.rstrip('.')}"):
                                # Extract the short name (e.g., "ns1" from "ns1.example.com")
                                ns_base = ns_base[:-len(f".{zone_name.rstrip('.')}")]
                            
                            for key in [ns, ns_fqdn, ns_fqdn.rstrip("."), ns_base]:
                                if key in ns_addresses:
                                    has_address = True
                                    break
                        
                        if not has_address:
                            errors.append(
                                f"In-zone nameserver '{ns}' requires an IP address in ns_addresses "
                                f"for zone validation to pass"
                            )
        
        return len(errors) == 0, errors
    
    # =========================================================================
    # BIND9 Tool Validation
    # =========================================================================
    
    async def check_zone_file(self, zone_name: str, zone_file: str) -> Tuple[bool, str]:
        """
        Validate zone file using named-checkzone
        Returns: (is_valid, output)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                self.checkzone_path, zone_name, zone_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            return process.returncode == 0, output.strip()
            
        except FileNotFoundError:
            return False, f"named-checkzone not found at {self.checkzone_path}"
        except Exception as e:
            return False, f"Error running named-checkzone: {e}"
    
    async def check_config(self, config_file: str = None) -> Tuple[bool, str]:
        """
        Validate BIND9 configuration using named-checkconf
        Returns: (is_valid, output)
        """
        try:
            args = [self.checkconf_path]
            if config_file:
                args.append(config_file)
            
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            return process.returncode == 0, output.strip()
            
        except FileNotFoundError:
            return False, f"named-checkconf not found at {self.checkconf_path}"
        except Exception as e:
            return False, f"Error running named-checkconf: {e}"
    
    async def check_bind9_status(self) -> Tuple[bool, str]:
        """
        Check if BIND9 is running and responsive
        Returns: (is_running, status_message)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                self.rndc_path, "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True, stdout.decode().strip()
            else:
                return False, stderr.decode().strip()
            
        except FileNotFoundError:
            return False, f"rndc not found at {self.rndc_path}"
        except Exception as e:
            return False, f"Error checking BIND9 status: {e}"
    
    # =========================================================================
    # Pre-flight Checks
    # =========================================================================
    
    async def preflight_check(self) -> Tuple[bool, List[str]]:
        """
        Run pre-flight checks before any operation
        Returns: (all_passed, list_of_issues)
        """
        issues = []
        
        # Check BIND9 is running
        is_running, status = await self.check_bind9_status()
        if not is_running:
            issues.append(f"BIND9 not running or not responding: {status}")
        
        # Check tools exist
        if not Path(self.checkzone_path).exists():
            issues.append(f"named-checkzone not found: {self.checkzone_path}")
        
        if not Path(self.checkconf_path).exists():
            issues.append(f"named-checkconf not found: {self.checkconf_path}")
        
        # Check config is valid
        is_valid, output = await self.check_config()
        if not is_valid:
            issues.append(f"BIND9 configuration invalid: {output}")
        
        return len(issues) == 0, issues
    
    async def validate_before_zone_create(
        self,
        zone_name: str,
        zone_type: str,
        soa_mname: str = None,
        soa_rname: str = None,
        nameservers: List[str] = None,
        ns_addresses: Dict[str, str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Complete validation before creating a zone
        Returns: (can_proceed, list_of_errors)
        """
        all_errors = []
        
        # Pre-flight checks
        passed, issues = await self.preflight_check()
        if not passed:
            all_errors.extend([f"Pre-flight: {i}" for i in issues])
        
        # Zone config validation
        valid, errors = self.validate_zone_config(
            zone_name=zone_name,
            zone_type=zone_type,
            soa_mname=soa_mname,
            soa_rname=soa_rname,
            nameservers=nameservers,
            ns_addresses=ns_addresses
        )
        if not valid:
            all_errors.extend(errors)
        
        return len(all_errors) == 0, all_errors
    
    async def validate_before_record_create(
        self,
        zone: str,
        name: str,
        record_type: str,
        data: str,
        ttl: int = 3600
    ) -> Tuple[bool, List[str]]:
        """
        Complete validation before creating a record
        Returns: (can_proceed, list_of_errors)
        """
        all_errors = []
        
        # Pre-flight checks
        passed, issues = await self.preflight_check()
        if not passed:
            all_errors.extend([f"Pre-flight: {i}" for i in issues])
        
        # Record validation
        valid, errors = self.validate_record(
            zone=zone,
            name=name,
            record_type=record_type,
            data=data,
            ttl=ttl
        )
        if not valid:
            all_errors.extend(errors)
        
        return len(all_errors) == 0, all_errors


# Singleton instance
_validation_service: Optional[ValidationService] = None


def get_validation_service() -> ValidationService:
    """Get validation service instance"""
    global _validation_service
    if _validation_service is None:
        _validation_service = ValidationService()
    return _validation_service

