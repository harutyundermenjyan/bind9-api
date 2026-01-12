"""
Zone File Service - Zone file parsing and manipulation
Handles reading and writing BIND9 zone files
"""

import re
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
import dns.zone
import dns.rdatatype
import dns.name
import dns.rdata

from ..config import settings
from ..models.zones import ZoneType, ZoneStatus
from ..models.records import RecordType


class ZoneFileError(Exception):
    """Zone file operation failed"""
    pass


class ZoneFileService:
    """Service for zone file operations"""
    
    def __init__(self):
        self.zones_path = Path(settings.bind9_zones_path)
        self.config_path = Path(settings.bind9_config_path)
        self.checkzone_path = settings.bind9_named_checkzone
        self.checkconf_path = settings.bind9_named_checkconf
    
    # =========================================================================
    # Zone File Reading
    # =========================================================================
    
    async def read_zone(self, zone_name: str, zone_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Read and parse a zone file
        Returns zone data as dictionary
        """
        if zone_file:
            file_path = Path(zone_file)
        else:
            file_path = self.zones_path / f"db.{zone_name}"
        
        if not file_path.exists():
            raise ZoneFileError(f"Zone file not found: {file_path}")
        
        try:
            # Use dnspython to parse zone file
            zone = dns.zone.from_file(str(file_path), zone_name, relativize=False)
            
            records = []
            soa_record = None
            
            for name, node in zone.nodes.items():
                name_str = str(name)
                if name_str.endswith("."):
                    name_str = name_str[:-1]
                
                for rdataset in node.rdatasets:
                    rtype = dns.rdatatype.to_text(rdataset.rdtype)
                    ttl = rdataset.ttl
                    
                    for rdata in rdataset:
                        record_data = {
                            "name": name_str,
                            "ttl": ttl,
                            "class": "IN",
                            "type": rtype,
                            "rdata": str(rdata)
                        }
                        
                        if rtype == "SOA":
                            soa_record = {
                                "mname": str(rdata.mname),
                                "rname": str(rdata.rname),
                                "serial": rdata.serial,
                                "refresh": rdata.refresh,
                                "retry": rdata.retry,
                                "expire": rdata.expire,
                                "minimum": rdata.minimum
                            }
                            record_data["soa"] = soa_record
                        
                        records.append(record_data)
            
            return {
                "zone": zone_name,
                "file": str(file_path),
                "soa": soa_record,
                "records": records,
                "record_count": len(records)
            }
            
        except dns.zone.NoSOA:
            raise ZoneFileError(f"Zone file has no SOA record: {file_path}")
        except dns.zone.NoNS:
            raise ZoneFileError(f"Zone file has no NS records: {file_path}")
        except Exception as e:
            raise ZoneFileError(f"Failed to parse zone file: {e}")
    
    async def get_records(
        self,
        zone_name: str,
        zone_file: Optional[str] = None,
        record_type: Optional[str] = None,
        name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get records from zone file with optional filtering"""
        zone_data = await self.read_zone(zone_name, zone_file)
        records = zone_data.get("records", [])
        
        if record_type:
            records = [r for r in records if r["type"].upper() == record_type.upper()]
        
        if name:
            records = [r for r in records if r["name"] == name or r["name"].startswith(f"{name}.")]
        
        return records
    
    async def get_soa(self, zone_name: str, zone_file: Optional[str] = None) -> Dict[str, Any]:
        """Get SOA record from zone"""
        zone_data = await self.read_zone(zone_name, zone_file)
        return zone_data.get("soa", {})
    
    async def get_serial(self, zone_name: str, zone_file: Optional[str] = None) -> int:
        """Get current serial number"""
        soa = await self.get_soa(zone_name, zone_file)
        return soa.get("serial", 0)
    
    # =========================================================================
    # Zone File Writing
    # =========================================================================
    
    async def create_zone_file(
        self,
        zone_name: str,
        zone_file: Optional[str] = None,
        soa_mname: str = "ns1",
        soa_rname: str = "hostmaster",
        soa_refresh: int = 86400,
        soa_retry: int = 7200,
        soa_expire: int = 3600000,
        soa_minimum: int = 3600,
        default_ttl: int = 3600,
        nameservers: List[str] = None,
        ns_addresses: Dict[str, str] = None
    ) -> str:
        """
        Create a new zone file
        
        Args:
            zone_name: The zone name (e.g., example.com)
            zone_file: Optional path to zone file
            soa_mname: Primary nameserver for SOA
            soa_rname: Responsible person email for SOA
            soa_refresh: SOA refresh interval
            soa_retry: SOA retry interval
            soa_expire: SOA expire time
            soa_minimum: SOA minimum/negative TTL
            default_ttl: Default TTL for records
            nameservers: List of nameserver names
            ns_addresses: Dict of nameserver name -> IP address for glue records
        """
        if zone_file:
            file_path = Path(zone_file)
        else:
            file_path = self.zones_path / f"db.{zone_name}"
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate serial (YYYYMMDDNN format)
        serial = int(datetime.utcnow().strftime("%Y%m%d01"))
        
        # Normalize names - handle FQDN (with trailing dot) properly
        # soa_mname handling:
        # - "ns1" (simple) -> "ns1.zone_name."
        # - "ns1.zone_name" (FQDN without dot) -> "ns1.zone_name."
        # - "ns1.zone_name." (FQDN with dot) -> "ns1.zone_name."
        # - "ns1.other.com" (external FQDN without dot) -> "ns1.other.com."
        if soa_mname.endswith("."):
            # Already FQDN with trailing dot, keep as is
            pass
        elif "." in soa_mname:
            # Contains dots - likely already a FQDN, just add trailing dot
            soa_mname = f"{soa_mname}."
        else:
            # Simple name like "ns1" - append zone name
            soa_mname = f"{soa_mname}.{zone_name}."
        
        # soa_rname handling (same logic, but also handle @ -> . conversion)
        soa_rname = soa_rname.replace('@', '.')
        if soa_rname.endswith("."):
            # Already FQDN with trailing dot, keep as is
            pass
        elif "." in soa_rname:
            # Contains dots - likely already a FQDN, just add trailing dot
            soa_rname = f"{soa_rname}."
        else:
            # Simple name like "hostmaster" - append zone name
            soa_rname = f"{soa_rname}.{zone_name}."
        
        # Build zone file content
        lines = [
            f"; Zone file for {zone_name}",
            f"; Generated by BIND9 REST API on {datetime.utcnow().isoformat()}",
            "",
            f"$TTL {default_ttl}",
            f"$ORIGIN {zone_name}.",
            "",
            f"@    IN    SOA    {soa_mname} {soa_rname} (",
            f"                  {serial}    ; Serial",
            f"                  {soa_refresh}        ; Refresh",
            f"                  {soa_retry}         ; Retry",
            f"                  {soa_expire}      ; Expire",
            f"                  {soa_minimum} )      ; Negative TTL",
            ""
        ]
        
        # Determine nameservers to use
        ns_list = nameservers if nameservers else [soa_mname]
        
        # Add NS records
        for ns in ns_list:
            ns_fqdn = ns if ns.endswith(".") else f"{ns}."
            lines.append(f"@    IN    NS    {ns_fqdn}")
        
        lines.append("")
        
        # Add glue A records for in-zone nameservers
        zone_suffix = f".{zone_name}."
        glue_records = []
        
        for ns in ns_list:
            # Make FQDN - just add trailing dot if missing
            ns_fqdn = ns if ns.endswith(".") else f"{ns}."
            
            # Check if this NS is in-zone (ends with zone name)
            if ns_fqdn.endswith(zone_suffix) or ns_fqdn == f"{zone_name}.":
                # Get the relative name (without zone suffix)
                if ns_fqdn.endswith(zone_suffix):
                    relative_name = ns_fqdn[:-len(zone_suffix)]
                else:
                    relative_name = "@"
                
                # Look for IP in ns_addresses
                ip_address = None
                if ns_addresses:
                    # Try to find by various name formats
                    for key in [ns, ns_fqdn, ns_fqdn.rstrip("."), relative_name]:
                        if key in ns_addresses:
                            ip_address = ns_addresses[key]
                            break
                
                if ip_address:
                    glue_records.append(f"{relative_name}    IN    A    {ip_address}")
        
        if glue_records:
            lines.append("; Glue records for in-zone nameservers")
            lines.extend(glue_records)
            lines.append("")
        
        content = "\n".join(lines)
        
        # Write file
        file_path.write_text(content)
        
        return str(file_path)
    
    async def write_zone_file(
        self,
        zone_name: str,
        records: List[Dict[str, Any]],
        zone_file: Optional[str] = None,
        default_ttl: int = 3600
    ) -> str:
        """Write complete zone file from records"""
        if zone_file:
            file_path = Path(zone_file)
        else:
            file_path = self.zones_path / f"db.{zone_name}"
        
        lines = [
            f"; Zone file for {zone_name}",
            f"; Generated by BIND9 REST API on {datetime.utcnow().isoformat()}",
            "",
            f"$TTL {default_ttl}",
            f"$ORIGIN {zone_name}.",
            ""
        ]
        
        # Sort records: SOA first, then NS, then others
        def sort_key(r):
            rtype = r.get("type", "").upper()
            if rtype == "SOA":
                return (0, r.get("name", ""))
            elif rtype == "NS":
                return (1, r.get("name", ""))
            else:
                return (2, r.get("name", ""), rtype)
        
        sorted_records = sorted(records, key=sort_key)
        
        for record in sorted_records:
            name = record.get("name", "@")
            ttl = record.get("ttl", "")
            rclass = record.get("class", "IN")
            rtype = record.get("type", "")
            rdata = record.get("rdata", "")
            
            if ttl:
                lines.append(f"{name}\t{ttl}\t{rclass}\t{rtype}\t{rdata}")
            else:
                lines.append(f"{name}\t{rclass}\t{rtype}\t{rdata}")
        
        content = "\n".join(lines) + "\n"
        
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        
        return str(file_path)
    
    async def increment_serial(
        self,
        zone_name: str,
        zone_file: Optional[str] = None
    ) -> int:
        """Increment zone serial number"""
        if zone_file:
            file_path = Path(zone_file)
        else:
            file_path = self.zones_path / f"db.{zone_name}"
        
        if not file_path.exists():
            raise ZoneFileError(f"Zone file not found: {file_path}")
        
        content = file_path.read_text()
        
        # Find and update serial in SOA record
        # Pattern matches serial number in SOA record
        serial_pattern = r"(\d{10})\s*;\s*[Ss]erial"
        
        match = re.search(serial_pattern, content)
        if match:
            old_serial = int(match.group(1))
            
            # Calculate new serial
            today = int(datetime.utcnow().strftime("%Y%m%d"))
            if old_serial // 100 == today:
                # Same day, increment sequence
                new_serial = old_serial + 1
            else:
                # New day, reset sequence
                new_serial = today * 100 + 1
            
            # Replace serial
            new_content = re.sub(
                serial_pattern,
                f"{new_serial}    ; Serial",
                content
            )
            
            file_path.write_text(new_content)
            return new_serial
        else:
            raise ZoneFileError("Could not find serial number in zone file")
    
    # =========================================================================
    # Zone Validation
    # =========================================================================
    
    async def check_zone(self, zone_name: str, zone_file: str) -> Tuple[bool, str]:
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
            return False, str(e)
    
    async def check_config(self, config_file: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate BIND configuration using named-checkconf
        Returns: (is_valid, output)
        """
        try:
            cmd = [self.checkconf_path]
            if config_file:
                cmd.append(config_file)
            else:
                cmd.append(str(self.config_path))
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            return process.returncode == 0, output.strip()
            
        except FileNotFoundError:
            return False, f"named-checkconf not found at {self.checkconf_path}"
        except Exception as e:
            return False, str(e)
    
    # =========================================================================
    # Zone Import/Export
    # =========================================================================
    
    async def export_zone(self, zone_name: str, zone_file: Optional[str] = None) -> str:
        """Export zone to BIND zone file format"""
        zone_data = await self.read_zone(zone_name, zone_file)
        
        lines = [
            f"; Exported zone: {zone_name}",
            f"; Export time: {datetime.utcnow().isoformat()}",
            "",
            f"$ORIGIN {zone_name}.",
            ""
        ]
        
        for record in zone_data.get("records", []):
            name = record.get("name", "@")
            ttl = record.get("ttl", "")
            rclass = record.get("class", "IN")
            rtype = record.get("type", "")
            rdata = record.get("rdata", "")
            
            lines.append(f"{name}\t{ttl}\t{rclass}\t{rtype}\t{rdata}")
        
        return "\n".join(lines)
    
    async def import_zone(
        self,
        zone_name: str,
        content: str,
        zone_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Import zone from zone file content"""
        if zone_file:
            file_path = Path(zone_file)
        else:
            file_path = self.zones_path / f"db.{zone_name}"
        
        # Write content to file
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        
        # Validate
        is_valid, validation_output = await self.check_zone(zone_name, str(file_path))
        
        if not is_valid:
            # Remove invalid file
            file_path.unlink()
            raise ZoneFileError(f"Invalid zone file: {validation_output}")
        
        # Read back and return
        return await self.read_zone(zone_name, str(file_path))
    
    # =========================================================================
    # Configuration Management
    # =========================================================================
    
    async def list_configured_zones(self) -> List[Dict[str, Any]]:
        """List zones from named.conf"""
        zones = []
        
        if not self.config_path.exists():
            return zones
        
        content = self.config_path.read_text()
        
        # Parse zone definitions
        # This is a simplified parser - real implementation would need to handle includes
        zone_pattern = r'zone\s+"([^"]+)"\s*(?:IN\s+)?{([^}]+)}'
        
        for match in re.finditer(zone_pattern, content, re.MULTILINE | re.DOTALL):
            zone_name = match.group(1)
            zone_config = match.group(2)
            
            zone_info = {"name": zone_name}
            
            # Extract type
            type_match = re.search(r'type\s+(\w+)', zone_config)
            if type_match:
                zone_info["type"] = type_match.group(1)
            
            # Extract file
            file_match = re.search(r'file\s+"([^"]+)"', zone_config)
            if file_match:
                zone_info["file"] = file_match.group(1)
            
            zones.append(zone_info)
        
        return zones
    
    async def get_zone_file_path(self, zone_name: str) -> Optional[str]:
        """Get zone file path from configuration"""
        zones = await self.list_configured_zones()
        
        for zone in zones:
            if zone.get("name") == zone_name:
                return zone.get("file")
        
        # Default path
        default_path = self.zones_path / f"db.{zone_name}"
        if default_path.exists():
            return str(default_path)
        
        return None
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def normalize_name(self, name: str, zone: str) -> str:
        """Normalize record name relative to zone"""
        if name == "@" or name == zone or name == f"{zone}.":
            return "@"
        
        zone_suffix = f".{zone}"
        if name.endswith(zone_suffix):
            return name[:-len(zone_suffix)]
        if name.endswith(f"{zone_suffix}."):
            return name[:-len(zone_suffix)-1]
        
        return name
    
    def denormalize_name(self, name: str, zone: str) -> str:
        """Convert relative name to FQDN"""
        if name == "@":
            return f"{zone}."
        
        if name.endswith("."):
            return name
        
        return f"{name}.{zone}."

