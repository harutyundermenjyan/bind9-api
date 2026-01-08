"""
NSUpdate Service - Dynamic DNS Updates (RFC 2136)
Handles all record modifications via nsupdate
"""

import asyncio
import tempfile
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..config import settings
from ..models.records import RecordType, RecordClass


class NSUpdateError(Exception):
    """NSUpdate operation failed"""
    def __init__(self, message: str, output: str = None):
        self.message = message
        self.output = output
        super().__init__(message)


class NSUpdateService:
    """Service for dynamic DNS updates via nsupdate"""
    
    def __init__(self):
        self.nsupdate_path = settings.bind9_nsupdate_path
        self.timeout = settings.nsupdate_timeout
        self.server = "127.0.0.1"
        self.port = 53
        
        # TSIG key configuration
        # Prefer key file over inline key
        self.tsig_key_file = settings.tsig_key_file
        self.tsig_key_name = settings.tsig_key_name
        self.tsig_key_secret = settings.tsig_key_secret
        self.tsig_key_algorithm = settings.tsig_key_algorithm
    
    def _build_commands(
        self,
        zone: str,
        operations: List[Dict[str, Any]],
        server: Optional[str] = None,
        port: Optional[int] = None
    ) -> str:
        """Build nsupdate command file content"""
        commands = []
        
        # Server specification
        commands.append(f"server {server or self.server} {port or self.port}")
        
        # Zone specification
        commands.append(f"zone {zone}")
        
        # TSIG key if configured (only add inline key if NOT using key file)
        # When using -k keyfile, nsupdate loads the key from the file
        if self.tsig_key_name and self.tsig_key_secret and not self.tsig_key_file:
            commands.append(f"key {self.tsig_key_algorithm}:{self.tsig_key_name} {self.tsig_key_secret}")
        
        # Process operations
        for op in operations:
            action = op.get("action", "add")
            name = op.get("name")
            ttl = op.get("ttl", 3600)
            record_class = op.get("class", "IN")
            record_type = op.get("type")
            rdata = op.get("rdata", "")
            
            if action == "add":
                commands.append(f"update add {name} {ttl} {record_class} {record_type} {rdata}")
            elif action == "delete":
                if rdata:
                    commands.append(f"update delete {name} {record_class} {record_type} {rdata}")
                elif record_type:
                    commands.append(f"update delete {name} {record_class} {record_type}")
                else:
                    commands.append(f"update delete {name}")
            elif action == "replace":
                # Delete existing, then add new
                commands.append(f"update delete {name} {record_class} {record_type}")
                commands.append(f"update add {name} {ttl} {record_class} {record_type} {rdata}")
        
        # Send the update
        commands.append("send")
        
        return "\n".join(commands)
    
    async def _run_nsupdate(
        self,
        commands: str,
        key_file: Optional[str] = None
    ) -> tuple[bool, str, str]:
        """
        Run nsupdate with given commands
        Returns: (success, stdout, stderr)
        """
        # Write commands to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.nsupdate', delete=False) as f:
            f.write(commands)
            cmd_file = f.name
        
        try:
            cmd = [self.nsupdate_path]
            
            # Use configured key file, or override if specified
            actual_key_file = key_file or self.tsig_key_file
            if actual_key_file and Path(actual_key_file).exists():
                cmd.extend(["-k", actual_key_file])
            
            # Add command file
            cmd.extend(["-v", cmd_file])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return False, "", "Command timed out"
            
            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()
            
            return process.returncode == 0, stdout_str, stderr_str
            
        finally:
            # Clean up temp file
            Path(cmd_file).unlink(missing_ok=True)
    
    # =========================================================================
    # Record Operations
    # =========================================================================
    
    async def add_record(
        self,
        zone: str,
        name: str,
        record_type: str,
        rdata: str,
        ttl: int = 3600,
        record_class: str = "IN",
        server: Optional[str] = None
    ) -> bool:
        """Add a DNS record"""
        # Convert relative name to FQDN for nsupdate
        fqdn = self._make_fqdn(name, zone)
        
        commands = self._build_commands(
            zone=zone,
            operations=[{
                "action": "add",
                "name": fqdn,
                "type": record_type,
                "rdata": rdata,
                "ttl": ttl,
                "class": record_class
            }],
            server=server
        )
        
        success, stdout, stderr = await self._run_nsupdate(commands)
        
        if not success:
            raise NSUpdateError(f"Failed to add record: {stderr}", stderr)
        
        return True
    
    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: Optional[str] = None,
        rdata: Optional[str] = None,
        record_class: str = "IN",
        server: Optional[str] = None
    ) -> bool:
        """Delete DNS record(s)"""
        # Convert relative name to FQDN for nsupdate
        fqdn = self._make_fqdn(name, zone)
        
        op = {
            "action": "delete",
            "name": fqdn,
            "class": record_class
        }
        if record_type:
            op["type"] = record_type
        if rdata:
            op["rdata"] = rdata
        
        commands = self._build_commands(
            zone=zone,
            operations=[op],
            server=server
        )
        
        success, stdout, stderr = await self._run_nsupdate(commands)
        
        if not success:
            raise NSUpdateError(f"Failed to delete record: {stderr}", stderr)
        
        return True
    
    async def update_record(
        self,
        zone: str,
        name: str,
        record_type: str,
        old_rdata: str,
        new_rdata: str,
        ttl: int = 3600,
        record_class: str = "IN",
        server: Optional[str] = None
    ) -> bool:
        """Update a DNS record (delete old, add new)"""
        # Convert relative name to FQDN for nsupdate
        fqdn = self._make_fqdn(name, zone)
        
        commands = self._build_commands(
            zone=zone,
            operations=[
                {
                    "action": "delete",
                    "name": fqdn,
                    "type": record_type,
                    "rdata": old_rdata,
                    "class": record_class
                },
                {
                    "action": "add",
                    "name": fqdn,
                    "type": record_type,
                    "rdata": new_rdata,
                    "ttl": ttl,
                    "class": record_class
                }
            ],
            server=server
        )
        
        success, stdout, stderr = await self._run_nsupdate(commands)
        
        if not success:
            raise NSUpdateError(f"Failed to update record: {stderr}", stderr)
        
        return True
    
    async def replace_records(
        self,
        zone: str,
        name: str,
        record_type: str,
        rdata: str,
        ttl: int = 3600,
        record_class: str = "IN",
        server: Optional[str] = None
    ) -> bool:
        """Replace all records of a type with new record"""
        # Convert relative name to FQDN for nsupdate
        fqdn = self._make_fqdn(name, zone)
        
        commands = self._build_commands(
            zone=zone,
            operations=[{
                "action": "replace",
                "name": fqdn,
                "type": record_type,
                "rdata": rdata,
                "ttl": ttl,
                "class": record_class
            }],
            server=server
        )
        
        success, stdout, stderr = await self._run_nsupdate(commands)
        
        if not success:
            raise NSUpdateError(f"Failed to replace records: {stderr}", stderr)
        
        return True
    
    # =========================================================================
    # Bulk Operations
    # =========================================================================
    
    async def bulk_update(
        self,
        zone: str,
        operations: List[Dict[str, Any]],
        server: Optional[str] = None
    ) -> tuple[int, int, List[str]]:
        """
        Perform bulk record operations
        Returns: (successful_count, failed_count, error_messages)
        """
        commands = self._build_commands(
            zone=zone,
            operations=operations,
            server=server
        )
        
        success, stdout, stderr = await self._run_nsupdate(commands)
        
        if success:
            return len(operations), 0, []
        else:
            # Try individual operations to identify failures
            successful = 0
            failed = 0
            errors = []
            
            for op in operations:
                single_commands = self._build_commands(zone=zone, operations=[op], server=server)
                op_success, _, op_stderr = await self._run_nsupdate(single_commands)
                
                if op_success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"{op.get('name')}: {op_stderr}")
            
            return successful, failed, errors
    
    # =========================================================================
    # Convenience Methods for Specific Record Types
    # =========================================================================
    
    async def add_a_record(
        self, zone: str, name: str, address: str, ttl: int = 3600
    ) -> bool:
        """Add an A record"""
        return await self.add_record(zone, name, "A", address, ttl)
    
    async def add_aaaa_record(
        self, zone: str, name: str, address: str, ttl: int = 3600
    ) -> bool:
        """Add an AAAA record"""
        return await self.add_record(zone, name, "AAAA", address, ttl)
    
    async def add_cname_record(
        self, zone: str, name: str, target: str, ttl: int = 3600
    ) -> bool:
        """Add a CNAME record"""
        return await self.add_record(zone, name, "CNAME", target, ttl)
    
    async def add_mx_record(
        self, zone: str, name: str, preference: int, exchange: str, ttl: int = 3600
    ) -> bool:
        """Add an MX record"""
        return await self.add_record(zone, name, "MX", f"{preference} {exchange}", ttl)
    
    async def add_txt_record(
        self, zone: str, name: str, text: str, ttl: int = 3600
    ) -> bool:
        """Add a TXT record"""
        # Escape and quote text properly
        if not text.startswith('"'):
            text = f'"{text}"'
        return await self.add_record(zone, name, "TXT", text, ttl)
    
    async def add_srv_record(
        self,
        zone: str,
        name: str,
        priority: int,
        weight: int,
        port: int,
        target: str,
        ttl: int = 3600
    ) -> bool:
        """Add an SRV record"""
        rdata = f"{priority} {weight} {port} {target}"
        return await self.add_record(zone, name, "SRV", rdata, ttl)
    
    async def add_caa_record(
        self,
        zone: str,
        name: str,
        flags: int,
        tag: str,
        value: str,
        ttl: int = 3600
    ) -> bool:
        """Add a CAA record"""
        rdata = f'{flags} {tag} "{value}"'
        return await self.add_record(zone, name, "CAA", rdata, ttl)
    
    async def add_ns_record(
        self, zone: str, name: str, nameserver: str, ttl: int = 3600
    ) -> bool:
        """Add an NS record"""
        return await self.add_record(zone, name, "NS", nameserver, ttl)
    
    async def add_ptr_record(
        self, zone: str, name: str, ptrdname: str, ttl: int = 3600
    ) -> bool:
        """Add a PTR record"""
        return await self.add_record(zone, name, "PTR", ptrdname, ttl)
    
    async def add_tlsa_record(
        self,
        zone: str,
        name: str,
        usage: int,
        selector: int,
        matching_type: int,
        certificate_data: str,
        ttl: int = 3600
    ) -> bool:
        """Add a TLSA record"""
        rdata = f"{usage} {selector} {matching_type} {certificate_data}"
        return await self.add_record(zone, name, "TLSA", rdata, ttl)
    
    async def add_sshfp_record(
        self,
        zone: str,
        name: str,
        algorithm: int,
        fingerprint_type: int,
        fingerprint: str,
        ttl: int = 3600
    ) -> bool:
        """Add an SSHFP record"""
        rdata = f"{algorithm} {fingerprint_type} {fingerprint}"
        return await self.add_record(zone, name, "SSHFP", rdata, ttl)
    
    async def add_naptr_record(
        self,
        zone: str,
        name: str,
        order: int,
        preference: int,
        flags: str,
        service: str,
        regexp: str,
        replacement: str,
        ttl: int = 3600
    ) -> bool:
        """Add a NAPTR record"""
        rdata = f'{order} {preference} "{flags}" "{service}" "{regexp}" {replacement}'
        return await self.add_record(zone, name, "NAPTR", rdata, ttl)
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _make_fqdn(self, name: str, zone: str) -> str:
        """Convert a record name to FQDN for nsupdate"""
        # Handle apex record
        if name == "@":
            return f"{zone}."
        
        # Already an FQDN (ends with dot)
        if name.endswith("."):
            return name
        
        # Already includes zone name
        zone_clean = zone.rstrip(".")
        if name.endswith(f".{zone_clean}"):
            return f"{name}."
        
        # Relative name - append zone
        return f"{name}.{zone_clean}."
    
    def format_rdata(self, record_type: str, data: Dict[str, Any]) -> str:
        """Format record data into RDATA string"""
        rtype = record_type.upper()
        
        if rtype == "A":
            return data.get("address", "")
        elif rtype == "AAAA":
            return data.get("address", "")
        elif rtype == "CNAME":
            return data.get("target", "")
        elif rtype == "MX":
            return f"{data.get('preference', 10)} {data.get('exchange', '')}"
        elif rtype == "TXT":
            text = data.get("text", "")
            if isinstance(text, list):
                return " ".join(f'"{t}"' for t in text)
            return f'"{text}"' if not text.startswith('"') else text
        elif rtype == "SRV":
            return f"{data.get('priority', 0)} {data.get('weight', 0)} {data.get('port', 0)} {data.get('target', '')}"
        elif rtype == "CAA":
            return f"{data.get('flags', 0)} {data.get('tag', 'issue')} \"{data.get('value', '')}\""
        elif rtype == "NS":
            return data.get("nameserver", "")
        elif rtype == "PTR":
            return data.get("ptrdname", "")
        elif rtype == "SOA":
            return f"{data.get('mname', '')} {data.get('rname', '')} {data.get('serial', 1)} {data.get('refresh', 86400)} {data.get('retry', 7200)} {data.get('expire', 3600000)} {data.get('minimum', 3600)}"
        elif rtype == "TLSA":
            return f"{data.get('usage', 0)} {data.get('selector', 0)} {data.get('matching_type', 0)} {data.get('certificate_data', '')}"
        elif rtype == "SSHFP":
            return f"{data.get('algorithm', 0)} {data.get('fingerprint_type', 0)} {data.get('fingerprint', '')}"
        elif rtype == "NAPTR":
            return f"{data.get('order', 0)} {data.get('preference', 0)} \"{data.get('flags', '')}\" \"{data.get('service', '')}\" \"{data.get('regexp', '')}\" {data.get('replacement', '.')}"
        elif rtype == "DNAME":
            return data.get("target", "")
        elif rtype == "LOC":
            return f"{data.get('latitude', '')} {data.get('longitude', '')} {data.get('altitude', 0)}m {data.get('size', 1)}m {data.get('horizontal_precision', 10000)}m {data.get('vertical_precision', 10)}m"
        elif rtype == "HINFO":
            return f'"{data.get("cpu", "")}" "{data.get("os", "")}"'
        elif rtype == "RP":
            return f"{data.get('mbox', '.')} {data.get('txtdname', '.')}"
        elif rtype == "HTTPS":
            return f"{data.get('priority', 0)} {data.get('target', '.')} {data.get('params', '')}"
        elif rtype == "SVCB":
            return f"{data.get('priority', 0)} {data.get('target', '.')} {data.get('params', '')}"
        else:
            # Generic: return rdata directly
            return data.get("rdata", "")
    
    def is_available(self) -> bool:
        """Check if nsupdate is available"""
        import shutil
        return shutil.which(self.nsupdate_path) is not None

