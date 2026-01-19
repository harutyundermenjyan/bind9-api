"""
RNDC Service - Remote Name Daemon Control
Handles all RNDC commands to control BIND9 server
"""

import asyncio
import shutil
import re
from datetime import datetime
from typing import Optional, List, Tuple
from pathlib import Path

from ..config import settings
from ..models.server import (
    RNDCCommand, ServerCommand, ServerCommandResult, 
    ServerStatus, ServerInfo, ZoneStatus_Detail
)
from ..models.zones import ZoneStatus


class RNDCError(Exception):
    """RNDC operation failed"""
    def __init__(self, message: str, output: str = None, return_code: int = None):
        self.message = message
        self.output = output
        self.return_code = return_code
        super().__init__(message)


class RNDCService:
    """Service for RNDC operations"""
    
    def __init__(self):
        self.rndc_path = settings.bind9_rndc_path
        self.rndc_key = settings.bind9_rndc_key
        self.timeout = settings.rndc_timeout
    
    def _get_rndc_cmd(self) -> List[str]:
        """Get base rndc command with key file"""
        cmd = [self.rndc_path]
        if self.rndc_key and Path(self.rndc_key).exists():
            cmd.extend(["-k", self.rndc_key])
        return cmd
    
    async def _run_command(
        self, 
        *args: str,
        timeout: Optional[int] = None
    ) -> Tuple[bool, str, str, float]:
        """
        Run an rndc command
        Returns: (success, stdout, stderr, duration_ms)
        """
        cmd = self._get_rndc_cmd() + list(args)
        start_time = datetime.utcnow()
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout or self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                duration = (datetime.utcnow() - start_time).total_seconds() * 1000
                return False, "", "Command timed out", duration
            
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()
            
            success = process.returncode == 0
            return success, stdout_str, stderr_str, duration
            
        except FileNotFoundError:
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            return False, "", f"rndc not found at {self.rndc_path}", duration
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            return False, "", str(e), duration
    
    async def execute(self, command: ServerCommand) -> ServerCommandResult:
        """Execute an RNDC command"""
        args = [command.command.value]
        
        # Add zone if specified
        if command.zone:
            args.append(command.zone)
        
        # Add view if specified
        if command.view:
            args.extend(["in", command.view])
        
        # Add additional arguments
        args.extend(command.args)
        
        success, stdout, stderr, duration = await self._run_command(*args)
        
        return ServerCommandResult(
            command=" ".join(args),
            success=success,
            output=stdout if stdout else None,
            error=stderr if not success and stderr else None,
            duration_ms=duration
        )
    
    # =========================================================================
    # Server Status Commands
    # =========================================================================
    
    async def status(self) -> ServerStatus:
        """Get server status"""
        success, stdout, stderr, _ = await self._run_command("status")
        
        if not success:
            raise RNDCError(f"Failed to get status: {stderr}")
        
        # Parse status output
        info = self._parse_status(stdout)
        
        return ServerStatus(
            info=info,
            raw_status=stdout
        )
    
    def _parse_status(self, output: str) -> ServerInfo:
        """Parse rndc status output"""
        info = ServerInfo(
            version="unknown",
            running=True
        )
        
        for line in output.split("\n"):
            line = line.strip()
            
            if line.startswith("version:"):
                info.version = line.split(":", 1)[1].strip()
            elif line.startswith("running on"):
                info.running = True
            elif "uptime" in line.lower():
                # Try to extract uptime
                match = re.search(r"(\d+)", line)
                if match:
                    info.uptime = float(match.group(1))
            elif line.startswith("number of zones:"):
                pass  # Could extract zone count
        
        return info
    
    async def version(self) -> str:
        """Get BIND9 version"""
        success, stdout, stderr, _ = await self._run_command("status")
        
        if not success:
            raise RNDCError(f"Failed to get version: {stderr}")
        
        for line in stdout.split("\n"):
            if line.startswith("version:"):
                return line.split(":", 1)[1].strip()
        
        return "unknown"
    
    # =========================================================================
    # Configuration Commands
    # =========================================================================
    
    async def reload(self, zone: Optional[str] = None) -> ServerCommandResult:
        """Reload server or specific zone"""
        if zone:
            return await self.execute(ServerCommand(
                command=RNDCCommand.RELOAD,
                zone=zone
            ))
        return await self.execute(ServerCommand(command=RNDCCommand.RELOAD))
    
    async def reconfig(self) -> ServerCommandResult:
        """Reload configuration file"""
        return await self.execute(ServerCommand(command=RNDCCommand.RECONFIG))
    
    # =========================================================================
    # Cache Commands
    # =========================================================================
    
    async def flush(self, view: Optional[str] = None) -> ServerCommandResult:
        """Flush all cache"""
        cmd = ServerCommand(command=RNDCCommand.FLUSH, view=view)
        return await self.execute(cmd)
    
    async def flushname(self, name: str, view: Optional[str] = None) -> ServerCommandResult:
        """Flush specific name from cache"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.FLUSHNAME,
            args=[name],
            view=view
        ))
    
    async def flushtree(self, name: str, view: Optional[str] = None) -> ServerCommandResult:
        """Flush entire tree from cache"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.FLUSHTREE,
            args=[name],
            view=view
        ))
    
    # =========================================================================
    # Zone Management Commands
    # =========================================================================
    
    async def freeze(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Freeze zone for manual editing"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.FREEZE,
            zone=zone,
            view=view
        ))
    
    async def thaw(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Thaw frozen zone"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.THAW,
            zone=zone,
            view=view
        ))
    
    async def sync(self, zone: str, clean: bool = False, view: Optional[str] = None) -> ServerCommandResult:
        """Sync zone to disk"""
        args = []
        if clean:
            args.append("-clean")
        return await self.execute(ServerCommand(
            command=RNDCCommand.SYNC,
            zone=zone,
            args=args,
            view=view
        ))
    
    async def notify(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Send NOTIFY to slaves"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.NOTIFY,
            zone=zone,
            view=view
        ))
    
    async def retransfer(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Force zone retransfer (slave zones)"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.RETRANSFER,
            zone=zone,
            view=view
        ))
    
    async def refresh(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Schedule zone refresh"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.REFRESH,
            zone=zone,
            view=view
        ))
    
    async def zonestatus(self, zone: str, view: Optional[str] = None) -> ZoneStatus_Detail:
        """Get detailed zone status"""
        result = await self.execute(ServerCommand(
            command=RNDCCommand.ZONESTATUS,
            zone=zone,
            view=view
        ))
        
        if not result.success:
            raise RNDCError(f"Failed to get zone status: {result.error}")
        
        return self._parse_zonestatus(zone, result.output)
    
    def _parse_zonestatus(self, zone: str, output: str) -> ZoneStatus_Detail:
        """Parse rndc zonestatus output"""
        status = ZoneStatus_Detail(
            name=zone,
            type="unknown",
            raw_output=output
        )
        
        for line in output.split("\n"):
            line = line.strip()
            
            if line.startswith("name:"):
                status.name = line.split(":", 1)[1].strip()
            elif line.startswith("type:"):
                status.type = line.split(":", 1)[1].strip()
            elif line.startswith("serial:"):
                try:
                    status.serial = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("loaded:"):
                status.loaded = "yes" in line.lower()
            elif "dynamic:" in line.lower():
                status.dynamic = "yes" in line.lower()
            elif "frozen:" in line.lower():
                status.frozen = "yes" in line.lower()
            elif "secure:" in line.lower():
                status.secure = "yes" in line.lower()
            elif "inline signing:" in line.lower():
                status.inline_signing = "yes" in line.lower()
            elif "key maintenance:" in line.lower():
                status.key_maintenance = "yes" in line.lower()
            elif line.startswith("expires:"):
                status.expires = line.split(":", 1)[1].strip()
            elif line.startswith("refresh:"):
                status.refresh = line.split(":", 1)[1].strip()
            elif line.startswith("next refresh:"):
                status.next_refresh = line.split(":", 2)[-1].strip()
            elif line.startswith("next key event:"):
                status.next_key_event = line.split(":", 2)[-1].strip()
        
        return status
    
    async def addzone(
        self, 
        zone: str, 
        zone_type: str,
        file: Optional[str] = None,
        masters: Optional[List[str]] = None,
        allow_query: Optional[List[str]] = None,
        allow_update: Optional[List[str]] = None,
        allow_transfer: Optional[List[str]] = None,
        view: Optional[str] = None
    ) -> ServerCommandResult:
        """
        Add a new zone dynamically using rndc addzone.
        
        Syntax: rndc addzone zone_name '{ type master; file "path"; allow-query { ... }; allow-update { ... }; };'
        """
        # Build zone configuration block (without the zone name)
        config_parts = ["{ "]
        config_parts.append(f'type {zone_type};')
        
        if file:
            config_parts.append(f' file "{file}";')
        
        if masters:
            masters_str = "; ".join(masters)
            config_parts.append(f' masters {{ {masters_str}; }};')
        
        if allow_query:
            # Format: allow-query { any; }; or allow-query { internal; };
            query_list = "; ".join(allow_query)
            config_parts.append(f' allow-query {{ {query_list}; }};')
        
        if allow_update:
            # Format: allow-update { key "ddns-key"; };
            update_list = "; ".join(allow_update)
            config_parts.append(f' allow-update {{ {update_list}; }};')
        
        if allow_transfer:
            transfer_list = "; ".join(allow_transfer)
            config_parts.append(f' allow-transfer {{ {transfer_list}; }};')
        
        config_parts.append(" };")
        config = "".join(config_parts)
        
        # rndc addzone expects: zone_name '{ config }'
        # We pass zone name and config as separate args
        args = [zone, config]
        if view:
            args.extend(["in", view])
        
        # Execute directly without using ServerCommand since addzone has special syntax
        success, stdout, stderr, duration = await self._run_command("addzone", *args)
        
        return ServerCommandResult(
            command=f"addzone {zone} '{config}'",
            success=success,
            output=stdout if stdout else None,
            error=stderr if not success and stderr else None,
            duration_ms=duration
        )
    
    async def delzone(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Delete a zone dynamically"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.DELZONE,
            zone=zone,
            view=view
        ))
    
    async def modzone(
        self,
        zone: str,
        zone_type: str,
        file: Optional[str] = None,
        masters: Optional[List[str]] = None,
        view: Optional[str] = None
    ) -> ServerCommandResult:
        """Modify zone configuration"""
        # Similar to addzone
        config_parts = [f'zone "{zone}"', "{"]
        config_parts.append(f'    type {zone_type};')
        
        if file:
            config_parts.append(f'    file "{file}";')
        
        if masters:
            masters_str = "; ".join(masters)
            config_parts.append(f'    masters {{ {masters_str}; }};')
        
        config_parts.append("};")
        config = " ".join(config_parts)
        
        return await self.execute(ServerCommand(
            command=RNDCCommand.MODZONE,
            zone=zone,
            args=[config],
            view=view
        ))
    
    async def showzone(self, zone: str, view: Optional[str] = None) -> str:
        """Show zone configuration"""
        result = await self.execute(ServerCommand(
            command=RNDCCommand.SHOWZONE,
            zone=zone,
            view=view
        ))
        
        if not result.success:
            raise RNDCError(f"Failed to show zone: {result.error}")
        
        return result.output
    
    # =========================================================================
    # DNSSEC Commands
    # =========================================================================
    
    async def sign(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Sign zone"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.SIGN,
            zone=zone,
            view=view
        ))
    
    async def loadkeys(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Load DNSSEC keys for zone"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.LOADKEYS,
            zone=zone,
            view=view
        ))
    
    async def signing(
        self, 
        zone: str, 
        action: str = "-list",
        view: Optional[str] = None
    ) -> ServerCommandResult:
        """Control signing process"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.SIGNING,
            zone=zone,
            args=[action],
            view=view
        ))
    
    async def dnssec_status(self, zone: str, view: Optional[str] = None) -> ServerCommandResult:
        """Get DNSSEC status for zone"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.DNSSEC,
            zone=zone,
            args=["-status"],
            view=view
        ))
    
    async def managed_keys(self, action: str = "status", view: Optional[str] = None) -> ServerCommandResult:
        """Manage trust anchors"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.MANAGED_KEYS,
            args=[action],
            view=view
        ))
    
    # =========================================================================
    # Trust Anchor Commands
    # =========================================================================
    
    async def nta_add(
        self, 
        domain: str, 
        lifetime: str = "1h",
        force: bool = False,
        view: Optional[str] = None
    ) -> ServerCommandResult:
        """Add Negative Trust Anchor"""
        args = ["-lifetime", lifetime]
        if force:
            args.append("-force")
        args.append(domain)
        
        return await self.execute(ServerCommand(
            command=RNDCCommand.NTA,
            args=args,
            view=view
        ))
    
    async def nta_remove(self, domain: str, view: Optional[str] = None) -> ServerCommandResult:
        """Remove Negative Trust Anchor"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.NTA,
            args=["-remove", domain],
            view=view
        ))
    
    async def nta_list(self, view: Optional[str] = None) -> ServerCommandResult:
        """List Negative Trust Anchors"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.NTA,
            args=["-dump"],
            view=view
        ))
    
    async def secroots(self, view: Optional[str] = None) -> ServerCommandResult:
        """Dump security roots"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.SECROOTS,
            view=view
        ))
    
    # =========================================================================
    # Debugging Commands
    # =========================================================================
    
    async def dumpdb(self, output_type: str = "-all") -> ServerCommandResult:
        """Dump database"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.DUMPDB,
            args=[output_type]
        ))
    
    async def trace(self, level: int = 1) -> ServerCommandResult:
        """Set debug level"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.TRACE,
            args=[str(level)]
        ))
    
    async def notrace(self) -> ServerCommandResult:
        """Disable debug tracing"""
        return await self.execute(ServerCommand(command=RNDCCommand.NOTRACE))
    
    async def querylog(self, enable: Optional[bool] = None) -> ServerCommandResult:
        """Toggle or set query logging"""
        args = []
        if enable is not None:
            args.append("on" if enable else "off")
        return await self.execute(ServerCommand(
            command=RNDCCommand.QUERYLOG,
            args=args
        ))
    
    async def recursing(self) -> ServerCommandResult:
        """Dump recursive queries"""
        return await self.execute(ServerCommand(command=RNDCCommand.RECURSING))
    
    # =========================================================================
    # Validation Commands
    # =========================================================================
    
    async def validation(self, enable: bool, view: Optional[str] = None) -> ServerCommandResult:
        """Enable/disable DNSSEC validation"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.VALIDATION,
            args=["on" if enable else "off"],
            view=view
        ))
    
    # =========================================================================
    # Other Commands
    # =========================================================================
    
    async def tcp_timeouts(
        self,
        initial: Optional[int] = None,
        idle: Optional[int] = None,
        keepalive: Optional[int] = None,
        advertised: Optional[int] = None
    ) -> ServerCommandResult:
        """Get or set TCP timeouts"""
        args = []
        if initial is not None:
            args.extend([str(initial), str(idle or 0), str(keepalive or 0), str(advertised or 0)])
        return await self.execute(ServerCommand(
            command=RNDCCommand.TCP_TIMEOUTS,
            args=args
        ))
    
    async def serve_stale(self, enable: bool) -> ServerCommandResult:
        """Enable/disable stale cache serving"""
        return await self.execute(ServerCommand(
            command=RNDCCommand.SERVE_STALE,
            args=["on" if enable else "off"]
        ))
    
    async def stop(self) -> ServerCommandResult:
        """Stop the server gracefully"""
        return await self.execute(ServerCommand(command=RNDCCommand.STOP))
    
    async def halt(self) -> ServerCommandResult:
        """Halt the server immediately"""
        return await self.execute(ServerCommand(command=RNDCCommand.HALT))
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def is_available(self) -> bool:
        """Check if rndc is available"""
        return shutil.which(self.rndc_path) is not None
    
    async def check_connection(self) -> bool:
        """Test rndc connection to server"""
        try:
            result = await self.status()
            return True
        except Exception:
            return False

