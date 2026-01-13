"""
ACL Service - Manages BIND9 Access Control Lists
Handles reading, writing, and managing the ACL configuration file
"""

import os
import re
import pwd
import grp
import asyncio
import fcntl
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from contextlib import contextmanager

from ..config import settings
from ..models.acls import ACLCreate, ACLResponse, ACLUpdate


class ACLError(Exception):
    """ACL operation failed"""
    pass


class ACLService:
    """Service for managing BIND9 ACLs"""
    
    def __init__(self):
        self.acl_file = Path(settings.bind9_acl_file)
        self.named_conf = Path(settings.bind9_config_path)
        self._lock_file = Path("/tmp/.bind9-api-acl.lock")
    
    @contextmanager
    def _file_lock(self):
        """
        Cross-process file lock for ACL operations.
        Uses fcntl.flock for proper multi-worker synchronization.
        """
        # Ensure lock file exists
        self._lock_file.touch(exist_ok=True)
        
        with open(self._lock_file, 'w') as lock_fd:
            try:
                # Acquire exclusive lock (blocks until available)
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                # Release lock
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
    
    # =========================================================================
    # File Operations
    # =========================================================================
    
    def _set_bind_ownership(self, path: Path) -> None:
        """
        Set file ownership to bind:bind and permissions to 664.
        This ensures BIND9 can read the file after API creates/updates it.
        """
        try:
            # Get bind user/group IDs
            bind_uid = pwd.getpwnam('bind').pw_uid
            bind_gid = grp.getgrnam('bind').gr_gid
            
            # Set ownership to bind:bind
            os.chown(path, bind_uid, bind_gid)
            
            # Set permissions to 664 (rw-rw-r--)
            os.chmod(path, 0o664)
        except KeyError:
            # 'bind' user doesn't exist - try 'named' (used on some distros)
            try:
                named_uid = pwd.getpwnam('named').pw_uid
                named_gid = grp.getgrnam('named').gr_gid
                os.chown(path, named_uid, named_gid)
                os.chmod(path, 0o664)
            except KeyError:
                # Neither bind nor named user exists - leave as is
                # Just set world-readable permissions
                os.chmod(path, 0o644)
        except PermissionError:
            # Can't change ownership (not running as root) - just set permissions
            try:
                os.chmod(path, 0o664)
            except PermissionError:
                pass  # Can't even change permissions - file may still work
    
    def _ensure_file_exists(self) -> None:
        """Ensure the ACL file exists with correct ownership and permissions"""
        if not self.acl_file.exists():
            self.acl_file.parent.mkdir(parents=True, exist_ok=True)
            header = f"""\
// BIND9 Access Control Lists
// Managed by bind9-api - DO NOT EDIT MANUALLY
// Generated: {datetime.utcnow().isoformat()}

"""
            self.acl_file.write_text(header)
            # Set correct ownership and permissions for BIND9
            self._set_bind_ownership(self.acl_file)
    
    def _read_file(self) -> str:
        """Read the ACL file content"""
        self._ensure_file_exists()
        return self.acl_file.read_text()
    
    def _write_file(self, content: str) -> None:
        """Write content to the ACL file with correct ownership"""
        self._ensure_file_exists()
        self.acl_file.write_text(content)
        # Ensure ownership/permissions are correct after write
        self._set_bind_ownership(self.acl_file)
    
    # =========================================================================
    # Parsing
    # =========================================================================
    
    def _parse_acls(self, content: str) -> Dict[str, ACLResponse]:
        """Parse ACL definitions from file content"""
        acls = {}
        
        # Pattern to match ACL blocks: acl "name" { entries };
        # Handles multi-line definitions
        acl_pattern = r'acl\s+"?([a-zA-Z][a-zA-Z0-9_-]*)"?\s*\{([^}]*)\}\s*;'
        
        # Also capture comments before ACLs
        comment_pattern = r'//\s*(.+?)(?=\nacl|\Z)'
        
        for match in re.finditer(acl_pattern, content, re.MULTILINE | re.DOTALL):
            name = match.group(1)
            entries_block = match.group(2)
            
            # Parse entries
            entries = []
            for line in entries_block.split('\n'):
                line = line.strip()
                # Remove inline comments
                if '//' in line:
                    line = line.split('//')[0].strip()
                # Remove trailing semicolon and whitespace
                line = line.rstrip(';').strip()
                if line:
                    entries.append(line)
            
            # Look for comment before this ACL
            comment = None
            start_pos = match.start()
            preceding = content[:start_pos]
            comment_match = re.search(r'//\s*([^\n]+)\s*$', preceding)
            if comment_match:
                comment = comment_match.group(1).strip()
            
            acls[name] = ACLResponse(
                name=name,
                entries=entries,
                comment=comment
            )
        
        return acls
    
    def _generate_acl_block(self, acl: ACLCreate, comment: Optional[str] = None) -> str:
        """Generate BIND9 ACL configuration block"""
        lines = []
        
        # Add comment if provided
        if comment or acl.comment:
            lines.append(f"// {comment or acl.comment}")
        
        lines.append(f'acl "{acl.name}" {{')
        
        for entry in acl.entries:
            entry = entry.strip()
            # Normalize key format
            if entry.startswith("key "):
                key_name = entry.replace("key ", "").replace('"', '').strip()
                lines.append(f'    key "{key_name}";')
            else:
                lines.append(f'    {entry};')
        
        lines.append("};")
        lines.append("")
        
        return "\n".join(lines)
    
    def _regenerate_file(self, acls: Dict[str, ACLResponse]) -> str:
        """Regenerate the entire ACL file from parsed ACLs"""
        lines = [
            "// BIND9 Access Control Lists",
            "// Managed by bind9-api - DO NOT EDIT MANUALLY",
            f"// Last updated: {datetime.utcnow().isoformat()}",
            "",
        ]
        
        for name, acl in sorted(acls.items()):
            if acl.comment:
                lines.append(f"// {acl.comment}")
            
            lines.append(f'acl "{name}" {{')
            for entry in acl.entries:
                entry = entry.strip()
                if entry.startswith("key "):
                    key_name = entry.replace("key ", "").replace('"', '').strip()
                    lines.append(f'    key "{key_name}";')
                else:
                    lines.append(f'    {entry};')
            lines.append("};")
            lines.append("")
        
        return "\n".join(lines)
    
    # =========================================================================
    # CRUD Operations
    # =========================================================================
    
    async def list_acls(self) -> List[ACLResponse]:
        """List all defined ACLs"""
        content = self._read_file()
        acls = self._parse_acls(content)
        return list(acls.values())
    
    async def get_acl(self, name: str) -> Optional[ACLResponse]:
        """Get a specific ACL by name"""
        content = self._read_file()
        acls = self._parse_acls(content)
        return acls.get(name)
    
    async def create_acl(self, acl: ACLCreate) -> ACLResponse:
        """Create a new ACL (process-safe with file locking)"""
        with self._file_lock():
            content = self._read_file()
            acls = self._parse_acls(content)
            
            if acl.name in acls:
                raise ACLError(f"ACL '{acl.name}' already exists")
            
            # Add new ACL
            acls[acl.name] = ACLResponse(
                name=acl.name,
                entries=acl.entries,
                comment=acl.comment
            )
            
            # Regenerate file
            new_content = self._regenerate_file(acls)
            self._write_file(new_content)
            
            # Ensure ACL file is included in named.conf before reloading
            await self.ensure_included()
            
            # Reload BIND9 to pick up changes
            await self._reload_bind9()
            
            return acls[acl.name]
    
    async def update_acl(self, name: str, update: ACLUpdate) -> ACLResponse:
        """Update an existing ACL (process-safe with file locking)"""
        with self._file_lock():
            content = self._read_file()
            acls = self._parse_acls(content)
            
            if name not in acls:
                raise ACLError(f"ACL '{name}' not found")
            
            existing = acls[name]
            
            # Update fields
            if update.entries is not None:
                existing.entries = update.entries
            if update.comment is not None:
                existing.comment = update.comment
            
            acls[name] = existing
            
            # Regenerate file
            new_content = self._regenerate_file(acls)
            self._write_file(new_content)
            
            # Reload BIND9
            await self._reload_bind9()
            
            return existing
    
    async def delete_acl(self, name: str) -> bool:
        """Delete an ACL (process-safe with file locking)"""
        with self._file_lock():
            content = self._read_file()
            acls = self._parse_acls(content)
            
            if name not in acls:
                raise ACLError(f"ACL '{name}' not found")
            
            del acls[name]
            
            # Regenerate file
            new_content = self._regenerate_file(acls)
            self._write_file(new_content)
            
            # Reload BIND9
            await self._reload_bind9()
            
            return True
    
    # =========================================================================
    # Include Management
    # =========================================================================
    
    async def ensure_included(self) -> bool:
        """
        Check if the ACL file is included in named.conf.
        
        Note: This method does NOT automatically modify named.conf.
        The include statement must be added manually by the administrator.
        This is a deliberate design choice for security and reliability.
        """
        if not self.named_conf.exists():
            return False
        
        try:
            content = self.named_conf.read_text()
            include_line = f'include "{self.acl_file}";'
            
            if include_line in content or str(self.acl_file) in content:
                return True  # Already included
            
            # Log warning but don't fail - ACLs will be written to file
            # but won't be active until admin adds include statement
            import logging
            logging.warning(
                f"ACL file '{self.acl_file}' is not included in named.conf. "
                f"ACLs will be saved but not active until you add: {include_line}"
            )
            return False
        except Exception:
            return False
    
    async def check_included(self) -> bool:
        """Check if ACL file is included in named.conf"""
        if not self.named_conf.exists():
            return False
        
        content = self.named_conf.read_text()
        return str(self.acl_file) in content
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    async def _reload_bind9(self) -> Tuple[bool, str]:
        """Reload BIND9 configuration and wait for it to take effect"""
        try:
            # First validate configuration
            check_proc = await asyncio.create_subprocess_exec(
                settings.bind9_named_checkconf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await check_proc.communicate()
            
            if check_proc.returncode != 0:
                error_msg = stderr.decode().strip()
                raise ACLError(f"Configuration validation failed: {error_msg}")
            
            # Reload BIND9
            reload_proc = await asyncio.create_subprocess_exec(
                settings.bind9_rndc_path,
                "reconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await reload_proc.communicate()
            
            if reload_proc.returncode != 0:
                error_msg = stderr.decode().strip()
                raise ACLError(f"Failed to reload BIND9: {error_msg}")
            
            # Wait for BIND9 to fully process the new configuration
            # This ensures ACLs are available before zones try to use them
            await asyncio.sleep(0.5)
            
            return True, "Configuration reloaded"
            
        except FileNotFoundError as e:
            raise ACLError(f"Command not found: {e}")
    
    async def validate_acl(self, acl: ACLCreate) -> Tuple[bool, str]:
        """Validate an ACL before creating"""
        errors = []
        
        for entry in acl.entries:
            entry = entry.strip()
            
            # Check for valid IP/network
            ip_pattern = r'^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$'
            # Check for valid key reference
            key_pattern = r'^!?key\s+"?[a-zA-Z][a-zA-Z0-9_-]*"?$'
            # Check for built-in or ACL reference
            ref_pattern = r'^!?[a-zA-Z][a-zA-Z0-9_-]*$'
            
            if not (re.match(ip_pattern, entry) or 
                    re.match(key_pattern, entry) or 
                    re.match(ref_pattern, entry)):
                errors.append(f"Invalid entry: {entry}")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, "Valid"
