"""
DNSSEC Service - DNSSEC key and signing management
Handles DNSSEC operations for BIND9
"""

import asyncio
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

from ..config import settings
from ..models.dnssec import (
    DNSSECAlgorithm, DNSSECDigestType, KeyType, KeyState,
    DNSSECKey, DNSSECKeyCreate, DNSSECKeyResponse,
    SigningStatus, DSRecordResponse, TrustAnchor, NegativeTrustAnchor
)
from .rndc import RNDCService


class DNSSECError(Exception):
    """DNSSEC operation failed"""
    pass


class DNSSECService:
    """Service for DNSSEC operations"""
    
    def __init__(self):
        self.keys_path = Path(settings.bind9_keys_path)
        self.keygen_path = settings.bind9_dnssec_keygen
        self.signzone_path = settings.bind9_dnssec_signzone
        self.rndc = RNDCService()
    
    # =========================================================================
    # Key Generation
    # =========================================================================
    
    async def generate_key(
        self,
        zone: str,
        key_type: KeyType,
        algorithm: DNSSECAlgorithm = DNSSECAlgorithm.ECDSAP256SHA256,
        bits: Optional[int] = None,
        ttl: int = 3600,
        publish: Optional[datetime] = None,
        activate: Optional[datetime] = None,
        inactive: Optional[datetime] = None,
        delete: Optional[datetime] = None,
    ) -> DNSSECKeyResponse:
        """Generate a new DNSSEC key"""
        
        # Ensure keys directory exists
        self.keys_path.mkdir(parents=True, exist_ok=True)
        
        # Build command
        cmd = [
            self.keygen_path,
            "-a", str(algorithm.value),
            "-K", str(self.keys_path),
        ]
        
        # Key type flags
        if key_type == KeyType.KSK:
            cmd.extend(["-f", "KSK"])
        elif key_type == KeyType.CSK:
            cmd.extend(["-f", "KSK"])  # CSK uses KSK flag
        
        # Key size (if specified and applicable)
        if bits and algorithm.value in [5, 7, 8, 10]:  # RSA algorithms
            cmd.extend(["-b", str(bits)])
        
        # Timing
        if publish:
            cmd.extend(["-P", publish.strftime("%Y%m%d%H%M%S")])
        if activate:
            cmd.extend(["-A", activate.strftime("%Y%m%d%H%M%S")])
        if inactive:
            cmd.extend(["-I", inactive.strftime("%Y%m%d%H%M%S")])
        if delete:
            cmd.extend(["-D", delete.strftime("%Y%m%d%H%M%S")])
        
        # Zone name
        cmd.append(zone)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.keys_path)
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise DNSSECError(f"Key generation failed: {stderr.decode()}")
            
            # Parse output to get key name
            key_name = stdout.decode().strip()
            
            # Read key info
            return await self.get_key_info(zone, key_name)
            
        except FileNotFoundError:
            raise DNSSECError(f"dnssec-keygen not found at {self.keygen_path}")
    
    async def get_key_info(self, zone: str, key_name: str) -> DNSSECKeyResponse:
        """Get information about a DNSSEC key"""
        key_file = self.keys_path / f"{key_name}.key"
        private_file = self.keys_path / f"{key_name}.private"
        
        if not key_file.exists():
            raise DNSSECError(f"Key file not found: {key_file}")
        
        # Parse public key file
        content = key_file.read_text()
        
        # Parse DNSKEY record
        # Format: zone. IN DNSKEY flags protocol algorithm public_key
        match = re.search(
            r'(\S+)\.\s+\d*\s*IN\s+DNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)',
            content
        )
        
        if not match:
            raise DNSSECError(f"Could not parse key file: {key_file}")
        
        flags = int(match.group(2))
        protocol = int(match.group(3))
        algorithm = int(match.group(4))
        public_key = match.group(5).replace(" ", "").replace("\n", "")
        
        # Determine key type from flags
        if flags == 257:
            key_type = KeyType.KSK
        elif flags == 256:
            key_type = KeyType.ZSK
        else:
            key_type = KeyType.CSK
        
        # Calculate key tag
        key_tag = self._calculate_key_tag(flags, protocol, algorithm, public_key)
        
        # Parse timing from private key if exists
        timing = {}
        if private_file.exists():
            private_content = private_file.read_text()
            timing = self._parse_key_timing(private_content)
        
        # Generate DS records
        ds_records = await self._generate_ds_records(zone, key_file)
        
        return DNSSECKeyResponse(
            zone=zone,
            key_tag=key_tag,
            algorithm=DNSSECAlgorithm(algorithm),
            key_type=key_type,
            bits=self._get_key_bits(algorithm, public_key),
            state=KeyState.ACTIVE,  # Would need more logic to determine
            flags=flags,
            protocol=protocol,
            public_key=public_key,
            private_key_file=str(private_file) if private_file.exists() else None,
            public_key_file=str(key_file),
            ds_records=ds_records,
            **timing
        )
    
    def _calculate_key_tag(
        self,
        flags: int,
        protocol: int,
        algorithm: int,
        public_key: str
    ) -> int:
        """Calculate DNSKEY key tag (RFC 4034)"""
        import base64
        
        # Build DNSKEY RDATA
        rdata = flags.to_bytes(2, 'big')
        rdata += protocol.to_bytes(1, 'big')
        rdata += algorithm.to_bytes(1, 'big')
        rdata += base64.b64decode(public_key)
        
        # Calculate key tag
        ac = 0
        for i, byte in enumerate(rdata):
            if i & 1:
                ac += byte
            else:
                ac += byte << 8
        
        ac += (ac >> 16) & 0xFFFF
        return ac & 0xFFFF
    
    def _parse_key_timing(self, content: str) -> Dict[str, datetime]:
        """Parse timing information from private key file"""
        timing = {}
        
        patterns = {
            'created': r'Created:\s*(\d+)',
            'publish': r'Publish:\s*(\d+)',
            'activate': r'Activate:\s*(\d+)',
            'inactive': r'Inactive:\s*(\d+)',
            'delete': r'Delete:\s*(\d+)',
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                timestamp = int(match.group(1))
                timing[key] = datetime.utcfromtimestamp(timestamp)
        
        return timing
    
    def _get_key_bits(self, algorithm: int, public_key: str) -> int:
        """Estimate key size from algorithm and public key"""
        import base64
        
        key_data = base64.b64decode(public_key)
        
        # ECDSA keys have fixed sizes
        if algorithm == 13:  # ECDSAP256SHA256
            return 256
        elif algorithm == 14:  # ECDSAP384SHA384
            return 384
        elif algorithm == 15:  # ED25519
            return 256
        elif algorithm == 16:  # ED448
            return 448
        else:
            # RSA - estimate from key length
            return len(key_data) * 8
    
    async def _generate_ds_records(self, zone: str, key_file: Path) -> List[str]:
        """Generate DS records from DNSKEY"""
        ds_records = []
        
        # Use dnssec-dsfromkey if available
        dsfromkey_path = str(Path(self.keygen_path).parent / "dnssec-dsfromkey")
        
        for digest_type in [2, 4]:  # SHA-256 and SHA-384
            try:
                process = await asyncio.create_subprocess_exec(
                    dsfromkey_path,
                    "-a", str(digest_type),
                    str(key_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, _ = await process.communicate()
                
                if process.returncode == 0:
                    ds_record = stdout.decode().strip()
                    if ds_record:
                        ds_records.append(ds_record)
                        
            except FileNotFoundError:
                pass
        
        return ds_records
    
    # =========================================================================
    # Key Management
    # =========================================================================
    
    async def list_keys(self, zone: str) -> List[DNSSECKeyResponse]:
        """List all DNSSEC keys for a zone"""
        keys = []
        
        if not self.keys_path.exists():
            return keys
        
        # Find all key files for this zone
        pattern = f"K{zone}.+*.key"
        for key_file in self.keys_path.glob(pattern):
            key_name = key_file.stem
            try:
                key_info = await self.get_key_info(zone, key_name)
                keys.append(key_info)
            except Exception:
                pass
        
        return keys
    
    async def delete_key(self, zone: str, key_tag: int) -> bool:
        """Delete a DNSSEC key"""
        keys = await self.list_keys(zone)
        
        for key in keys:
            if key.key_tag == key_tag:
                # Delete key files
                if key.public_key_file:
                    Path(key.public_key_file).unlink(missing_ok=True)
                if key.private_key_file:
                    Path(key.private_key_file).unlink(missing_ok=True)
                return True
        
        raise DNSSECError(f"Key with tag {key_tag} not found for zone {zone}")
    
    async def set_key_timing(
        self,
        zone: str,
        key_tag: int,
        publish: Optional[datetime] = None,
        activate: Optional[datetime] = None,
        inactive: Optional[datetime] = None,
        delete: Optional[datetime] = None,
    ) -> DNSSECKeyResponse:
        """Update key timing"""
        # Use dnssec-settime
        settime_path = str(Path(self.keygen_path).parent / "dnssec-settime")
        
        keys = await self.list_keys(zone)
        target_key = None
        
        for key in keys:
            if key.key_tag == key_tag:
                target_key = key
                break
        
        if not target_key or not target_key.public_key_file:
            raise DNSSECError(f"Key with tag {key_tag} not found")
        
        key_name = Path(target_key.public_key_file).stem
        
        cmd = [settime_path, "-K", str(self.keys_path)]
        
        if publish:
            cmd.extend(["-P", publish.strftime("%Y%m%d%H%M%S")])
        if activate:
            cmd.extend(["-A", activate.strftime("%Y%m%d%H%M%S")])
        if inactive:
            cmd.extend(["-I", inactive.strftime("%Y%m%d%H%M%S")])
        if delete:
            cmd.extend(["-D", delete.strftime("%Y%m%d%H%M%S")])
        
        cmd.append(key_name)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise DNSSECError(f"Failed to set key timing: {stderr.decode()}")
            
            return await self.get_key_info(zone, key_name)
            
        except FileNotFoundError:
            raise DNSSECError(f"dnssec-settime not found at {settime_path}")
    
    # =========================================================================
    # Zone Signing
    # =========================================================================
    
    async def sign_zone(self, zone: str, view: Optional[str] = None) -> bool:
        """Sign a zone (trigger inline signing)"""
        result = await self.rndc.sign(zone, view)
        
        if not result.success:
            raise DNSSECError(f"Failed to sign zone: {result.error}")
        
        return True
    
    async def loadkeys(self, zone: str, view: Optional[str] = None) -> bool:
        """Load DNSSEC keys for a zone"""
        result = await self.rndc.loadkeys(zone, view)
        
        if not result.success:
            raise DNSSECError(f"Failed to load keys: {result.error}")
        
        return True
    
    async def get_signing_status(self, zone: str, view: Optional[str] = None) -> SigningStatus:
        """Get zone signing status"""
        result = await self.rndc.signing(zone, "-list", view)
        
        # Parse signing status
        keys = await self.list_keys(zone)
        
        return SigningStatus(
            zone=zone,
            signed=len(keys) > 0,
            inline_signing=True,  # Would need to check zone config
            ksk_count=len([k for k in keys if k.key_type == KeyType.KSK]),
            zsk_count=len([k for k in keys if k.key_type == KeyType.ZSK]),
            active_keys=[k.key_tag for k in keys if k.state == KeyState.ACTIVE],
        )
    
    # =========================================================================
    # DS Record Generation
    # =========================================================================
    
    async def generate_ds_records(
        self,
        zone: str,
        digest_types: List[DNSSECDigestType] = None,
        key_tag: Optional[int] = None
    ) -> List[DSRecordResponse]:
        """Generate DS records for registrar"""
        if digest_types is None:
            digest_types = [DNSSECDigestType.SHA256, DNSSECDigestType.SHA384]
        
        keys = await self.list_keys(zone)
        ds_records = []
        
        for key in keys:
            # Only generate DS for KSK/CSK
            if key.key_type == KeyType.ZSK:
                continue
            
            if key_tag and key.key_tag != key_tag:
                continue
            
            for ds in key.ds_records:
                # Parse DS record
                match = re.search(
                    r'(\S+)\s+\d*\s*IN\s+DS\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)',
                    ds
                )
                
                if match:
                    ds_records.append(DSRecordResponse(
                        zone=zone,
                        ds_records=[ds],
                        key_tag=int(match.group(2)),
                        algorithm=DNSSECAlgorithm(int(match.group(3))),
                        digest_type=DNSSECDigestType(int(match.group(4))),
                        digest=match.group(5),
                        bind_format=ds,
                        generic_format=f"{match.group(2)} {match.group(3)} {match.group(4)} {match.group(5)}"
                    ))
        
        return ds_records
    
    # =========================================================================
    # Trust Anchors
    # =========================================================================
    
    async def list_trust_anchors(self, view: Optional[str] = None) -> List[TrustAnchor]:
        """List trust anchors"""
        result = await self.rndc.managed_keys("status", view)
        
        # Parse output
        anchors = []
        # Implementation would parse the managed-keys status output
        
        return anchors
    
    async def add_nta(
        self,
        domain: str,
        lifetime: str = "1h",
        force: bool = False,
        view: Optional[str] = None
    ) -> NegativeTrustAnchor:
        """Add Negative Trust Anchor"""
        result = await self.rndc.nta_add(domain, lifetime, force, view)
        
        if not result.success:
            raise DNSSECError(f"Failed to add NTA: {result.error}")
        
        # Parse expiry from lifetime
        expires = None
        if lifetime != "forever":
            # Parse duration
            match = re.match(r'(\d+)([hdwm]?)', lifetime)
            if match:
                value = int(match.group(1))
                unit = match.group(2) or 'h'
                
                if unit == 'h':
                    expires = datetime.utcnow() + timedelta(hours=value)
                elif unit == 'd':
                    expires = datetime.utcnow() + timedelta(days=value)
                elif unit == 'w':
                    expires = datetime.utcnow() + timedelta(weeks=value)
                elif unit == 'm':
                    expires = datetime.utcnow() + timedelta(days=value*30)
        
        return NegativeTrustAnchor(
            zone=domain,
            expires=expires,
            forced=force
        )
    
    async def remove_nta(self, domain: str, view: Optional[str] = None) -> bool:
        """Remove Negative Trust Anchor"""
        result = await self.rndc.nta_remove(domain, view)
        
        if not result.success:
            raise DNSSECError(f"Failed to remove NTA: {result.error}")
        
        return True
    
    async def list_ntas(self, view: Optional[str] = None) -> List[NegativeTrustAnchor]:
        """List all Negative Trust Anchors"""
        result = await self.rndc.nta_list(view)
        
        ntas = []
        if result.success and result.output:
            for line in result.output.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    # Parse NTA line
                    parts = line.split()
                    if parts:
                        ntas.append(NegativeTrustAnchor(
                            zone=parts[0],
                            expires=None,  # Would need to parse expiry
                        ))
        
        return ntas

