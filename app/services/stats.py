"""
Statistics Service - BIND9 Statistics Channel
Retrieves and parses statistics from BIND9's statistics channel
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
import httpx

from ..config import settings
from ..models.server import (
    ServerStatistics, QueryStats, OpcodeStats, RcodeStats,
    ResolverStats, CacheStats, SocketStats, MemoryStats,
    TrafficStats, ZoneStats
)


class StatisticsError(Exception):
    """Statistics retrieval failed"""
    pass


class StatisticsService:
    """Service for BIND9 statistics channel"""
    
    def __init__(self):
        self.stats_url = settings.bind9_stats_url
        self.stats_format = settings.bind9_stats_format
        self.timeout = 30
    
    async def _fetch_stats(self, path: str = "") -> Dict[str, Any]:
        """Fetch statistics from BIND9 statistics channel"""
        url = f"{self.stats_url}/{self.stats_format}"
        if path:
            url = f"{url}/{path}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                if self.stats_format == "json":
                    return response.json()
                else:
                    # XML format - would need xml parsing
                    return {"raw": response.text}
                    
        except httpx.TimeoutException:
            raise StatisticsError("Statistics channel request timed out")
        except httpx.ConnectError:
            raise StatisticsError(f"Cannot connect to statistics channel at {self.stats_url}")
        except httpx.HTTPStatusError as e:
            raise StatisticsError(f"Statistics channel returned error: {e.response.status_code}")
        except Exception as e:
            raise StatisticsError(f"Failed to fetch statistics: {e}")
    
    async def get_full_stats(self) -> ServerStatistics:
        """Get complete server statistics"""
        data = await self._fetch_stats()
        return self._parse_full_stats(data)
    
    def _parse_full_stats(self, data: Dict[str, Any]) -> ServerStatistics:
        """Parse full statistics JSON"""
        stats = ServerStatistics()
        stats.raw_json = data
        
        # Parse timestamp
        if "boot-time" in data:
            try:
                stats.boot_time = datetime.fromisoformat(data["boot-time"].replace("Z", "+00:00"))
            except:
                pass
        
        if "config-time" in data:
            try:
                stats.config_time = datetime.fromisoformat(data["config-time"].replace("Z", "+00:00"))
            except:
                pass
        
        if "current-time" in data:
            try:
                stats.current_time = datetime.fromisoformat(data["current-time"].replace("Z", "+00:00"))
            except:
                pass
        
        # Parse query statistics
        if "qtypes" in data:
            stats.queries = self._parse_query_stats(data["qtypes"])
        
        # Parse opcode statistics
        if "opcodes" in data:
            stats.opcodes = self._parse_opcode_stats(data["opcodes"])
        
        # Parse rcode statistics
        if "rcodes" in data:
            stats.rcodes = self._parse_rcode_stats(data["rcodes"])
        
        # Parse resolver statistics
        if "resolver" in data:
            stats.resolver = self._parse_resolver_stats(data.get("resolver", {}).get("stats", {}))
        
        # Parse cache statistics
        if "cachestats" in data:
            stats.cache = self._parse_cache_stats(data["cachestats"])
        
        # Parse socket statistics
        if "socketstats" in data:
            stats.sockets = self._parse_socket_stats(data["socketstats"])
        
        # Parse memory statistics
        if "memory" in data:
            stats.memory = self._parse_memory_stats(data["memory"])
        
        # Parse traffic statistics
        if "traffic" in data:
            stats.traffic = self._parse_traffic_stats(data["traffic"])
        elif "nsstats" in data:
            stats.traffic = self._parse_traffic_stats(data["nsstats"])
        
        # Parse zone statistics
        if "zonestats" in data:
            stats.zones = self._parse_zone_stats(data["zonestats"])
        elif "views" in data:
            stats.zones = self._parse_zone_stats_from_views(data["views"])
        
        return stats
    
    def _parse_query_stats(self, data: Dict[str, Any]) -> QueryStats:
        """Parse query type statistics"""
        return QueryStats(
            A=data.get("A", 0),
            AAAA=data.get("AAAA", 0),
            CNAME=data.get("CNAME", 0),
            MX=data.get("MX", 0),
            NS=data.get("NS", 0),
            PTR=data.get("PTR", 0),
            SOA=data.get("SOA", 0),
            TXT=data.get("TXT", 0),
            SRV=data.get("SRV", 0),
            CAA=data.get("CAA", 0),
            DNSKEY=data.get("DNSKEY", 0),
            DS=data.get("DS", 0),
            HTTPS=data.get("HTTPS", 0),
            ANY=data.get("ANY", 0),
            OTHER=sum(v for k, v in data.items() if k not in [
                "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT",
                "SRV", "CAA", "DNSKEY", "DS", "HTTPS", "ANY"
            ])
        )
    
    def _parse_opcode_stats(self, data: Dict[str, Any]) -> OpcodeStats:
        """Parse opcode statistics"""
        return OpcodeStats(
            QUERY=data.get("QUERY", 0),
            IQUERY=data.get("IQUERY", 0),
            STATUS=data.get("STATUS", 0),
            NOTIFY=data.get("NOTIFY", 0),
            UPDATE=data.get("UPDATE", 0),
        )
    
    def _parse_rcode_stats(self, data: Dict[str, Any]) -> RcodeStats:
        """Parse response code statistics"""
        return RcodeStats(
            NOERROR=data.get("NOERROR", 0),
            FORMERR=data.get("FORMERR", 0),
            SERVFAIL=data.get("SERVFAIL", 0),
            NXDOMAIN=data.get("NXDOMAIN", 0),
            NOTIMP=data.get("NOTIMP", 0),
            REFUSED=data.get("REFUSED", 0),
            YXDOMAIN=data.get("YXDOMAIN", 0),
            YXRRSET=data.get("YXRRSET", 0),
            NXRRSET=data.get("NXRRSET", 0),
            NOTAUTH=data.get("NOTAUTH", 0),
            NOTZONE=data.get("NOTZONE", 0),
        )
    
    def _parse_resolver_stats(self, data: Dict[str, Any]) -> ResolverStats:
        """Parse resolver statistics"""
        return ResolverStats(
            queries_sent=data.get("Queryv4", 0) + data.get("Queryv6", 0),
            queries_in_progress=data.get("QryInProgress", 0),
            queries_timeout=data.get("QueryTimeout", 0),
            lame_delegations=data.get("Lame", 0),
            nxdomain=data.get("NXDOMAIN", 0),
            servfail=data.get("SERVFAIL", 0),
            formerr=data.get("FORMERR", 0),
            other_errors=data.get("OtherError", 0),
            edns0_failures=data.get("EDNS0Fail", 0),
            truncated=data.get("Truncated", 0),
            retries=data.get("Retry", 0),
            gluefetch=data.get("GlueFetchv4", 0) + data.get("GlueFetchv6", 0),
            dns64=data.get("DNS64", 0),
            rpz_rewrites=data.get("RPZRewrites", 0),
        )
    
    def _parse_cache_stats(self, data: Dict[str, Any]) -> CacheStats:
        """Parse cache statistics"""
        return CacheStats(
            cache_hits=data.get("CacheHits", 0),
            cache_misses=data.get("CacheMisses", 0),
            query_hits=data.get("QueryHits", 0),
            query_misses=data.get("QueryMisses", 0),
            delete_lru=data.get("DeleteLRU", 0),
            delete_ttl=data.get("DeleteTTL", 0),
            cache_nodes=data.get("CacheNodes", 0),
            cache_buckets=data.get("CacheBuckets", 0),
            tree_memory=data.get("TreeMemTotal", 0),
            heap_memory=data.get("HeapMemTotal", 0),
        )
    
    def _parse_socket_stats(self, data: Dict[str, Any]) -> SocketStats:
        """Parse socket statistics"""
        return SocketStats(
            udp4_open=data.get("UDP4Open", 0),
            udp6_open=data.get("UDP6Open", 0),
            tcp4_open=data.get("TCP4Open", 0),
            tcp6_open=data.get("TCP6Open", 0),
            raw_open=data.get("RawOpen", 0),
            udp4_active=data.get("UDP4Active", 0),
            udp6_active=data.get("UDP6Active", 0),
            tcp4_active=data.get("TCP4Active", 0),
            tcp6_active=data.get("TCP6Active", 0),
            raw_active=data.get("RawActive", 0),
            udp4_bindfail=data.get("UDP4BindFail", 0),
            udp6_bindfail=data.get("UDP6BindFail", 0),
            tcp4_connectfail=data.get("TCP4ConnFail", 0),
            tcp6_connectfail=data.get("TCP6ConnFail", 0),
        )
    
    def _parse_memory_stats(self, data: Dict[str, Any]) -> MemoryStats:
        """Parse memory statistics"""
        return MemoryStats(
            total_use=data.get("TotalUse", 0),
            in_use=data.get("InUse", 0),
            block_size=data.get("BlockSize", 0),
            context_size=data.get("ContextSize", 0),
            lost=data.get("Lost", 0),
            contexts=data.get("contexts", {}),
        )
    
    def _parse_traffic_stats(self, data: Dict[str, Any]) -> TrafficStats:
        """Parse traffic statistics"""
        return TrafficStats(
            dns_udp_requests_received_ipv4=data.get("Requestv4", 0),
            dns_udp_requests_received_ipv6=data.get("Requestv6", 0),
            dns_udp_responses_sent_ipv4=data.get("Response", 0),
            dns_tcp_requests_received_ipv4=data.get("ReqTCP", 0),
            queries_resulted_in_successful_answer=data.get("QrySuccess", 0),
            queries_resulted_in_authoritative_answer=data.get("QryAuthAns", 0),
            queries_resulted_in_non_authoritative_answer=data.get("QryNoauthAns", 0),
            queries_resulted_in_referral_answer=data.get("QryReferral", 0),
            queries_resulted_in_nxrrset=data.get("QryNXRRSET", 0),
            queries_resulted_in_servfail=data.get("QrySERVFAIL", 0),
            queries_resulted_in_nxdomain=data.get("QryNXDOMAIN", 0),
            queries_caused_recursion=data.get("QryRecursion", 0),
            duplicate_queries_received=data.get("QryDuplicate", 0),
            queries_dropped=data.get("QryDropped", 0),
        )
    
    def _parse_zone_stats(self, data: List[Dict[str, Any]]) -> List[ZoneStats]:
        """Parse zone statistics list"""
        zones = []
        for zone_data in data:
            zones.append(ZoneStats(
                zone_name=zone_data.get("name", ""),
                serial=zone_data.get("serial", 0),
                notify_sent=zone_data.get("NotifyOutv4", 0) + zone_data.get("NotifyOutv6", 0),
                notify_received=zone_data.get("NotifyInv4", 0) + zone_data.get("NotifyInv6", 0),
                axfr_sent=zone_data.get("XfrSuccess", 0),
                axfr_received=zone_data.get("XfrFail", 0),
                updates_received=zone_data.get("UpdateReqFwd", 0),
                updates_rejected=zone_data.get("UpdateRej", 0),
                updates_completed=zone_data.get("UpdateDone", 0),
            ))
        return zones
    
    def _parse_zone_stats_from_views(self, data: Dict[str, Any]) -> List[ZoneStats]:
        """Parse zone statistics from views structure"""
        zones = []
        for view_name, view_data in data.items():
            if "zones" in view_data:
                for zone_name, zone_data in view_data["zones"].items():
                    zones.append(ZoneStats(
                        zone_name=zone_name,
                        serial=zone_data.get("serial", 0),
                    ))
        return zones
    
    # =========================================================================
    # Specific Statistics Endpoints
    # =========================================================================
    
    async def get_query_stats(self) -> QueryStats:
        """Get query type statistics"""
        data = await self._fetch_stats()
        return self._parse_query_stats(data.get("qtypes", {}))
    
    async def get_resolver_stats(self) -> ResolverStats:
        """Get resolver statistics"""
        data = await self._fetch_stats()
        resolver_data = data.get("resolver", {})
        return self._parse_resolver_stats(resolver_data.get("stats", {}))
    
    async def get_cache_stats(self) -> CacheStats:
        """Get cache statistics"""
        data = await self._fetch_stats()
        return self._parse_cache_stats(data.get("cachestats", {}))
    
    async def get_memory_stats(self) -> MemoryStats:
        """Get memory statistics"""
        data = await self._fetch_stats()
        return self._parse_memory_stats(data.get("memory", {}))
    
    async def get_traffic_stats(self) -> TrafficStats:
        """Get traffic statistics"""
        data = await self._fetch_stats()
        return self._parse_traffic_stats(data.get("nsstats", data.get("traffic", {})))
    
    async def get_zone_stats(self) -> List[ZoneStats]:
        """Get per-zone statistics"""
        data = await self._fetch_stats()
        if "zonestats" in data:
            return self._parse_zone_stats(data["zonestats"])
        elif "views" in data:
            return self._parse_zone_stats_from_views(data["views"])
        return []
    
    # =========================================================================
    # Health Check
    # =========================================================================
    
    async def is_available(self) -> bool:
        """Check if statistics channel is available"""
        try:
            await self._fetch_stats()
            return True
        except:
            return False
    
    async def get_server_time(self) -> Optional[datetime]:
        """Get server current time from statistics"""
        try:
            data = await self._fetch_stats()
            if "current-time" in data:
                return datetime.fromisoformat(data["current-time"].replace("Z", "+00:00"))
        except:
            pass
        return None
    
    async def get_uptime(self) -> Optional[float]:
        """Get server uptime in seconds"""
        try:
            data = await self._fetch_stats()
            boot_time = data.get("boot-time")
            current_time = data.get("current-time")
            
            if boot_time and current_time:
                boot = datetime.fromisoformat(boot_time.replace("Z", "+00:00"))
                current = datetime.fromisoformat(current_time.replace("Z", "+00:00"))
                return (current - boot).total_seconds()
        except:
            pass
        return None

