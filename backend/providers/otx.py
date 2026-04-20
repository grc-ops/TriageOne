"""TriageOne — OTX AlienVault provider."""
from __future__ import annotations
from backend.models.ioc import IOCType, ProviderResult
from backend.providers.base import BaseProvider


class OTXProvider(BaseProvider):
    name = "OTX AlienVault"
    requires_key = True
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL,
                       IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256, IOCType.FILENAME]
    BASE = "https://otx.alienvault.com/api/v1"

    def _endpoint(self, value, ioc_type):
        m = {IOCType.IP: f"indicators/IPv4/{value}/general",
             IOCType.DOMAIN: f"indicators/domain/{value}/general",
             IOCType.URL: f"indicators/url/{value}/general",
             IOCType.FILENAME: f"indicators/file/{value}/general"}
        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            return f"{self.BASE}/indicators/file/{value}/general"
        return f"{self.BASE}/{m.get(ioc_type, '')}"

    async def _query(self, value, ioc_type):
        client = await self.get_client()
        resp = await client.get(self._endpoint(value, ioc_type),
                                headers={"X-OTX-API-KEY": self.api_key})
        if resp.status_code == 404:
            return ProviderResult(provider=self.name, score=0, raw_score="Not found")
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count == 0: score = 0.0
        elif pulse_count <= 3: score = 25.0
        elif pulse_count <= 10: score = 50.0
        elif pulse_count <= 30: score = 75.0
        else: score = 90.0
        tags_raw = []
        for p in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags_raw.extend(p.get("tags", []))
        tags = list(set(t.lower() for t in tags_raw))[:10]
        if any(t in tags for t in ["malware","ransomware","apt","c2","botnet"]):
            score = min(100, score + 15)
        details = {"pulse_count": pulse_count, "country_code": data.get("country_code", ""),
                   "country_name": data.get("country_name", ""), "asn": data.get("asn", "")}
        return ProviderResult(provider=self.name, score=round(score, 1),
                              raw_score=f"{pulse_count} pulses", details=details, tags=tags)
