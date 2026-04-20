"""TriageOne — URLhaus provider (requires Auth-Key)."""
from __future__ import annotations
from backend.models.ioc import IOCType, ProviderResult
from backend.providers.base import BaseProvider


class URLhausProvider(BaseProvider):
    name = "URLhaus"
    requires_key = True
    supported_types = [IOCType.URL, IOCType.DOMAIN, IOCType.IP]
    BASE = "https://urlhaus-api.abuse.ch/v1"

    async def _query(self, value, ioc_type):
        client = await self.get_client()
        headers = {"Auth-Key": self.api_key}
        if ioc_type == IOCType.URL:
            resp = await client.post(f"{self.BASE}/url/", data={"url": value}, headers=headers)
        elif ioc_type in (IOCType.DOMAIN, IOCType.IP):
            resp = await client.post(f"{self.BASE}/host/", data={"host": value}, headers=headers)
        else:
            return ProviderResult(provider=self.name, available=False, error="Unsupported type")
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "no_results":
            return ProviderResult(provider=self.name, score=0, raw_score="Clean")
        if "threat" in data:
            threat = data.get("threat", "")
            url_status = data.get("url_status", "")
            score = 85.0 if threat == "malware_download" else 65.0
            if url_status == "offline": score *= 0.7
            tags = [t for t in (data.get("tags") or []) if t][:10]
            return ProviderResult(provider=self.name, score=round(score, 1),
                                  raw_score=f"{threat} ({url_status})",
                                  details={"threat": threat, "url_status": url_status,
                                           "date_added": data.get("date_added",""), "reporter": data.get("reporter","")},
                                  tags=tags)
        url_count = data.get("url_count", 0) or 0
        urls = data.get("urls", []) or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        if url_count == 0: score = 0.0
        elif online > 5: score = 85.0
        elif online > 0: score = 60.0
        else: score = 30.0
        tags = list(set(t for u in urls[:10] for t in (u.get("tags") or []) if t))[:10]
        return ProviderResult(provider=self.name, score=round(score, 1),
                              raw_score=f"{url_count} URLs ({online} online)",
                              details={"url_count": url_count, "online_count": online}, tags=tags)
