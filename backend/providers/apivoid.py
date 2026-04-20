"""TriageOne — APIVoid provider (80+ blacklists)."""
from __future__ import annotations
from backend.models.ioc import IOCType, ProviderResult
from backend.providers.base import BaseProvider


class APIVoidProvider(BaseProvider):
    name = "APIVoid"
    requires_key = True
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL]
    timeout = 20.0
    BASE = "https://api.apivoid.com/v2"

    async def _query(self, value, ioc_type):
        client = await self.get_client()
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        ep = {"ip": "ip-reputation", "domain": "domain-reputation", "url": "url-reputation"}
        key = {"ip": "ip", "domain": "host", "url": "url"}
        resp = await client.post(f"{self.BASE}/{ep[ioc_type.value]}",
                                 json={key[ioc_type.value]: value}, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        bl = data.get("blacklists", {})
        engines = bl.get("engines", {})
        detections = bl.get("detection_count", 0)
        engine_count = bl.get("engine_count", len(engines))
        risk = data.get("risk_score", {})
        score = float(risk.get("result", 0) if isinstance(risk, dict) else 0)
        details = {"detections": f"{detections}/{engine_count} engines"}
        tags = []
        if ioc_type == IOCType.IP:
            geo = data.get("geo", {})
            anon = data.get("anonymity", {}) or {}
            details.update({"country_code": geo.get("country_code",""), "country_name": geo.get("country_name",""),
                           "isp": (data.get("isp",{}) or {}).get("name",""),
                           "is_tor": anon.get("is_tor",False), "is_vpn": anon.get("is_vpn",False),
                           "is_proxy": anon.get("is_proxy",False)})
            for k in ["tor","vpn","proxy"]:
                if details.get(f"is_{k}"): tags.append(k)
        for eid, eng in list(engines.items())[:5]:
            if isinstance(eng, dict) and eng.get("detected"):
                tags.append(eng.get("name","").lower())
        return ProviderResult(provider=self.name, score=round(score,1),
                              raw_score=f"{detections}/{engine_count} blacklists",
                              details=details, tags=tags[:15])
