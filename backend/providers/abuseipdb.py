"""TriageOne — AbuseIPDB provider."""
from __future__ import annotations
from backend.models.ioc import IOCType, ProviderResult
from backend.providers.base import BaseProvider


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    requires_key = True
    supported_types = [IOCType.IP]
    BASE = "https://api.abuseipdb.com/api/v2"

    async def _query(self, value: str, ioc_type: IOCType) -> ProviderResult:
        client = await self.get_client()
        resp = await client.get(
            f"{self.BASE}/check",
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = float(data.get("abuseConfidenceScore", 0))
        details = {
            "country_code": data.get("countryCode", ""), "country_name": data.get("countryName", ""),
            "isp": data.get("isp", ""), "domain": data.get("domain", ""),
            "usage_type": data.get("usageType", ""), "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt", ""),
            "is_tor": data.get("isTor", False), "is_whitelisted": data.get("isWhitelisted", False),
        }
        tags = []
        if data.get("isTor"): tags.append("tor-exit")
        if data.get("totalReports", 0) > 100: tags.append("heavily-reported")
        if data.get("usageType"): tags.append(data["usageType"].lower().replace(" ", "-"))
        return ProviderResult(provider=self.name, score=score, raw_score=f"{score}% confidence",
                              details=details, tags=tags)
