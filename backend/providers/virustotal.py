"""TriageOne — VirusTotal provider with crowdsourced context & deep scan."""

from __future__ import annotations
import asyncio
import base64
from backend.models.ioc import IOCType, ProviderResult
from backend.providers.base import BaseProvider


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    requires_key = True
    supported_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL,
                       IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    BASE = "https://www.virustotal.com/api/v3"

    def _endpoint(self, value: str, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.IP:
            return f"{self.BASE}/ip_addresses/{value}"
        if ioc_type == IOCType.DOMAIN:
            return f"{self.BASE}/domains/{value}"
        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            return f"{self.BASE}/files/{value}"
        if ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"{self.BASE}/urls/{url_id}"
        return ""

    def _type_path(self, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.IP: return "ip_addresses"
        if ioc_type == IOCType.DOMAIN: return "domains"
        if ioc_type == IOCType.URL: return "urls"
        return "files"

    async def _query(self, value: str, ioc_type: IOCType) -> ProviderResult:
        client = await self.get_client()
        headers = {"x-apikey": self.api_key}
        url = self._endpoint(value, ioc_type)
        resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            return ProviderResult(provider=self.name, score=0, raw_score="Not found")
        resp.raise_for_status()

        full_data = resp.json().get("data", {})
        data = full_data.get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious_ct = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values()) if stats else 1
        score = min(100.0, ((malicious + suspicious_ct * 0.5) / max(total, 1)) * 100)

        details: dict = {}
        tags: list[str] = data.get("tags", []) or []

        details["analysis_stats"] = {"malicious": malicious, "suspicious": suspicious_ct,
                                     "undetected": undetected, "harmless": harmless, "total": total}

        votes = data.get("total_votes", {})
        if votes:
            details["community_votes"] = {"harmless": votes.get("harmless", 0), "malicious": votes.get("malicious", 0)}
        rep = data.get("reputation")
        if rep is not None:
            details["community_reputation"] = rep

        # Crowdsourced context
        for ctx_list in [data.get("crowdsourced_context", [])]:
            if ctx_list:
                details["crowdsourced_context"] = [
                    {"title": c.get("title",""), "source": c.get("source",""),
                     "severity": c.get("severity",""), "details": c.get("details",""),
                     "timestamp": c.get("timestamp","")}
                    for c in ctx_list[:10]
                ]

        ids_rules = data.get("crowdsourced_ids_results", [])
        if ids_rules:
            details["crowdsourced_ids"] = [
                {"rule_msg": i.get("rule_msg",""), "rule_source": i.get("rule_source",""),
                 "alert_severity": i.get("alert_severity","")}
                for i in ids_rules[:5]
            ]

        yara = data.get("crowdsourced_yara_results", [])
        if yara:
            details["yara_rules"] = [
                {"rule_name": y.get("rule_name",""), "ruleset_name": y.get("ruleset_name",""),
                 "description": y.get("description",""), "source": y.get("source","")}
                for y in yara[:5]
            ]

        sigma = data.get("sigma_analysis_results", [])
        if sigma:
            details["sigma_rules"] = [
                {"rule_title": s.get("rule_title",""), "rule_level": s.get("rule_level",""),
                 "rule_description": s.get("rule_description","")}
                for s in sigma[:5]
            ]

        threat_sev = data.get("threat_severity", {})
        if threat_sev:
            details["threat_severity"] = {"level": threat_sev.get("threat_severity_level",""),
                                          "category": threat_sev.get("level_description","")}

        popular = data.get("popular_threat_classification", {})
        if popular:
            label = popular.get("suggested_threat_label", "")
            if label:
                details["threat_label"] = label
                tags.insert(0, label)

        # Type-specific details
        if ioc_type == IOCType.IP:
            details["country"] = data.get("country", "")
            details["as_owner"] = data.get("as_owner", "")
            details["asn"] = data.get("asn", "")
            details["network"] = data.get("network", "")
            details["continent"] = data.get("continent", "")
            cert = data.get("last_https_certificate", {})
            if cert:
                subj = cert.get("subject", {})
                details["ssl_subject"] = subj.get("CN", "")
                details["ssl_issuer"] = cert.get("issuer", {}).get("O", "")
        elif ioc_type == IOCType.DOMAIN:
            details["registrar"] = data.get("registrar", "")
            details["creation_date"] = data.get("creation_date", "")
            details["last_dns_records"] = [
                {"type": r.get("type",""), "value": r.get("value",""), "ttl": r.get("ttl","")}
                for r in (data.get("last_dns_records") or [])[:10]
            ]
            whois = data.get("whois", "")
            if whois:
                details["whois_snippet"] = whois[:500]
        elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            details["type_description"] = data.get("type_description", "")
            details["size"] = data.get("size", 0)
            details["meaningful_name"] = data.get("meaningful_name", "")
            details["magic"] = data.get("magic", "")
            names = data.get("names", [])
            if names:
                details["known_filenames"] = names[:5]

        return ProviderResult(
            provider=self.name, score=round(score, 1),
            raw_score=f"{malicious}/{total} detections",
            details=details, tags=list(dict.fromkeys(tags))[:15],
        )

    async def fetch_relations(self, value: str, ioc_type: IOCType) -> dict:
        """Deep scan: fetch VT relationships (resolutions, communicating files, etc.)."""
        client = await self.get_client()
        headers = {"x-apikey": self.api_key}
        relations = {}

        if ioc_type == IOCType.IP:
            type_path = "ip_addresses"
            rel_types = ["resolutions", "communicating_files", "downloaded_files", "referrer_files"]
        elif ioc_type == IOCType.DOMAIN:
            type_path = "domains"
            rel_types = ["resolutions", "communicating_files", "downloaded_files", "referrer_files", "subdomains"]
        elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            type_path = "files"
            rel_types = ["contacted_ips", "contacted_domains", "contacted_urls", "dropped_files"]
        elif ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            type_path = "urls"
            value = url_id
            rel_types = ["downloaded_files", "contacted_ips", "contacted_domains"]
        else:
            return relations

        for rel in rel_types:
            try:
                await asyncio.sleep(0.5)  # Rate limit: 4 req/min
                resp = await client.get(
                    f"{self.BASE}/{type_path}/{value}/{rel}",
                    params={"limit": 10}, headers=headers,
                )
                if resp.status_code == 200:
                    items = resp.json().get("data", [])
                    parsed = []
                    for item in items[:10]:
                        attrs = item.get("attributes", {})
                        entry = {"id": item.get("id", ""), "type": item.get("type", "")}
                        if rel == "resolutions":
                            entry["host_name"] = attrs.get("host_name", "")
                            entry["ip_address"] = attrs.get("ip_address", "")
                            entry["date"] = attrs.get("date", "")
                        else:
                            stats = attrs.get("last_analysis_stats", {})
                            entry["malicious"] = stats.get("malicious", 0)
                            entry["total"] = sum(stats.values()) if stats else 0
                            entry["meaningful_name"] = attrs.get("meaningful_name", "")
                            entry["type_description"] = attrs.get("type_description", "")
                        parsed.append(entry)
                    if parsed:
                        relations[rel] = parsed
            except Exception:
                continue
        return relations

    async def fetch_comments(self, value: str, ioc_type: IOCType) -> list[dict]:
        """Deep scan: fetch VT community comments."""
        client = await self.get_client()
        headers = {"x-apikey": self.api_key}

        if ioc_type == IOCType.IP:
            type_path = "ip_addresses"
        elif ioc_type == IOCType.DOMAIN:
            type_path = "domains"
        elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            type_path = "files"
        elif ioc_type == IOCType.URL:
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            type_path = "urls"
        else:
            return []

        try:
            await asyncio.sleep(0.5)
            resp = await client.get(
                f"{self.BASE}/{type_path}/{value}/comments",
                params={"limit": 20}, headers=headers,
            )
            if resp.status_code != 200:
                return []
            items = resp.json().get("data", [])
            return [
                {
                    "text": c.get("attributes", {}).get("text", ""),
                    "date": c.get("attributes", {}).get("date", 0),
                    "votes": c.get("attributes", {}).get("votes", {}),
                    "html": c.get("attributes", {}).get("html", ""),
                }
                for c in items[:20]
            ]
        except Exception:
            return []
