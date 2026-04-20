"""TriageOne — Cybersecurity monitoring feed fetcher & classifier."""
from __future__ import annotations
import re, time
from datetime import datetime, timezone
import feedparser, httpx
from dateutil import parser as dateparser
from backend.database import get_cached_advisories, save_advisories

FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "source": "CISA"},
    {"name": "US-CERT NCAS", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "source": "US-CERT"},
    {"name": "CERT-EU", "url": "https://cert.europa.eu/publications/security-advisories/rss", "source": "CERT-EU"},
]

SECTOR_KEYWORDS = {
    "finance": ["bank","financial","fintech","swift","payment","atm","credit","trading","insurance","crypto"],
    "healthcare": ["health","hospital","medical","pharma","patient","hipaa","clinical","fda","vaccine"],
    "government": ["government","federal","agency","military","defense","election","intelligence"],
    "retail": ["retail","ecommerce","pos","merchant","shopping","consumer"],
    "telecom": ["telecom","5g","lte","carrier","mobile","voip","broadband","isp"],
    "manufacturing": ["manufactur","factory","production","supply chain","automotive","semiconductor"],
    "energy": ["energy","power","grid","utility","oil","gas","pipeline","renewable","nuclear"],
    "education": ["education","university","school","student","campus","academic"],
    "technology": ["software","cloud","saas","api","devops","kubernetes","linux","windows","microsoft","google","aws","azure"],
    "industrial": ["ics","scada","plc","ot","hmi","dcs","industrial control","modbus","critical infrastructure"],
}

COUNTRY_KEYWORDS = {
    "US": ["united states","us-cert","cisa","fbi","american"],
    "UK": ["united kingdom","uk","ncsc","british"],
    "DE": ["germany","german","bsi"],
    "CN": ["china","chinese","apt1","apt10","apt41"],
    "RU": ["russia","russian","apt28","apt29","cozy bear","fancy bear"],
    "IN": ["india","indian","cert-in"],
    "EU": ["europe","european","cert-eu","enisa"],
    "GLOBAL": ["global","worldwide","international"],
}

def _classify_sectors(text):
    lower = text.lower()
    return [s for s, kw in SECTOR_KEYWORDS.items() if any(k in lower for k in kw)] or ["technology"]

def _classify_countries(text):
    lower = text.lower()
    return [c for c, kw in COUNTRY_KEYWORDS.items() if any(k in lower for k in kw)] or ["GLOBAL"]

def _estimate_severity(text, cvss=None):
    if cvss is not None:
        if cvss >= 9.0: return "critical"
        if cvss >= 7.0: return "high"
        if cvss >= 4.0: return "medium"
        return "low"
    lower = text.lower()
    if any(w in lower for w in ["critical","emergency","actively exploited","zero-day"]): return "critical"
    if any(w in lower for w in ["high","severe","remote code execution","rce"]): return "high"
    if any(w in lower for w in ["medium","moderate","denial of service"]): return "medium"
    return "low"

def _extract_cve(text):
    m = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return m.group(0).upper() if m else None

def _extract_cvss(text):
    m = re.search(r"CVSS[:\s]*(\d+\.?\d*)", text, re.IGNORECASE)
    return float(m.group(1)) if m else None

def _parse_rss_feed(feed_cfg):
    try: parsed = feedparser.parse(feed_cfg["url"])
    except: return []
    advisories = []
    for entry in parsed.entries[:50]:
        title = entry.get("title","")
        desc = entry.get("summary", entry.get("description",""))
        combined = f"{title} {desc}"
        pub = entry.get("published_parsed") or entry.get("updated_parsed")
        pub_ts = time.mktime(pub) if pub else time.time()
        cvss = _extract_cvss(combined)
        advisories.append({"source": feed_cfg["source"], "title": title[:300], "description": desc[:1000],
                          "link": entry.get("link",""), "severity": _estimate_severity(combined, cvss),
                          "sectors": _classify_sectors(combined), "countries": _classify_countries(combined),
                          "published_at": pub_ts, "cve_id": _extract_cve(combined), "cvss": cvss})
    return advisories

async def _fetch_cisa_kev():
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            resp.raise_for_status()
            data = resp.json()
    except: return []
    advisories = []
    for vuln in data.get("vulnerabilities",[])[:50]:
        title = f"{vuln.get('cveID','')} — {vuln.get('vulnerabilityName','')}"
        desc = vuln.get("shortDescription","")
        combined = f"{title} {desc} {vuln.get('vendorProject','')} {vuln.get('product','')}"
        try: pub_ts = dateparser.parse(vuln.get("dateAdded","")).timestamp()
        except: pub_ts = time.time()
        advisories.append({"source": "CISA KEV", "title": title[:300], "description": desc[:1000],
                          "link": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID','')}",
                          "severity": "critical", "sectors": _classify_sectors(combined),
                          "countries": ["US","GLOBAL"], "published_at": pub_ts, "cve_id": vuln.get("cveID")})
    return advisories

async def _fetch_nvd_recent():
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"resultsPerPage": 40})
            resp.raise_for_status()
            data = resp.json()
    except: return []
    advisories = []
    for item in data.get("vulnerabilities",[])[:40]:
        cve = item.get("cve",{})
        cve_id = cve.get("id","")
        descs = cve.get("descriptions",[])
        desc_en = next((d["value"] for d in descs if d.get("lang")=="en"), descs[0]["value"] if descs else "")
        metrics = cve.get("metrics",{})
        cvss_score = None
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            ml = metrics.get(key,[])
            if ml: cvss_score = ml[0].get("cvssData",{}).get("baseScore"); break
        try: pub_ts = dateparser.parse(cve.get("published","")).timestamp()
        except: pub_ts = time.time()
        combined = f"{cve_id} {desc_en}"
        advisories.append({"source":"NVD", "title": f"{cve_id} — {desc_en[:120]}", "description": desc_en[:1000],
                          "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                          "severity": _estimate_severity(combined, cvss_score),
                          "sectors": _classify_sectors(combined), "countries": _classify_countries(combined),
                          "published_at": pub_ts, "cve_id": cve_id, "cvss": cvss_score})
    return advisories

async def fetch_all_feeds():
    all_adv = []
    for f in FEEDS:
        all_adv.extend(_parse_rss_feed(f))
    all_adv.extend(await _fetch_cisa_kev())
    all_adv.extend(await _fetch_nvd_recent())
    seen, unique = set(), []
    for a in all_adv:
        key = a["title"][:100].lower()
        if key not in seen: seen.add(key); unique.append(a)
    unique.sort(key=lambda x: x.get("published_at",0), reverse=True)
    save_advisories(unique)
    return unique

def compute_dashboard_stats(advisories):
    sector_data, country_counts, source_counts = {}, {}, {}
    severity_counts = {"critical":0,"high":0,"medium":0,"low":0}
    for adv in advisories:
        sev = adv.get("severity","medium")
        severity_counts[sev] = severity_counts.get(sev,0)+1
        source_counts[adv.get("source","unknown")] = source_counts.get(adv.get("source","unknown"),0)+1
        for sector in adv.get("sectors",[]):
            if sector not in sector_data: sector_data[sector] = {"total":0,"critical":0,"high":0,"medium":0,"low":0}
            sector_data[sector]["total"] += 1
            sector_data[sector][sev] = sector_data[sector].get(sev,0)+1
        for country in adv.get("countries",[]):
            country_counts[country] = country_counts.get(country,0)+1
    return {"total_advisories": len(advisories), "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"], "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"], "sectors_affected": len(sector_data),
            "by_sector": sector_data, "by_country": dict(sorted(country_counts.items(), key=lambda x:-x[1])),
            "by_source": source_counts, "recent_advisories": advisories[:30]}
