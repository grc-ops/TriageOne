"""TriageOne — Auto-generated analyst brief from triage results."""

from __future__ import annotations
from datetime import datetime
from backend.models.ioc import IOCType, ProviderResult, Verdict


def generate_analyst_brief(
    ioc_value: str,
    ioc_type: str,
    risk_score: float,
    verdict: str,
    provider_results: list[ProviderResult],
    merged_details: dict,
    vt_relations: dict | None = None,
    vt_comments: list[dict] | None = None,
) -> str:
    """Generate a one-paragraph analyst brief with recommended actions."""

    parts: list[str] = []
    ioc_upper = ioc_type.upper() if isinstance(ioc_type, str) else ioc_type

    # ── Identity line ───────────────────────────────────────────────
    country = merged_details.get("country") or merged_details.get("country_name") or ""
    country_code = merged_details.get("country_code") or ""
    as_owner = merged_details.get("as_owner") or ""
    asn = merged_details.get("asn") or ""
    isp = merged_details.get("isp") or ""
    network = merged_details.get("network") or ""

    identity = f"This {ioc_upper} ({ioc_value})"
    if ioc_type in ("ip", IOCType.IP.value):
        geo_parts = []
        if as_owner:
            geo_parts.append(f"operated by {as_owner}")
        if asn:
            geo_parts.append(f"AS{asn}")
        if country:
            geo_parts.append(f"in {country}")
            if country_code:
                geo_parts[-1] = f"in {country} ({country_code})"
        if isp and isp != as_owner:
            geo_parts.append(f"ISP: {isp}")
        if geo_parts:
            identity += " is " + ", ".join(geo_parts)
        else:
            identity += " was analyzed"
    elif ioc_type in ("domain", IOCType.DOMAIN.value):
        registrar = merged_details.get("registrar", "")
        if registrar:
            identity += f" (registrar: {registrar})"
        identity += " was analyzed"
    elif ioc_type in ("url", IOCType.URL.value):
        identity += " was analyzed"
    else:
        name = merged_details.get("meaningful_name") or merged_details.get("file_name") or ""
        type_desc = merged_details.get("type_description") or ""
        if name:
            identity += f" (filename: {name})"
        if type_desc:
            identity += f", identified as {type_desc},"
        identity += " was analyzed"
    parts.append(identity + ".")

    # ── Detection summary ───────────────────────────────────────────
    responding = [r for r in provider_results if r.score is not None and r.error is None]
    total_providers = len(responding)

    if total_providers > 0:
        detection_parts = []
        for r in responding:
            if r.raw_score and r.score is not None:
                if r.score >= 50:
                    detection_parts.append(f"{r.provider}: {r.raw_score}")
        if detection_parts:
            parts.append("Detection signals: " + "; ".join(detection_parts) + ".")

    # ── Tags and threat label ───────────────────────────────────────
    all_tags = merged_details.get("tags", [])
    threat_label = merged_details.get("threat_label", "")
    if threat_label:
        parts.append(f"Threat classification: {threat_label}.")
    elif all_tags:
        notable = [t for t in all_tags if t.lower() not in ("", "unknown")][:5]
        if notable:
            parts.append(f"Associated tags: {', '.join(notable)}.")

    # ── Crowdsourced context highlights ─────────────────────────────
    crowd = merged_details.get("crowdsourced_context", [])
    if crowd:
        highlights = []
        for ctx in crowd[:3]:
            title = ctx.get("title", "")
            if title:
                highlights.append(title)
        if highlights:
            parts.append("Crowdsourced intelligence reports: " + "; ".join(highlights) + ".")

    # ── IDS rules ───────────────────────────────────────────────────
    ids = merged_details.get("crowdsourced_ids", [])
    if ids:
        msgs = [i.get("rule_msg", "") for i in ids[:2] if i.get("rule_msg")]
        if msgs:
            parts.append(f"IDS alerts triggered: {'; '.join(msgs)}.")

    # ── Abuse reports ───────────────────────────────────────────────
    total_reports = merged_details.get("total_reports")
    distinct_users = merged_details.get("num_distinct_users")
    if total_reports and int(total_reports) > 0:
        report_str = f"AbuseIPDB shows {total_reports} abuse reports"
        if distinct_users:
            report_str += f" from {distinct_users} distinct sources"
        last_reported = merged_details.get("last_reported_at", "")
        if last_reported:
            report_str += f", last reported {last_reported}"
        parts.append(report_str + ".")

    # ── Tor / VPN / Proxy flags ─────────────────────────────────────
    flags = []
    if merged_details.get("is_tor"): flags.append("Tor exit node")
    if merged_details.get("is_vpn"): flags.append("VPN endpoint")
    if merged_details.get("is_proxy"): flags.append("proxy server")
    if flags:
        parts.append(f"Anonymity indicators: {', '.join(flags)}.")

    # ── Relations summary ───────────────────────────────────────────
    if vt_relations:
        rel_parts = []
        for rel_type, items in vt_relations.items():
            if items:
                mal_count = sum(1 for i in items if i.get("malicious", 0) > 5)
                label = rel_type.replace("_", " ")
                if mal_count > 0:
                    rel_parts.append(f"{len(items)} {label} ({mal_count} malicious)")
                else:
                    rel_parts.append(f"{len(items)} {label}")
        if rel_parts:
            parts.append("VT relations: " + ", ".join(rel_parts) + ".")

    # ── Community comments summary ──────────────────────────────────
    if vt_comments and len(vt_comments) > 0:
        parts.append(f"VirusTotal community: {len(vt_comments)} comments from security researchers.")

    # ── Verdict + score ─────────────────────────────────────────────
    verdict_label = verdict.replace("_", " ").upper() if isinstance(verdict, str) else str(verdict)
    parts.append(f"Final assessment: {verdict_label} (risk score: {risk_score}/100 across {total_providers} providers).")

    # ── Recommended actions ─────────────────────────────────────────
    actions = _get_recommended_actions(ioc_type, verdict, risk_score, merged_details)
    if actions:
        parts.append("Recommended actions: " + "; ".join(actions) + ".")

    return " ".join(parts)


def _get_recommended_actions(
    ioc_type: str, verdict: str, score: float, details: dict
) -> list[str]:
    """Generate recommended actions based on verdict and IOC type."""
    actions = []

    if verdict in ("malicious", Verdict.MALICIOUS.value):
        if ioc_type in ("ip", IOCType.IP.value):
            actions.append("block at perimeter firewall")
            actions.append("add to threat intel watchlist")
            actions.append("search SIEM for historical connections to this IP (90-day lookback)")
            if details.get("is_tor"):
                actions.append("review Tor policy and consider blocking Tor exit nodes")
        elif ioc_type in ("domain", IOCType.DOMAIN.value):
            actions.append("block domain in DNS sinkhole/proxy")
            actions.append("add to threat intel feed")
            actions.append("search DNS logs for resolution attempts")
        elif ioc_type in ("url", IOCType.URL.value):
            actions.append("block URL in web proxy/gateway")
            actions.append("check if any endpoint accessed this URL")
            actions.append("submit to sandbox for payload analysis")
        elif ioc_type in ("md5", "sha1", "sha256"):
            actions.append("quarantine any matching files on endpoints")
            actions.append("add hash to EDR block list")
            actions.append("investigate affected hosts for lateral movement")
            actions.append("check for persistence mechanisms")

    elif verdict in ("suspicious", Verdict.SUSPICIOUS.value):
        actions.append("escalate for manual review")
        actions.append("monitor for additional indicators")
        if ioc_type in ("ip", IOCType.IP.value):
            actions.append("check NetFlow/firewall logs for connection volume and patterns")
        elif ioc_type in ("domain", IOCType.DOMAIN.value):
            actions.append("monitor DNS queries and set alert threshold")

    elif verdict in ("low_risk", Verdict.LOW_RISK.value):
        actions.append("no immediate action required")
        actions.append("continue monitoring")

    return actions
