"""TriageOne — Weighted risk scoring engine."""
from __future__ import annotations
from backend.config import settings
from backend.models.ioc import ProviderResult, Verdict

WEIGHT_MAP = {
    "VirusTotal": settings.weight_virustotal,
    "AbuseIPDB": settings.weight_abuseipdb,
    "OTX AlienVault": settings.weight_otx,
    "URLhaus": settings.weight_urlhaus,
    "MalwareBazaar": settings.weight_malwarebazaar,
    "APIVoid": settings.weight_apivoid,
}


def compute_risk_score(results: list[ProviderResult]) -> float:
    scored = [(r, WEIGHT_MAP.get(r.provider, 0.1))
              for r in results if r.score is not None and r.available and r.error is None]
    if not scored:
        return 0.0
    total_weight = sum(w for _, w in scored)
    if total_weight == 0:
        return 0.0
    return round(sum(r.score * w for r, w in scored) / total_weight, 1)


def determine_verdict(score: float) -> Verdict:
    if score >= settings.threshold_malicious: return Verdict.MALICIOUS
    if score >= settings.threshold_suspicious: return Verdict.SUSPICIOUS
    if score >= settings.threshold_low_risk: return Verdict.LOW_RISK
    if score > 0: return Verdict.LOW_RISK
    return Verdict.UNKNOWN
