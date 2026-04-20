"""TriageOne — IOC triage orchestrator with deep scan."""
from __future__ import annotations
import asyncio
import time
from backend.database import save_triage_result
from backend.models.ioc import IOCType, ProviderResult, TriageResult, Verdict
from backend.providers import get_all_providers, get_vt_provider
from backend.services.risk_scorer import compute_risk_score, determine_verdict
from backend.services.analyst_brief import generate_analyst_brief
from backend.utils.detector import defang, detect_ioc_type


async def triage_single(value: str, ioc_type_override=None, deep_scan=False) -> TriageResult:
    clean = defang(value)
    ioc_type = ioc_type_override or detect_ioc_type(clean)
    if ioc_type == IOCType.UNKNOWN:
        return TriageResult(ioc_value=clean, ioc_type=ioc_type, verdict=Verdict.UNKNOWN)

    providers = get_all_providers()
    applicable = [p for p in providers if p.supports(ioc_type) and p.is_available]

    start = time.monotonic()
    tasks = [p.query(clean, ioc_type) for p in applicable]
    results: list[ProviderResult] = await asyncio.gather(*tasks, return_exceptions=False)
    elapsed_ms = round((time.monotonic() - start) * 1000, 1)

    for p in providers:
        await p.close()

    risk_score = compute_risk_score(results)
    verdict = determine_verdict(risk_score)

    merged_details: dict = {}
    all_tags: list[str] = []
    for r in results:
        if r.details:
            for k, v in r.details.items():
                if v and k not in merged_details:
                    merged_details[k] = v
        all_tags.extend(r.tags)
    merged_details["tags"] = list(dict.fromkeys(all_tags))[:20]

    # Deep scan: fetch VT relations and comments
    vt_relations = {}
    vt_comments = []
    if deep_scan:
        vt = get_vt_provider()
        if vt.is_available:
            try:
                vt_relations = await vt.fetch_relations(clean, ioc_type)
                vt_comments = await vt.fetch_comments(clean, ioc_type)
            except Exception:
                pass
            finally:
                await vt.close()

    # Generate analyst brief
    brief = generate_analyst_brief(
        ioc_value=clean, ioc_type=ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
        risk_score=risk_score,
        verdict=verdict.value if isinstance(verdict, Verdict) else verdict,
        provider_results=results, merged_details=merged_details,
        vt_relations=vt_relations, vt_comments=vt_comments,
    )

    result = TriageResult(
        ioc_value=clean, ioc_type=ioc_type, risk_score=risk_score, verdict=verdict,
        provider_results=results,
        providers_queried=len(applicable),
        providers_responded=sum(1 for r in results if r.error is None),
        query_time_ms=elapsed_ms, details=merged_details,
        analyst_brief=brief, vt_relations=vt_relations, vt_comments=vt_comments,
    )

    try:
        save_triage_result(
            ioc_value=clean,
            ioc_type=ioc_type.value if isinstance(ioc_type, IOCType) else ioc_type,
            risk_score=risk_score,
            verdict=verdict.value if isinstance(verdict, Verdict) else verdict,
            provider_results={r.provider: r.model_dump() for r in results},
            details=merged_details,
        )
    except Exception:
        pass
    return result


async def triage_bulk(values: list[str]) -> list[TriageResult]:
    sem = asyncio.Semaphore(5)
    async def _limited(v):
        async with sem:
            return await triage_single(v)
    return await asyncio.gather(*[_limited(v) for v in values])
