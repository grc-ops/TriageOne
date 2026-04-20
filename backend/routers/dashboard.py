"""TriageOne — /api/dashboard endpoints."""
from __future__ import annotations
from fastapi import APIRouter
from backend.database import get_cached_advisories
from backend.services.monitor import compute_dashboard_stats, fetch_all_feeds

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/refresh")
async def refresh_feeds():
    advisories = await fetch_all_feeds()
    return compute_dashboard_stats(advisories)


@router.get("/stats")
async def dashboard_stats():
    cached = get_cached_advisories(limit=300)
    if not cached:
        advisories = await fetch_all_feeds()
        return compute_dashboard_stats(advisories)
    return compute_dashboard_stats(cached)


@router.get("/advisories")
async def list_advisories(sector: str | None = None, severity: str | None = None,
                          country: str | None = None, limit: int = 50):
    cached = get_cached_advisories(limit=300)
    filtered = cached
    if sector: filtered = [a for a in filtered if sector.lower() in [s.lower() for s in a.get("sectors",[])]]
    if severity: filtered = [a for a in filtered if a.get("severity","").lower() == severity.lower()]
    if country: filtered = [a for a in filtered if country.upper() in [c.upper() for c in a.get("countries",[])]]
    return {"advisories": filtered[:limit], "total": len(filtered)}
