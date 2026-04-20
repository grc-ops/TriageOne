"""TriageOne — /api/triage endpoints."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from backend.database import get_history_stats, get_triage_history
from backend.models.ioc import BulkTriageRequest, TriageRequest, TriageResult
from backend.services.ioc_triage import triage_bulk, triage_single
from backend.utils.detector import detect_ioc_type

router = APIRouter(prefix="/api/triage", tags=["triage"])


@router.post("/single", response_model=TriageResult)
async def triage_single_endpoint(req: TriageRequest):
    return await triage_single(req.value, req.ioc_type, deep_scan=req.deep_scan)


@router.post("/bulk", response_model=list[TriageResult])
async def triage_bulk_endpoint(req: BulkTriageRequest):
    if len(req.values) > 100:
        raise HTTPException(400, "Maximum 100 IOCs per bulk request")
    return await triage_bulk(req.values)


@router.get("/detect")
async def detect_type(value: str):
    return {"value": value, "ioc_type": detect_ioc_type(value).value}


@router.get("/history")
async def history(limit: int = 50, offset: int = 0):
    return {"results": get_triage_history(limit=limit, offset=offset), "limit": limit, "offset": offset}


@router.get("/stats")
async def stats():
    return get_history_stats()
