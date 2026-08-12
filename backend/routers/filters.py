"""TriageOne v2.1 — Filters & Classification API Endpoints."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from backend.services.classification import (
    classification_service,
    Classification,
    IOCClassification,
    FilterCriteria,
    IOCStatistics,
)
from pydantic import BaseModel, Field
from typing import Any


router = APIRouter(prefix="/api/filters", tags=["filters"])


class ClassifyRequest(BaseModel):
    """Request to classify an IOC."""
    ioc_value: str
    classification: str  # "clean", "suspicious", "unknown"
    analyst: str = "analyst"
    notes: str = ""


class ClassifyResponse(BaseModel):
    """Response from classification endpoint."""
    ioc_value: str
    classification: str
    timestamp: str
    analyst: str
    badge_html: str


class FilterRequest(BaseModel):
    """Request to filter IOCs."""
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    ioc_types: list[str] = Field(
        default_factory=lambda: ["ip", "domain", "url", "md5", "sha256", "filename"]
    )
    malicious_only: bool = False


class FilterResponse(BaseModel):
    """Response from filter endpoint."""
    total_count: int
    filtered_count: int
    filtered_iocs: list[dict[str, Any]]
    statistics: dict[str, Any]


class StatisticsResponse(BaseModel):
    """Statistics response."""
    total_count: int
    malicious_count: int
    suspicious_count: int
    clean_count: int
    unknown_count: int
    by_type: dict[str, int]
    by_verdict: dict[str, int]


@router.post("/classify", response_model=ClassifyResponse)
async def classify_ioc(request: ClassifyRequest):
    """Classify an IOC."""
    try:
        classification = Classification(request.classification.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid classification. Must be: clean, suspicious, unknown",
        )

    record = classification_service.set_classification(
        ioc_value=request.ioc_value,
        classification=classification,
        analyst=request.analyst,
        notes=request.notes,
    )

    return ClassifyResponse(
        ioc_value=record.ioc_value,
        classification=record.classification.value,
        timestamp=record.timestamp.isoformat(),
        analyst=record.analyst,
        badge_html=classification_service.get_badge_html(record.classification),
    )


@router.get("/classify/{ioc_value}")
async def get_classification(ioc_value: str):
    """Get classification for an IOC."""
    record = classification_service.get_classification(ioc_value)

    if not record:
        return {
            "ioc_value": ioc_value,
            "classification": "unknown",
            "timestamp": None,
            "analyst": None,
        }

    return {
        "ioc_value": record.ioc_value,
        "classification": record.classification.value,
        "timestamp": record.timestamp.isoformat(),
        "analyst": record.analyst,
        "notes": record.notes,
    }


@router.post("/filter", response_model=FilterResponse)
async def filter_iocs(request: FilterRequest):
    """Filter IOCs based on criteria."""
    criteria = FilterCriteria(
        ioc_types=request.ioc_types,
        malicious_only=request.malicious_only,
    )

    filtered_iocs = classification_service.filter_iocs(request.iocs, criteria)
    stats = classification_service.calculate_statistics(filtered_iocs)

    return FilterResponse(
        total_count=len(request.iocs),
        filtered_count=len(filtered_iocs),
        filtered_iocs=filtered_iocs,
        statistics={
            "total": stats.total_count,
            "malicious": stats.malicious_count,
            "suspicious": stats.suspicious_count,
            "clean": stats.clean_count,
            "unknown": stats.unknown_count,
            "by_type": stats.by_type,
            "by_verdict": stats.by_verdict,
        },
    )


@router.post("/statistics", response_model=StatisticsResponse)
async def calculate_statistics(iocs: list[dict[str, Any]]):
    """Calculate statistics for IOCs."""
    stats = classification_service.calculate_statistics(iocs)

    return StatisticsResponse(
        total_count=stats.total_count,
        malicious_count=stats.malicious_count,
        suspicious_count=stats.suspicious_count,
        clean_count=stats.clean_count,
        unknown_count=stats.unknown_count,
        by_type=stats.by_type,
        by_verdict=stats.by_verdict,
    )


@router.post("/export")
async def export_classifications():
    """Export all classifications."""
    return {"data": classification_service.export_classifications()}


@router.post("/import")
async def import_classifications(data: dict[str, Any]):
    """Import classifications."""
    try:
        classification_service.import_classifications(data)
        return {"status": "ok", "message": "Classifications imported"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
