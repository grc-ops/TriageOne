"""TriageOne v2.1 — Classification & Filtering Service."""
from __future__ import annotations
from enum import Enum
from typing import Any
from datetime import datetime
from pydantic import BaseModel, Field


class Classification(str, Enum):
    """User-assigned classification for IOCs."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class IOCClassification(BaseModel):
    """Classification record for an IOC."""
    ioc_value: str
    classification: Classification = Classification.UNKNOWN
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analyst: str = "system"
    notes: str = ""


class FilterCriteria(BaseModel):
    """Filter criteria for IOC results."""
    ioc_types: list[str] = Field(default_factory=lambda: ["ip", "domain", "url", "md5", "sha256", "filename"])
    malicious_only: bool = False
    classifications: list[Classification] = Field(default_factory=list)


class IOCStatistics(BaseModel):
    """Statistics for a set of IOCs."""
    total_count: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    unknown_count: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_verdict: dict[str, int] = Field(default_factory=dict)


class ClassificationService:
    """Service for managing IOC classifications and filtering."""

    def __init__(self):
        # In-memory storage (in production, use database)
        self.classifications: dict[str, IOCClassification] = {}
        self.verdict_to_classification = {
            "malicious": Classification.SUSPICIOUS,
            "suspicious": Classification.SUSPICIOUS,
            "low_risk": Classification.CLEAN,
            "unknown": Classification.UNKNOWN,
        }

    def set_classification(
        self,
        ioc_value: str,
        classification: Classification,
        analyst: str = "system",
        notes: str = "",
    ) -> IOCClassification:
        """Set classification for an IOC."""
        record = IOCClassification(
            ioc_value=ioc_value,
            classification=classification,
            analyst=analyst,
            notes=notes,
            timestamp=datetime.utcnow(),
        )
        self.classifications[ioc_value] = record
        return record

    def get_classification(self, ioc_value: str) -> IOCClassification | None:
        """Get classification for an IOC."""
        return self.classifications.get(ioc_value)

    def classify_from_verdict(self, ioc_value: str, verdict: str) -> Classification:
        """Auto-classify based on vendor verdict."""
        return self.verdict_to_classification.get(verdict, Classification.UNKNOWN)

    def filter_iocs(
        self,
        iocs: list[dict[str, Any]],
        criteria: FilterCriteria,
    ) -> list[dict[str, Any]]:
        """Filter IOCs based on criteria."""
        filtered = iocs

        # Filter by type
        if criteria.ioc_types:
            filtered = [
                ioc for ioc in filtered
                if ioc.get("ioc_type", "").lower() in criteria.ioc_types
            ]

        # Filter by malicious only
        if criteria.malicious_only:
            filtered = [
                ioc for ioc in filtered
                if ioc.get("verdict", "").lower() in ["malicious", "suspicious"]
            ]

        # Filter by classification
        if criteria.classifications:
            filtered = [
                ioc for ioc in filtered
                if self.get_classification(ioc.get("ioc_value", "")).classification
                in criteria.classifications
                if ioc.get("ioc_value") in self.classifications
            ]

        return filtered

    def calculate_statistics(self, iocs: list[dict[str, Any]]) -> IOCStatistics:
        """Calculate statistics for IOCs."""
        stats = IOCStatistics(total_count=len(iocs))

        if not iocs:
            return stats

        # Count by verdict
        for ioc in iocs:
            verdict = ioc.get("verdict", "unknown").lower()
            if verdict == "malicious":
                stats.malicious_count += 1
            elif verdict == "suspicious":
                stats.suspicious_count += 1
            elif verdict == "low_risk":
                stats.clean_count += 1
            else:
                stats.unknown_count += 1

            # Count by type
            ioc_type = ioc.get("ioc_type", "unknown").lower()
            stats.by_type[ioc_type] = stats.by_type.get(ioc_type, 0) + 1

            # Count by verdict
            stats.by_verdict[verdict] = stats.by_verdict.get(verdict, 0) + 1

        return stats

    def get_color_class(self, classification: Classification | str) -> str:
        """Get CSS class for classification color."""
        if isinstance(classification, str):
            classification = Classification(classification)

        color_map = {
            Classification.CLEAN: "bg-green-50 border-green-300",
            Classification.SUSPICIOUS: "bg-red-50 border-red-300",
            Classification.UNKNOWN: "bg-yellow-50 border-yellow-300",
        }
        return color_map.get(classification, "bg-gray-50 border-gray-300")

    def get_badge_html(self, classification: Classification | str) -> str:
        """Get HTML badge for classification."""
        if isinstance(classification, str):
            classification = Classification(classification)

        color_map = {
            Classification.CLEAN: ("#059669", "Clean"),
            Classification.SUSPICIOUS: ("#dc2626", "Suspicious"),
            Classification.UNKNOWN: ("#d97706", "Unknown"),
        }

        color, label = color_map.get(
            classification, ("#6b7280", classification.value.capitalize())
        )
        return (
            f'<span style="background:{color};color:#fff;padding:4px 14px;'
            f'border-radius:6px;font-weight:600;font-size:13px;">{label}</span>'
        )

    def export_classifications(self) -> dict[str, Any]:
        """Export all classifications."""
        return {
            ioc: {
                "classification": record.classification.value,
                "timestamp": record.timestamp.isoformat(),
                "analyst": record.analyst,
                "notes": record.notes,
            }
            for ioc, record in self.classifications.items()
        }

    def import_classifications(self, data: dict[str, Any]) -> None:
        """Import classifications."""
        for ioc_value, record_data in data.items():
            classification = Classification(record_data.get("classification", "unknown"))
            self.set_classification(
                ioc_value=ioc_value,
                classification=classification,
                analyst=record_data.get("analyst", "imported"),
                notes=record_data.get("notes", ""),
            )


# Global instance
classification_service = ClassificationService()
