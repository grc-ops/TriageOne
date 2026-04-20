"""TriageOne — Pydantic schemas for monitoring dashboard."""
from __future__ import annotations
from pydantic import BaseModel, Field


class Advisory(BaseModel):
    source: str
    title: str
    description: str = ""
    link: str = ""
    severity: str = "medium"
    sectors: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    published_at: float | None = None
    cvss: float | None = None
    cve_id: str | None = None
    affected_products: list[str] = Field(default_factory=list)


class DashboardStats(BaseModel):
    total_advisories: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    sectors_affected: int = 0
    by_sector: dict[str, dict] = Field(default_factory=dict)
    by_country: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    recent_advisories: list[Advisory] = Field(default_factory=list)
