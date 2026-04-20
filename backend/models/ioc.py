"""TriageOne — Pydantic schemas for IOC triage."""

from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    FILENAME = "filename"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LOW_RISK = "low_risk"
    UNKNOWN = "unknown"


class TriageRequest(BaseModel):
    value: str = Field(..., min_length=1)
    ioc_type: IOCType | None = None
    deep_scan: bool = False


class BulkTriageRequest(BaseModel):
    values: list[str] = Field(..., min_length=1, max_length=100)


class ProviderResult(BaseModel):
    provider: str
    available: bool = True
    score: float | None = None
    raw_score: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    error: str | None = None


class TriageResult(BaseModel):
    ioc_value: str
    ioc_type: IOCType
    risk_score: float = Field(0.0, ge=0, le=100)
    verdict: Verdict = Verdict.UNKNOWN
    provider_results: list[ProviderResult] = Field(default_factory=list)
    providers_queried: int = 0
    providers_responded: int = 0
    query_time_ms: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    analyst_brief: str = ""
    vt_relations: dict[str, Any] = Field(default_factory=dict)
    vt_comments: list[dict[str, Any]] = Field(default_factory=list)

    class Config:
        use_enum_values = True
