"""TriageOne — Configuration & settings."""

from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


class Settings(BaseSettings):
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    abusech_auth_key: str = ""
    apivoid_api_key: str = ""

    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    frontend_port: int = 8501
    database_path: str = "triageone.db"
    log_level: str = "INFO"

    threshold_malicious: int = 70
    threshold_suspicious: int = 40
    threshold_low_risk: int = 15

    weight_virustotal: float = 0.30
    weight_abuseipdb: float = 0.25
    weight_otx: float = 0.10
    weight_urlhaus: float = 0.10
    weight_malwarebazaar: float = 0.10
    weight_apivoid: float = 0.15

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
