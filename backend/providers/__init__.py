"""TriageOne — Provider registry."""
from backend.config import settings
from backend.providers.base import BaseProvider
from backend.providers.virustotal import VirusTotalProvider
from backend.providers.abuseipdb import AbuseIPDBProvider
from backend.providers.otx import OTXProvider
from backend.providers.urlhaus import URLhausProvider
from backend.providers.malwarebazaar import MalwareBazaarProvider
from backend.providers.apivoid import APIVoidProvider


def get_all_providers() -> list[BaseProvider]:
    return [
        VirusTotalProvider(api_key=settings.vt_api_key),
        AbuseIPDBProvider(api_key=settings.abuseipdb_api_key),
        OTXProvider(api_key=settings.otx_api_key),
        URLhausProvider(api_key=settings.abusech_auth_key),
        MalwareBazaarProvider(api_key=settings.abusech_auth_key),
        APIVoidProvider(api_key=settings.apivoid_api_key),
    ]


def get_vt_provider() -> VirusTotalProvider:
    return VirusTotalProvider(api_key=settings.vt_api_key)
