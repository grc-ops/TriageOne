"""TriageOne — Abstract base class for threat intel providers."""

from __future__ import annotations
from abc import ABC, abstractmethod
import httpx
from backend.models.ioc import IOCType, ProviderResult


class BaseProvider(ABC):
    name: str = "base"
    supported_types: list[IOCType] = []
    requires_key: bool = False
    timeout: float = 15.0

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._client: httpx.AsyncClient | None = None

    @property
    def is_available(self) -> bool:
        return not self.requires_key or bool(self.api_key)

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout), follow_redirects=True)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def query(self, value: str, ioc_type: IOCType) -> ProviderResult:
        if not self.is_available:
            return ProviderResult(provider=self.name, available=False, error="API key not configured")
        if not self.supports(ioc_type):
            return ProviderResult(provider=self.name, available=False, error=f"Does not support {ioc_type.value}")
        try:
            return await self._query(value, ioc_type)
        except httpx.TimeoutException:
            return ProviderResult(provider=self.name, available=True, error="Request timed out")
        except Exception as e:
            return ProviderResult(provider=self.name, available=True, error=str(e)[:200])

    @abstractmethod
    async def _query(self, value: str, ioc_type: IOCType) -> ProviderResult: ...
