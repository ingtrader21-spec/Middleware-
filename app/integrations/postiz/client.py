from collections.abc import Mapping
from typing import Any

import httpx

from app.core.config import settings
from .exceptions import PostizError


class PostizClient:
    """Small async client for the installed Postiz public API.

    It is deliberately provider-only: callers are middleware routes and never
    Odoo or n8n. The API key is read from the root-owned middleware secret.
    """

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = settings.postiz_internal_base_url.rstrip("/")
        self.timeout = settings.postiz_timeout_seconds
        self.transport = transport

    def _url(self, path: str) -> str:
        if not self.base_url:
            raise PostizError("not_configured", "Postiz base URL is not configured")
        return f"{self.base_url}/api/public/v1/{path.lstrip('/')}"

    def _headers(self, correlation_id: str | None = None) -> dict[str, str]:
        key = settings.postiz_api_key
        if not key:
            raise PostizError("not_configured", "Postiz API key is not configured")
        headers = {"Authorization": key, "Accept": "application/json"}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        return headers

    async def request(self, method: str, path: str, *, correlation_id: str | None = None, **kwargs: Any) -> Any:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                response = await client.request(method, self._url(path), headers=self._headers(correlation_id), **kwargs)
        except httpx.ReadTimeout as exc:
            raise PostizError("unknown_result", "Postiz result is unknown", unknown_result=True) from exc
        except (httpx.ConnectTimeout, httpx.ConnectError, httpx.NetworkError) as exc:
            raise PostizError("temporary", "Postiz connection failed", retryable=True) from exc
        if response.status_code == 429:
            raise PostizError("rate_limit", "Postiz rate limit reached", retryable=True, status=429)
        if response.status_code in (401, 403):
            raise PostizError("authentication", "Postiz authentication failed", status=response.status_code)
        if response.status_code >= 500:
            raise PostizError("temporary", "Postiz service unavailable", retryable=True, status=response.status_code)
        if response.status_code >= 400:
            raise PostizError("provider_error", "Postiz rejected the request", status=response.status_code)
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise PostizError("provider_error", "Postiz returned invalid JSON", status=response.status_code) from exc

    async def connection_check(self, correlation_id: str) -> Any:
        return await self.request("GET", "integrations", correlation_id=correlation_id)

    async def channels(self, correlation_id: str) -> Any:
        query = {"group": settings.postiz_organization_reference} if settings.postiz_organization_reference else None
        return await self.request("GET", "integrations", params=query, correlation_id=correlation_id)

    async def create_post(self, payload: Mapping[str, Any], correlation_id: str) -> Any:
        return await self.request("POST", "posts", json=dict(payload), correlation_id=correlation_id)

    async def upload_from_url(self, url: str, correlation_id: str) -> Any:
        return await self.request("POST", "upload-from-url", json={"url": url}, correlation_id=correlation_id)

    async def list_posts(self, *, start_date: str, end_date: str, correlation_id: str) -> Any:
        return await self.request("GET", "posts", params={"startDate": start_date, "endDate": end_date}, correlation_id=correlation_id)

    async def cancel_post(self, post_id: str, correlation_id: str) -> Any:
        return await self.request("DELETE", f"posts/{post_id}", correlation_id=correlation_id)

    async def analytics(self, integration_id: str, date: str, correlation_id: str) -> Any:
        return await self.request("GET", f"analytics/{integration_id}", params={"date": date}, correlation_id=correlation_id)
