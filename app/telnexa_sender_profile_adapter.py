from __future__ import annotations

from typing import Any

import httpx

from .telnexa_provider_adapter import TelnexaProviderAdapterError, TelnexaSmsAdapter


class TelnexaSenderProfileAdapterError(TelnexaProviderAdapterError):
    pass


class TelnexaSenderProfileAdapter(TelnexaSmsAdapter):
    """Provisions per-campaign Telnexa sender profiles (Milestone 9).

    A sibling of :class:`TelnexaSmsAdapter` reusing its base-URL/API-key
    transport helpers. Telnexa's real ``POST /api/v1/senders`` has no
    idempotency key of its own - a second call for the same sender value
    creates a second row rather than returning the first - so this adapter
    lists the tenant's existing senders and reuses a match by value before
    ever calling POST, instead of relying on the provider to deduplicate.
    Does not touch Telnexa's wallet/billing ledger.
    """

    SENDERS_PATH = "/api/v1/senders"

    def _sender_headers(self, tenant_id: str) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key(),
            "X-Tenant-ID": tenant_id,
            "Content-Type": "application/json",
        }

    def _require_write_enabled(self) -> None:
        if not self.settings.telnexa_write_enabled:
            raise TelnexaSenderProfileAdapterError(
                "Telnexa sender-profile provisioning is disabled by "
                "TELNEXA_WRITE_ENABLED"
            )

    async def _find_existing(
        self, *, tenant_id: str, sender: str
    ) -> dict[str, Any] | None:
        url = self._base_url() + self.SENDERS_PATH
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.get(url, headers=self._sender_headers(tenant_id))
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelnexaSenderProfileAdapterError(
                "Telnexa sender-profile lookup failed"
            ) from exc
        items = value.get("items") if isinstance(value, dict) else None
        if not isinstance(items, list):
            raise TelnexaSenderProfileAdapterError(
                "Telnexa sender-profile lookup is malformed"
            )
        for item in items:
            if isinstance(item, dict) and item.get("sender") == sender:
                return item
        return None

    async def provision_sender_profile(
        self,
        *,
        tenant_id: str,
        sender: str,
        sender_type: str = "alphanumeric",
        countries: list[str] | None = None,
    ) -> dict[str, Any]:
        self._require_write_enabled()
        existing = await self._find_existing(tenant_id=tenant_id, sender=sender)
        if existing is not None:
            return existing
        url = self._base_url() + self.SENDERS_PATH
        body = {
            "sender": sender,
            "type": sender_type,
            "countries": countries or [],
            "metadata": {},
        }
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    url, json=body, headers=self._sender_headers(tenant_id)
                )
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelnexaSenderProfileAdapterError(
                "Telnexa sender-profile provisioning failed"
            ) from exc
        if not isinstance(value, dict) or not value.get("id"):
            raise TelnexaSenderProfileAdapterError(
                "Telnexa sender-profile response is malformed"
            )
        return value

    async def readback_sender_profile(
        self, *, tenant_id: str, sender: str
    ) -> dict[str, Any] | None:
        return await self._find_existing(tenant_id=tenant_id, sender=sender)
