from __future__ import annotations

from typing import Any

import httpx

from .klyrow_email_adapter import KlyrowEmailAdapter, KlyrowEmailAdapterError


class KlyrowSenderIdentityAdapterError(KlyrowEmailAdapterError):
    pass


class KlyrowSenderIdentityAdapter(KlyrowEmailAdapter):
    """Provisions per-campaign Klyrow sender identities (Milestone 8).

    A sibling of :class:`KlyrowEmailAdapter` that reuses its private
    transport helpers (approved private base URL, mTLS context, OAuth
    client-credentials token) but calls the service-authenticated
    ``/v1/internal/sender-identities`` API instead of the message-send
    endpoint. That endpoint is itself idempotent by tenant+address, so no
    separate idempotency bookkeeping is needed here - a retry after a
    prior success returns the same identity rather than erroring or
    duplicating it.
    """

    SENDER_IDENTITIES_PATH = "/v1/internal/sender-identities"
    SENDER_IDENTITY_PATH = SENDER_IDENTITIES_PATH + "/{item_id}"
    ACTIVE_STATUSES = frozenset({"ACTIVE"})

    async def _auth_headers(
        self, tenant_id: str, correlation_id: str
    ) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": "Bearer " + await self._access_token(),
            "Content-Type": "application/json",
            "X-Tenant-ID": tenant_id,
            "X-Klyrow-Tenant-Id": tenant_id,
            "X-Correlation-ID": correlation_id,
        }

    def _require_write_enabled(self) -> None:
        if not self.settings.klyrow_write_enabled:
            raise KlyrowSenderIdentityAdapterError(
                "Klyrow sender-identity provisioning is disabled by "
                "KLYROW_WRITE_ENABLED"
            )

    async def provision_sender_identity(
        self,
        *,
        tenant_id: str,
        domain_claim_id: str,
        email: str,
        display_name: str,
        correlation_id: str,
        stream: str = "transactional",
    ) -> dict[str, Any]:
        self._require_write_enabled()
        url = self._base_url() + self.SENDER_IDENTITIES_PATH
        tls_context = self._tls_context()
        headers = await self._auth_headers(tenant_id, correlation_id)
        body = {
            "domain_claim_id": domain_claim_id,
            "email": email,
            "display_name": display_name,
            "stream": stream,
        }
        try:
            async with httpx.AsyncClient(
                verify=tls_context,
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(url, json=body, headers=headers)
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KlyrowSenderIdentityAdapterError(
                "Klyrow sender-identity provisioning failed"
            ) from exc
        if not isinstance(value, dict) or not value.get("id"):
            raise KlyrowSenderIdentityAdapterError(
                "Klyrow sender-identity response is malformed"
            )
        return value

    async def readback_sender_identity(
        self, *, tenant_id: str, item_id: str, correlation_id: str
    ) -> dict[str, Any]:
        url = self._base_url() + self.SENDER_IDENTITY_PATH.format(item_id=item_id)
        tls_context = self._tls_context()
        headers = await self._auth_headers(tenant_id, correlation_id)
        try:
            async with httpx.AsyncClient(
                verify=tls_context,
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
            ) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                value = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KlyrowSenderIdentityAdapterError(
                "Klyrow sender-identity readback failed"
            ) from exc
        if not isinstance(value, dict):
            raise KlyrowSenderIdentityAdapterError(
                "Klyrow sender-identity readback is malformed"
            )
        return value
