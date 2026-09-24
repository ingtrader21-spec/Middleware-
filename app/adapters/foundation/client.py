"""Read-only client for ``codestra-foundation``'s tenant/entitlement API.

``codestra-foundation`` (github.com/appolon1908-hue/codestra-foundation) is
the existing, already-implemented authority for tenant lifecycle, billing,
and consent/preferences (routers: ``tenants.py``, ``billing.py``,
``profiles.py``). Session Context must resolve tenant and entitlement state
by calling it, not by reimplementing tenant storage in this codebase - see
Mission-02's explicit "do not create duplicate identity/tenant authorities"
instruction.

This client exposes exactly these read operations:

  1. get_tenant            -> GET /v1/tenants/{tenant_id}
  2. list_entitlements     -> GET /v1/tenants/{tenant_id}/entitlements
  3. list_tenants          -> GET /v1/tenants

Nothing here writes to codestra-foundation. Tenant/billing/consent mutation
remains that service's own API surface, called by whatever system (Odoo,
its own admin UI) already owns those write paths.

Auth: codestra-foundation's ``app.security.current_principal`` expects a
Bearer RS256/ES256 JWT with ``sub``, ``iss``, ``aud``, ``exp``, ``iat``, a
space-delimited ``scope`` claim, and an optional ``tenant_id`` claim (a
token carrying ``foundation.admin`` in scope bypasses its per-tenant
boundary check). ``get_tenant``/``list_entitlements`` intentionally never
request that scope - they authenticate as a tenant-scoped reader only, one
call per tenant. ``list_tenants`` is cross-tenant by definition and the
authoritative codestra-foundation route requires ``foundation.admin``. The
Middleware route is correspondingly restricted to platform administrators
and operators and remains read-only. The route, scope, status filter, and
pagination contract are pinned to codestra-foundation's API catalogue and
``app/routers/tenants.py`` rather than inferred locally.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import Settings
from app.core.token_manager import ClientSecretTokenManager

LOGGER = logging.getLogger("codestra.foundation_client")
REQUEST_TIMEOUT_SECONDS = 5.0


class FoundationClientError(RuntimeError):
    pass


class FoundationUnavailable(FoundationClientError):
    """Raised on transport failure or a non-2xx response other than 404."""


class FoundationTenantNotFound(FoundationClientError):
    pass


@dataclass(frozen=True)
class TenantRecord:
    id: str
    slug: str
    name: str
    status: str


@dataclass(frozen=True)
class EntitlementRecord:
    entitlement_key: str
    enabled: bool
    limit_value: float | None
    unit: str | None


class FoundationClient:
    """Thin, read-only wrapper around codestra-foundation's tenant API."""

    def __init__(
        self,
        settings: Settings,
        *,
        token_manager: ClientSecretTokenManager | None = None,
        client_secret_loader: Any = None,
    ) -> None:
        self._settings = settings
        self._token_manager = token_manager or ClientSecretTokenManager(
            client_id=settings.foundation_client_id,
            client_secret_loader=client_secret_loader or self._load_secret,
        )

    async def _load_secret(self, _credential_reference_id: str) -> str:
        if self._settings.foundation_client_secret_file:
            with open(
                self._settings.foundation_client_secret_file, encoding="utf-8"
            ) as handle:
                return handle.read().strip()
        return self._settings.foundation_client_secret

    def _ensure_configured(self) -> None:
        if not (
            self._settings.foundation_base_url
            and self._settings.foundation_token_url
            and self._settings.foundation_client_id
        ):
            raise FoundationUnavailable(
                "codestra-foundation integration is not configured"
            )

    async def _authorized_get(
        self,
        http: httpx.AsyncClient,
        path: str,
        *,
        scopes: tuple[str, ...] = ("foundation.tenant.read",),
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        self._ensure_configured()
        token = await self._token_manager.get_token(
            http,
            token_url=self._settings.foundation_token_url,
            audience=self._settings.foundation_audience,
            scopes=scopes,
            credential_reference_id="foundation-client",
        )
        try:
            response = await http.get(
                f"{self._settings.foundation_base_url.rstrip('/')}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise FoundationUnavailable(str(exc)) from exc
        return response

    async def get_tenant(self, http: httpx.AsyncClient, tenant_id: str) -> TenantRecord:
        response = await self._authorized_get(http, f"/v1/tenants/{tenant_id}")
        if response.status_code == 404:
            raise FoundationTenantNotFound(tenant_id)
        if response.status_code != 200:
            raise FoundationUnavailable(
                f"codestra-foundation returned {response.status_code} for tenant {tenant_id}"
            )
        body = response.json()
        return TenantRecord(
            id=str(body["id"]),
            slug=body["slug"],
            name=body["name"],
            status=body["status"],
        )

    async def list_entitlements(
        self,
        http: httpx.AsyncClient,
        tenant_id: str,
    ) -> list[EntitlementRecord]:
        response = await self._authorized_get(
            http, f"/v1/tenants/{tenant_id}/entitlements"
        )
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            raise FoundationUnavailable(
                f"codestra-foundation returned {response.status_code} for entitlements of {tenant_id}"
            )
        return [
            EntitlementRecord(
                entitlement_key=item["entitlement_key"],
                enabled=bool(item["enabled"]),
                limit_value=item.get("limit_value"),
                unit=item.get("unit"),
            )
            for item in response.json()
        ]

    async def list_tenants(
        self,
        http: httpx.AsyncClient,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TenantRecord]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status is not None:
            params["status"] = status
        response = await self._authorized_get(
            http,
            "/v1/tenants",
            scopes=("foundation.admin",),
            params=params,
        )
        if response.status_code != 200:
            raise FoundationUnavailable(
                f"codestra-foundation returned {response.status_code} listing tenants"
            )
        return [
            TenantRecord(
                id=str(item["id"]),
                slug=item["slug"],
                name=item["name"],
                status=item["status"],
            )
            for item in response.json()
        ]
