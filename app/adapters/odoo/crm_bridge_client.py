"""Client for ``codestra_middleware_bridge``'s CRM/contact HTTP surface.

``appolon1908-hue/Odoo``'s ``codestra_middleware_bridge`` addon already
implements, and is the sole authority for, contact/note/task/opportunity/
ticket state (``cc.customer.profile``, ``mail.message``, ``mail.activity``,
``crm.lead``, ``cc.helpdesk.ticket``) -- per the platform spec's "do not
duplicate Odoo CRM business logic in Middleware" rule, this client is a thin
HTTP adapter over that bridge, not a second implementation of any of it.

Auth is that controller's own ``_authenticate()`` scheme (HMAC-SHA256 over
``timestamp\\nevent_id\\nmethod\\npath\\ntenant\\ncorrelation_id\\n
idempotency_key\\nbody``), a different, narrower contract than
``app.adapters.odoo.sync.OdooRuntimeClient``'s nonce+bearer scheme used
elsewhere in this codebase for a different Odoo integration surface.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Request

from app.core.config import Settings, settings

REQUEST_TIMEOUT_SECONDS = 10.0


class CrmBridgeError(RuntimeError):
    pass


class CrmBridgeUnavailable(CrmBridgeError):
    """Transport failure or a non-2xx/404 response."""


class CrmBridgeNotFound(CrmBridgeError):
    pass


class CrmBridgeNotConfigured(CrmBridgeError):
    """Raised instead of silently no-op'ing when settings are incomplete."""


@dataclass(frozen=True)
class BridgeResponse:
    status_code: int
    body: dict[str, Any]


class OdooCrmBridgeClient:
    """Thin, signed HTTP adapter over the Odoo CRM bridge controller."""

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        if not settings.odoo_crm_bridge_base_url or not settings.odoo_crm_bridge_hmac_secret or not settings.odoo_crm_bridge_tenant_id:
            raise CrmBridgeNotConfigured(
                "odoo_crm_bridge_base_url/hmac_secret/tenant_id must all be set"
            )
        self._base_url = settings.odoo_crm_bridge_base_url.rstrip("/")
        self._secret = settings.odoo_crm_bridge_hmac_secret.encode()
        self._tenant_id = settings.odoo_crm_bridge_tenant_id
        self._client = client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)
        self._owns_client = client is None

    @property
    def configured_tenant_id(self) -> str:
        """Tenant bound to this bridge credential and service identity."""
        return self._tenant_id

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _sign(
        self, method: str, path: str, body: bytes, *, correlation_id: str, idempotency_key: str
    ) -> dict[str, str]:
        timestamp = str(int(time.time()))
        event_id = str(uuid.uuid4())
        canonical = b"\n".join(
            (
                timestamp.encode(),
                event_id.encode(),
                method.encode(),
                path.encode(),
                self._tenant_id.encode(),
                correlation_id.encode(),
                idempotency_key.encode(),
                body,
            )
        )
        signature = hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Event-ID": event_id,
            "X-Codestra-Signature": f"sha256={signature}",
            "X-Tenant-ID": self._tenant_id,
            "X-Correlation-ID": correlation_id,
            "Idempotency-Key": idempotency_key,
        }

    async def _call(
        self,
        method: str,
        path: str,
        *,
        correlation_id: str,
        idempotency_key: str,
        payload: dict[str, Any] | None = None,
    ) -> BridgeResponse:
        body = json.dumps(payload if payload is not None else {}).encode()
        headers = self._sign(
            method, path, body, correlation_id=correlation_id, idempotency_key=idempotency_key
        )
        url = f"{self._base_url}{path}"
        try:
            response = await self._client.request(method, url, content=body, headers=headers)
        except httpx.HTTPError as error:
            raise CrmBridgeUnavailable(str(error)) from error
        if response.status_code == 404:
            raise CrmBridgeNotFound(path)
        if response.status_code >= 500:
            raise CrmBridgeUnavailable(f"{response.status_code}: {response.text[:200]}")
        try:
            data = response.json()
        except ValueError as error:
            raise CrmBridgeUnavailable("non-JSON response from Odoo CRM bridge") from error
        return BridgeResponse(status_code=response.status_code, body=data)

    # -- contacts (cc.customer.profile) --

    async def list_contacts(self, *, correlation_id: str, limit: int = 50, offset: int = 0) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/customer-profiles?limit={limit}&offset={offset}",
            correlation_id=correlation_id,
            idempotency_key=f"list-contacts-{correlation_id}",
        )

    async def get_contact(self, contact_id: int, *, correlation_id: str) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}",
            correlation_id=correlation_id,
            idempotency_key=f"get-contact-{contact_id}-{correlation_id}",
        )

    async def create_contact(
        self, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            "/codestra/middleware/v1/customer-profiles",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def update_contact(
        self, contact_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "PATCH",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    # -- notes (mail.message) --

    async def list_notes(self, contact_id: int, *, correlation_id: str) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}/notes",
            correlation_id=correlation_id,
            idempotency_key=f"list-notes-{contact_id}-{correlation_id}",
        )

    async def create_note(
        self, contact_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}/notes",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def update_note(
        self, note_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "PATCH",
            f"/codestra/middleware/v1/notes/{note_id}",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    # -- tasks (mail.activity) --

    async def list_tasks(self, contact_id: int, *, correlation_id: str) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}/tasks",
            correlation_id=correlation_id,
            idempotency_key=f"list-tasks-{contact_id}-{correlation_id}",
        )

    async def create_task(
        self, contact_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            f"/codestra/middleware/v1/customer-profiles/{contact_id}/tasks",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def update_task(
        self, task_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "PATCH",
            f"/codestra/middleware/v1/tasks/{task_id}",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def complete_task(
        self, task_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            f"/codestra/middleware/v1/tasks/{task_id}/complete",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    # -- opportunities (crm.lead) -- reuses the existing crm/leads/{id}
    # read/update endpoints; list required one small, minimal addition to the
    # Odoo bridge controller (GET /crm/leads had no list handler before this
    # change), following that controller's own list-endpoint convention
    # (see cc.customer.profile's list handler in the same file).

    async def list_opportunities(self, *, correlation_id: str, limit: int = 50, offset: int = 0) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/crm/leads?limit={limit}&offset={offset}",
            correlation_id=correlation_id,
            idempotency_key=f"list-opportunities-{correlation_id}",
        )

    async def get_opportunity(self, external_id: str, *, correlation_id: str) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/crm/leads/{external_id}",
            correlation_id=correlation_id,
            idempotency_key=f"get-opportunity-{external_id}-{correlation_id}",
        )

    async def update_opportunity(
        self, external_id: str, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "PATCH",
            f"/codestra/middleware/v1/crm/leads/{external_id}",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def create_opportunity(
        self, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            "/codestra/middleware/v1/crm/leads",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    # -- tickets (cc.helpdesk.ticket) --

    async def list_tickets(self, *, correlation_id: str, limit: int = 50, offset: int = 0) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/tickets?limit={limit}&offset={offset}",
            correlation_id=correlation_id,
            idempotency_key=f"list-tickets-{correlation_id}",
        )

    async def get_ticket(self, ticket_id: int, *, correlation_id: str) -> BridgeResponse:
        return await self._call(
            "GET",
            f"/codestra/middleware/v1/tickets/{ticket_id}",
            correlation_id=correlation_id,
            idempotency_key=f"get-ticket-{ticket_id}-{correlation_id}",
        )

    async def create_ticket(
        self, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "POST",
            "/codestra/middleware/v1/tickets",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )

    async def update_ticket(
        self, ticket_id: int, payload: dict[str, Any], *, correlation_id: str, idempotency_key: str
    ) -> BridgeResponse:
        return await self._call(
            "PATCH",
            f"/codestra/middleware/v1/tickets/{ticket_id}",
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            payload=payload,
        )


def get_crm_bridge_client(request: Request) -> OdooCrmBridgeClient:
    """FastAPI dependency. Constructed lazily (not at import time) so an
    unconfigured deployment surfaces as a per-request 503 from the router,
    not an app-startup crash. The active factory runtime owns the settings;
    the module-global settings are only a compatibility fallback for the
    legacy module-level application that does not install a runtime state.
    """
    client = getattr(request.app.state, "crm_bridge_client", None)
    if client is None:
        runtime = getattr(request.app.state, "runtime", None)
        configured_settings = getattr(runtime, "settings", settings)
        client = OdooCrmBridgeClient(configured_settings)
        request.app.state.crm_bridge_client = client
    return client
