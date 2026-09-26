"""Shared plumbing for the contacts/opportunities/tickets routers.

Reads are thin adapters over ``codestra_middleware_bridge`` (see
``app.adapters.odoo.crm_bridge_client``). Writes are kernel wrappers: the
request is normalized into a ``crm.<entity>.<action>.v1`` command on the
``odoo-19`` target and submitted through the one command kernel, which
executes it asynchronously through the Odoo adapter (policy, safety,
idempotency, ledger, readback). This module carries the glue (correlation
id, idempotency key, exception mapping, the kernel submission), not any CRM
business logic.
"""

from __future__ import annotations

from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.commands import API_OPERATION_STATES, CommandEnvelope
from app.api_inputs import optional_header
from app.core.header_authority import CORRELATION_ID, IDEMPOTENCY_KEY
from app.control_plane_auth import ControlPlaneCaller
from app.core.provisioning_auth import ProvisioningPrincipal, require_tenant_match
from app.platform.principal import KernelPrincipal
from app.storage import StorageError
from app.adapters.odoo.crm_bridge_client import (
    BridgeResponse,
    CrmBridgeNotConfigured,
    CrmBridgeNotFound,
    CrmBridgeUnavailable,
)


def correlation_id(request: Request) -> str:
    return (optional_header(request, CORRELATION_ID, minimum=1, maximum=180) or str(uuid4()))


def ensure_bridge_tenant(client: object, tenant_id: str) -> None:
    """Fail closed when this bridge instance is pinned to another tenant.

    The bridge credential is configured for one tenant. The API still accepts
    a tenant selector so the caller's token can be checked at the edge, but a
    request must never be signed with the configured tenant while claiming to
    serve a different one. Test doubles may omit the property; the concrete
    OdooCrmBridgeClient always exposes it.
    """
    configured = getattr(client, "configured_tenant_id", None)
    if isinstance(configured, str) and configured and configured != tenant_id:
        raise HTTPException(
            503,
            "Odoo CRM bridge is not configured for the requested tenant",
        )


def idempotency_key(request: Request, correlation: str) -> str:
    return optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or correlation


def command_identity(request: Request, *, tenant_id: str, command_type: str) -> tuple[str, str]:
    """``(correlation_id, idempotency_key)`` for a kernel-wrapped CRM write.

    The ledger binds the idempotency key to the whole envelope, correlation
    id included, so a retry that repeats the ``Idempotency-Key`` but omits
    ``X-Correlation-ID`` must derive the same correlation id — otherwise the
    identical retry would read as identity reuse with different content (409)
    instead of the documented ``200 duplicate=true``. With neither header the
    request claims no idempotency and both values are fresh.
    """
    supplied_key = optional_header(request, IDEMPOTENCY_KEY, minimum=1, maximum=180) or ""
    supplied_cid = optional_header(request, CORRELATION_ID, minimum=1, maximum=180) or ""
    if supplied_cid:
        cid = supplied_cid
    elif supplied_key:
        cid = str(uuid5(CRM_COMMAND_NAMESPACE, f"correlation\x1f{tenant_id}\x1f{command_type}\x1f{supplied_key}"))
    else:
        cid = str(uuid4())
    return cid, supplied_key or cid


def as_response(result: BridgeResponse) -> JSONResponse:
    return JSONResponse(result.body, status_code=result.status_code)


async def call_bridge(coro) -> JSONResponse:
    """Run a ``OdooCrmBridgeClient`` call, mapping its errors to HTTP ones.

    A 4xx from the bridge (validation, tenant scoping, etc.) is relayed
    as-is via ``as_response`` -- only transport-level failures and the
    bridge's own 404 are translated here.
    """
    try:
        result = await coro
    except CrmBridgeNotConfigured as exc:
        raise HTTPException(503, str(exc)) from exc
    except CrmBridgeNotFound as exc:
        raise HTTPException(404, "not found") from exc
    except CrmBridgeUnavailable as exc:
        raise HTTPException(502, f"Odoo CRM bridge unavailable: {exc}") from exc
    return as_response(result)


# ----------------------------------------------------------------------
# V3: writes go through the command kernel, never straight to Odoo
# ----------------------------------------------------------------------
CRM_TARGET = "odoo-19"
CRM_CAPABILITY = "ODOO_WRITE"
CRM_ROUTE_SCOPE = "identity.request"
# A wrapper derives the command identity from the caller's idempotency key so
# an exact retry replays the same ledger row (the ledger digest covers the
# command id) and a different payload under the same key conflicts (409).
CRM_COMMAND_NAMESPACE = uuid5(NAMESPACE_URL, "https://contracts.codestra.co/platform/crm-command")


def _kernel(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    platform = getattr(runtime, "platform", None)
    if runtime is None or platform is None or runtime.commands is None:
        raise StorageError("command kernel is unavailable")
    return platform.kernel


def crm_principal(principal: ProvisioningPrincipal) -> KernelPrincipal:
    """The verified provisioning identity as a kernel principal.

    The route already verified the JWT (issuer, audience, azp, scope) and
    the tenant grant; the wrapper declares the authority it delegates — the
    ``crm.`` family on ``odoo-19`` — so the Policy Engine decides on exactly
    that, never on a body-supplied claim.
    """
    authority = ControlPlaneCaller(
        client_id=principal.authorized_party,
        command_scope=CRM_ROUTE_SCOPE,
        status_scope=CRM_ROUTE_SCOPE,
        allowed_command_prefixes=("crm.",),
        allowed_targets=frozenset({CRM_TARGET}),
        connector_commands_allowed=True,
        compatibility_only=False,
    )
    return KernelPrincipal(
        subject=principal.subject,
        client_id=principal.authorized_party,
        tenants=tuple(sorted(principal.tenant_ids)),
        roles=(),
        scopes=(CRM_ROUTE_SCOPE,),
        caller=authority,
    )


async def submit_crm_command(
    request: Request,
    *,
    principal: ProvisioningPrincipal,
    tenant_id: str,
    command_type: str,
    payload: dict[str, Any],
) -> JSONResponse:
    """Normalize a CRM write into the kernel and answer 202 + Location."""
    require_tenant_match(principal, tenant_id)
    cid, key = command_identity(request, tenant_id=tenant_id, command_type=command_type)
    if not 8 <= len(key) <= 180:
        raise HTTPException(400, "Idempotency-Key must contain 8 to 180 characters")
    envelope = CommandEnvelope(
        command_id=uuid5(CRM_COMMAND_NAMESPACE, f"{tenant_id}{command_type}{key}"),
        command_type=command_type,
        command_version="1.0",
        target=CRM_TARGET,
        tenant_id=tenant_id,
        requested_by=principal.subject,
        correlation_id=cid,
        idempotency_key=key,
        capability=CRM_CAPABILITY,
        payload=payload,
    )
    result = await _kernel(request).submit(
        envelope, crm_principal(principal), required_scope=CRM_ROUTE_SCOPE
    )
    operation = result.operation
    body = {
        "operation_id": str(operation.command_id),
        "command_id": str(operation.command_id),
        "state": API_OPERATION_STATES[operation.state],
        "correlation_id": operation.correlation_id,
        "duplicate": operation.duplicate,
    }
    return JSONResponse(
        body,
        status_code=200 if operation.duplicate else 202,
        headers={
            "Location": f"/platform/v1/operations/{operation.command_id}",
            "X-Correlation-ID": operation.correlation_id,
        },
    )
