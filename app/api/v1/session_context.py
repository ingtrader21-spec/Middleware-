"""``GET /platform/v1/session/context`` and ``POST .../select``.

The one authorization-center endpoint every Codestra UI/product is meant to
call after login (per the platform API spec). Resolves, per request, rather
than trusting a long-lived token claim:

  * identity + global role      -> this codebase's own agent-provisioning
                                    read-side state (there is no separate
                                    durable platform-user table yet - see
                                    ``app.api.v1.agent_provisioning_reads``'s
                                    module docstring for why)
  * tenant + entitlements        -> codestra-foundation (already implements
                                    this; never reimplemented here - see
                                    ``app.adapters.foundation.client``)
  * campaign memberships/channels -> this codebase's own
                                    ``AgentProvisioningRequest``/``Step`` rows

Never places dynamic campaign/channel/entitlement state into a Keycloak
token; this endpoint is the resolution point precisely so tokens can stay
small, per the spec's explicit instruction.

``POST /session/context/select`` does not mutate any stored state - there is
nothing durable to select "into" in this codebase yet (no session/context
table). It validates the requested tenant/campaign against what the
caller's own token and provisioning records actually cover, and echoes back
the same context shape scoped to that selection. A future durable "active
context" concept, if ever needed, is out of scope here - documented as a
limitation rather than invented.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.foundation.client import (
    FoundationClient,
    FoundationTenantNotFound,
    FoundationUnavailable,
)
from app.api.v1.agent_provisioning import AgentProvisioningRequest
from app.core.config import settings
from app.core.providers import get_http_client
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.session import get_session

router = APIRouter(prefix="/platform/v1/session", tags=["session-context"])

POLICY_REVISION = settings.agent_provisioning_policy_revision


async def _latest_requests_for_tenant(
    session: AsyncSession, tenant_id: str,
) -> list[AgentProvisioningRequest]:
    stmt = (
        select(AgentProvisioningRequest)
        .where(AgentProvisioningRequest.tenant_id == tenant_id)
        .order_by(AgentProvisioningRequest.created_at.desc())
        .limit(500)
    )
    return list((await session.execute(stmt)).scalars().all())


def _campaigns_for(request: AgentProvisioningRequest) -> list[dict[str, Any]]:
    return [
        {"campaign_id": entry.get("campaign_id"), "role": entry.get("role")}
        for entry in (request.campaigns_json or [])
        if isinstance(entry, dict) and entry.get("campaign_id")
    ]


def _products_for(request: AgentProvisioningRequest) -> dict[str, dict[str, bool]]:
    channels = request.channels_json or {}
    return {
        channel: {"effective": bool(enabled) and request.state == "EFFECTIVE"}
        for channel, enabled in channels.items()
    }


async def _resolve_context(
    session: AsyncSession, principal: ProvisioningPrincipal, tenant_id: str, http: httpx.AsyncClient,
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    foundation = FoundationClient(settings)
    tenant_status = "UNKNOWN"
    entitlements: list[dict[str, Any]] = []
    try:
        tenant = await foundation.get_tenant(http, tenant_id)
        tenant_status = tenant.status
        entitlement_records = await foundation.list_entitlements(http, tenant_id)
        entitlements = [
            {"key": item.entitlement_key, "enabled": item.enabled}
            for item in entitlement_records
        ]
    except FoundationTenantNotFound:
        raise HTTPException(404, "tenant not found in codestra-foundation") from None
    except FoundationUnavailable:
        # Fail closed on entitlement resolution, not on the whole
        # endpoint - a foundation outage should not take down every
        # other Codestra UI's login, but it must not fabricate
        # entitlement state either. tenant_status stays "UNKNOWN" and
        # entitlements stays empty (deny-by-default), which callers
        # must treat as "resolve again", not "no entitlements".
        tenant_status = "UNAVAILABLE"

    requests_for_tenant = await _latest_requests_for_tenant(session, tenant_id)
    campaigns: dict[str, dict[str, Any]] = {}
    products: dict[str, dict[str, bool]] = {}
    for request in requests_for_tenant:
        for entry in _campaigns_for(request):
            campaigns.setdefault(entry["campaign_id"], entry)
        for channel, state in _products_for(request).items():
            existing = products.get(channel, {"effective": False})
            products[channel] = {"effective": existing["effective"] or state["effective"]}

    return {
        "subject": principal.subject,
        "tenant_id": tenant_id,
        "tenant_status": tenant_status,
        "campaigns": list(campaigns.values()),
        "products": products,
        "entitlements": entitlements,
        "permissions": sorted(principal.tenant_ids and {"session.context.read"} or set()),
        "routing": {"home": "/platform", "requires_context_selection": len(campaigns) > 1},
        "policy_revision": POLICY_REVISION,
    }


class ContextSelectRequest(BaseModel):
    tenant_id: str
    campaign_id: str | None = None


@router.get("/context")
async def get_session_context(
    tenant_id: str,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
    http: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, Any]:
    return await _resolve_context(session, principal, tenant_id, http)


@router.post("/context/select")
async def select_session_context(
    payload: ContextSelectRequest,
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
    http: httpx.AsyncClient = Depends(get_http_client),
) -> dict[str, Any]:
    context = await _resolve_context(session, principal, payload.tenant_id, http)
    if payload.campaign_id is not None:
        matching = [c for c in context["campaigns"] if c["campaign_id"] == payload.campaign_id]
        if not matching:
            raise HTTPException(
                403, "requested campaign is not authorized for this identity/tenant"
            )
        context["selected_campaign_id"] = payload.campaign_id
    return context
