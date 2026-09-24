"""``GET /platform/v1/agents/presence``, ``/agents/{user_id}/presence``, and
``GET /platform/v1/me/presence``.

VICIdial is the runtime authority for agent presence. This module does not
introduce a new Middleware-owned presence table - it reads the durable
``integration_event`` rows this codebase's own ``POST /api/v1/events/vicidial``
ingestion endpoint already writes for every ``vicidial.agent.state.changed``
webhook (see ``app.schemas.registry.AgentState``: ``agent_id``, ``state`` in
``available|busy|pause|after_call_work|offline``, ``changed_at``), taking the
most recent row per agent.

Tenant-scoping limitation, stated plainly rather than glossed over:
``integration_event`` carries no tenant/business_unit column at all (unlike
``telephony_call_lifecycle``, which at least shares a ``correlation_id`` with
a same-transaction ``audit_event`` row - see ``calls.py``). A
``vicidial.agent.state.changed`` event's envelope *does* carry
``business_unit``, but ``app.api.v1.events.ingest_vicidial`` does not persist
it onto ``integration_event`` today. To scope a tenant-wide presence list
without leaking cross-tenant state, this module instead recovers business
unit from the agent's own most recent ``agent_call_state`` row (which does
carry ``business_unit_id`` alongside ``agent_id``). An agent who has never
appeared in a tracked call has no recoverable business unit and is excluded
from tenant-scoped list results - fail closed, not fail open. The single-agent
detail endpoint (``/agents/{user_id}/presence``) applies the same check.

``PATCH /me/presence`` was deliberately NOT implemented. VICIdial presence
changes originate from the agent's phone/softphone session, not from an API
Middleware calls; no existing Vicidialer-Codestra adapter operation sets
agent presence (PR #52 added ``sync_agent``/``disable_agent``/extension and
WebRTC operations, none of which touch presence state). Building a PATCH
endpoint here would either be a no-op that lies about taking effect, or
require inventing a new external capability in a different repo outside this
task's scope. Documented as a deliberate gap, not an oversight - see the
mission report for this round.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.webphone import BrowserIdentity, browser_identity
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import AgentCallState, IntegrationEvent
from app.db.session import get_session

router = APIRouter(prefix="/platform/v1", tags=["presence"])

PRESENCE_EVENT_TYPE = "vicidial.agent.state.changed"
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _entity_key(agent_id: str) -> str:
    return f"agent_id:{agent_id}"


async def _latest_business_unit(session: AsyncSession, agent_id: str) -> str | None:
    stmt = (
        select(AgentCallState.business_unit_id)
        .where(AgentCallState.agent_id == agent_id)
        .order_by(AgentCallState.updated_at.desc())
        .limit(1)
    )
    return await session.scalar(stmt)


async def _latest_presence_row(
    session: AsyncSession, agent_id: str
) -> IntegrationEvent | None:
    stmt = (
        select(IntegrationEvent)
        .where(
            IntegrationEvent.event_type == PRESENCE_EVENT_TYPE,
            IntegrationEvent.entity_key == _entity_key(agent_id),
        )
        .order_by(IntegrationEvent.created_at.desc())
        .limit(1)
    )
    return await session.scalar(stmt)


def _presence_out(agent_id: str, row: IntegrationEvent | None) -> dict[str, Any]:
    if row is None:
        return {
            "agent_id": agent_id,
            "state": "offline",
            "changed_at": None,
            "known": False,
        }
    return {
        "agent_id": agent_id,
        "state": row.payload_json.get("state"),
        "changed_at": row.payload_json.get("changed_at"),
        "known": True,
    }


@router.get("/agents/presence")
async def list_agents_presence(
    tenant_id: str = Query(..., description="business_unit to scope results to"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    # Recover the set of agents known to this tenant via their most recent
    # tracked call, then take the latest presence row for each. There is no
    # durable "all known agents for this tenant" table independent of call
    # history - an agent who has never had a tracked call is not listable
    # here (see module docstring).
    agent_ids_stmt = (
        select(AgentCallState.agent_id)
        .where(AgentCallState.business_unit_id == tenant_id)
        .distinct()
        .limit(limit)
    )
    agent_ids = [row for row in (await session.execute(agent_ids_stmt)).scalars().all()]

    items = []
    for agent_id in agent_ids:
        row = await _latest_presence_row(session, agent_id)
        items.append(_presence_out(agent_id, row))
    return {"items": items}


@router.get("/agents/{user_id}/presence")
async def get_agent_presence(
    user_id: str,
    tenant_id: str = Query(..., description="business_unit expected to own this agent"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    business_unit = await _latest_business_unit(session, user_id)
    if business_unit != tenant_id:
        raise HTTPException(404, "agent not found for this tenant")

    row = await _latest_presence_row(session, user_id)
    return _presence_out(user_id, row)


@router.get("/me/presence")
async def get_my_presence(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    identity: BrowserIdentity = await browser_identity(request)
    row = await _latest_presence_row(session, identity.agent_id)
    return _presence_out(identity.agent_id, row)
