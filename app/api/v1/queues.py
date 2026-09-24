"""``GET /platform/v1/queues``, ``/queues/{queue_id}``, ``/members``,
``/calls``, and ``/metrics``.

Vicidialer-Codestra/Asterisk remain the runtime authority for queues, same
principle as ``calls.py``. This module introduces no new Middleware-owned
queue model. It reads:

  * ``campaign_registry``   - the reviewed catalogue of provisioned campaigns
                               (``campaign_code``, ``vicidial_campaign_id``)
  * ``integration_event``   - durable ``vicidial.hopper.low`` /
                               ``vicidial.hopper.empty`` (backlog signal, see
                               ``app.schemas.registry.HopperState``) and
                               ``vicidial.queue.abandoned`` (see
                               ``QueueAbandoned``) webhook rows
  * ``telephony_call_lifecycle`` / ``audit_event`` - reused via the same
                               ``campaign`` filter join ``calls.py`` already
                               established, for ``/calls``

Naming assumption, stated plainly: ``campaign_registry.campaign_code`` is
this org's business-unit vocabulary (``MOY``/``COD``/``SCP``/... - the same
three-letter codes as ``app.schemas.registry.Envelope.business_unit`` and the
``tenant_id`` values used throughout this API, e.g. ``calls.py``'s test
fixtures use ``COD``). A queue/campaign identifier (``HopperState
.campaign_id`` or ``QueueAbandoned.queue_id``) is treated as tenant-scoped by
looking it up in ``campaign_registry`` via ``vicidial_campaign_id`` and
reading its ``campaign_code`` as the owning tenant. An identifier not found
in ``campaign_registry`` is excluded from tenant-scoped results rather than
guessed at - fail closed, matching ``calls.py``'s convention.

``/queues/{queue_id}/members`` has no durable "queue roster" table anywhere
in this codebase (agent-to-campaign assignment is Odoo-side,
``cc.campaign.membership`` - not read here). This endpoint instead reports
agents recently *active* on the queue's campaign, derived from
``agent_call_state`` - explicitly labelled ``recently_active_agents``, not a
membership roster, to avoid implying data that does not exist here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.calls import _business_unit_column, _call_out
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import (
    AgentCallState,
    AuditEvent,
    CampaignRegistry,
    IntegrationEvent,
    TelephonyCallLifecycle,
)
from app.db.session import get_session

router = APIRouter(prefix="/platform/v1/queues", tags=["queues"])

HOPPER_EVENT_TYPES = ("vicidial.hopper.low", "vicidial.hopper.empty")
ABANDON_EVENT_TYPE = "vicidial.queue.abandoned"
RECENT_WINDOW = timedelta(hours=1)
RECENT_ACTIVE_WINDOW = timedelta(minutes=30)


async def _registry_row(session: AsyncSession, queue_id: str) -> CampaignRegistry | None:
    return await session.scalar(
        select(CampaignRegistry).where(CampaignRegistry.vicidial_campaign_id == queue_id)
    )


async def _latest_hopper(session: AsyncSession, queue_id: str) -> IntegrationEvent | None:
    stmt = (
        select(IntegrationEvent)
        .where(
            IntegrationEvent.event_type.in_(HOPPER_EVENT_TYPES),
            IntegrationEvent.entity_key == f"campaign_id:{queue_id}",
        )
        .order_by(IntegrationEvent.created_at.desc())
        .limit(1)
    )
    return await session.scalar(stmt)


async def _recent_abandon_stats(
    session: AsyncSession, queue_id: str
) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - RECENT_WINDOW
    # QueueAbandoned events key on call_id (CallIdentity), not queue_id - the
    # queue association lives inside the payload, so filter there instead.
    stmt = select(IntegrationEvent).where(
        IntegrationEvent.event_type == ABANDON_EVENT_TYPE,
        IntegrationEvent.created_at >= since,
    )
    rows = [
        row
        for row in (await session.execute(stmt)).scalars().all()
        if row.payload_json.get("queue_id") == queue_id
    ]
    wait_seconds = [row.payload_json.get("wait_seconds", 0) for row in rows]
    return {
        "abandoned_count_last_hour": len(rows),
        "avg_wait_seconds_last_hour": (
            round(sum(wait_seconds) / len(wait_seconds), 1) if wait_seconds else None
        ),
    }


def _queue_out(registry: CampaignRegistry, hopper: IntegrationEvent | None) -> dict[str, Any]:
    return {
        "queue_id": registry.vicidial_campaign_id,
        "campaign_code": registry.campaign_code,
        "name": registry.name,
        "registry_status": registry.registry_status,
        "backlog_remaining": hopper.payload_json.get("remaining") if hopper else None,
        "backlog_observed_at": hopper.payload_json.get("observed_at") if hopper else None,
    }


@router.get("")
async def list_queues(
    tenant_id: str = Query(..., description="campaign_code to scope results to"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    stmt = select(CampaignRegistry).where(CampaignRegistry.campaign_code == tenant_id)
    registries = (await session.execute(stmt)).scalars().all()

    items = []
    for registry in registries:
        hopper = await _latest_hopper(session, registry.vicidial_campaign_id)
        items.append(_queue_out(registry, hopper))
    return {"items": items}


@router.get("/{queue_id}")
async def get_queue(
    queue_id: str,
    tenant_id: str = Query(..., description="campaign_code expected to own this queue"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    registry = await _registry_row(session, queue_id)
    if registry is None or registry.campaign_code != tenant_id:
        raise HTTPException(404, "queue not found for this tenant")

    hopper = await _latest_hopper(session, queue_id)
    return _queue_out(registry, hopper)


@router.get("/{queue_id}/members")
async def list_queue_members(
    queue_id: str,
    tenant_id: str = Query(..., description="campaign_code expected to own this queue"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    registry = await _registry_row(session, queue_id)
    if registry is None or registry.campaign_code != tenant_id:
        raise HTTPException(404, "queue not found for this tenant")

    since = datetime.now(timezone.utc) - RECENT_ACTIVE_WINDOW
    stmt = (
        select(AgentCallState.agent_id)
        .where(
            AgentCallState.campaign_id == queue_id,
            AgentCallState.updated_at >= since,
        )
        .distinct()
    )
    agent_ids = list((await session.execute(stmt)).scalars().all())
    return {
        "queue_id": queue_id,
        "recently_active_agents": agent_ids,
        "window_minutes": int(RECENT_ACTIVE_WINDOW.total_seconds() // 60),
    }


@router.get("/{queue_id}/calls")
async def list_queue_calls(
    queue_id: str,
    tenant_id: str = Query(..., description="campaign_code expected to own this queue"),
    limit: int = Query(default=50, ge=1, le=200),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    registry = await _registry_row(session, queue_id)
    if registry is None or registry.campaign_code != tenant_id:
        raise HTTPException(404, "queue not found for this tenant")

    stmt = (
        select(TelephonyCallLifecycle)
        .join(
            AuditEvent,
            AuditEvent.correlation_id == TelephonyCallLifecycle.correlation_id,
        )
        .where(
            AuditEvent.action == "telephony.calls.originate",
            _business_unit_column() == tenant_id,
            AuditEvent.redacted_payload["campaign"].astext == queue_id,
        )
        .order_by(TelephonyCallLifecycle.created_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return {"items": [_call_out(row) for row in rows]}


@router.get("/{queue_id}/metrics")
async def get_queue_metrics(
    queue_id: str,
    tenant_id: str = Query(..., description="campaign_code expected to own this queue"),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)

    registry = await _registry_row(session, queue_id)
    if registry is None or registry.campaign_code != tenant_id:
        raise HTTPException(404, "queue not found for this tenant")

    hopper = await _latest_hopper(session, queue_id)
    abandon_stats = await _recent_abandon_stats(session, queue_id)
    return {
        "queue_id": queue_id,
        "backlog_remaining": hopper.payload_json.get("remaining") if hopper else None,
        "backlog_observed_at": hopper.payload_json.get("observed_at") if hopper else None,
        **abandon_stats,
    }
