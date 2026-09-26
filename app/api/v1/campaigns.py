"""``GET /platform/v1/campaigns``, ``/campaigns/{campaign_id}``,
``/campaigns/{campaign_id}/members``, ``/campaigns/{campaign_id}/channels``,
``/campaigns/{campaign_id}/health``.

Campaigns are genuinely Middleware/VICIdial-domain data (unlike tenants,
which ``tenants.py`` resolves through ``codestra-foundation``). This module
reads the same ``campaign_registry`` table ``queues.py`` already reads -
note that in this deployment a VICIdial "queue" and a "campaign" are the
same underlying ``campaign_registry`` row (``vicidial_campaign_id``); this
router exposes campaign-shaped fields (channels, membership) that
``queues.py`` does not, rather than duplicating its queue/hopper-backlog
view.

``/members`` follows the exact same honesty convention ``queues.py``
established: there is no durable campaign-membership roster in this
codebase (that is Odoo-side, ``cc.campaign.membership``) - this reports
agents recently *active* in the campaign, explicitly labelled as such.

``/channels`` has no durable campaign-level channel-state table either. It
uses each agent's latest provisioning request and reports how many current
desired-state records include each channel. Historical requests and revoked,
suspended, or failed latest requests are excluded, so retries do not inflate
the result. This is still desired intent, not live effective provider state.

``/health`` reuses ``calls.py``'s ``telephony_call_lifecycle`` +
``audit_event`` business-unit join for a basic call-volume signal - no
health-scoring model exists anywhere in this codebase to draw from. Stated
limitation: the audit payload's ``campaign`` field (a ``TEST_SYN``-style
code from ``OriginateCallRequest.campaign``) was not confirmed this pass to
map cleanly onto ``campaign_registry.vicidial_campaign_id``/
``campaign_number``, so this endpoint scopes by tenant (business_unit) only,
not by the specific campaign - it reports the whole tenant's call volume,
not this campaign's alone. Narrowing this needs that mapping confirmed
first, not guessed at.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.calls import _business_unit_column
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import (
    AgentCallState,
    AgentProvisioningRequest,
    AuditEvent,
    CampaignRegistry,
    TelephonyCallLifecycle,
)
from app.db.session import get_session, set_transaction_tenant_context

router = APIRouter(prefix="/platform/v1/campaigns", tags=["campaigns"])

RECENT_ACTIVE_WINDOW = timedelta(minutes=30)
RECENT_HEALTH_WINDOW = timedelta(hours=1)
INACTIVE_PROVISIONING_STATES = frozenset({"FAILED", "SUSPENDED", "REVOKED"})


async def _registry_row(
    session: AsyncSession,
    campaign_id: str,
    tenant_id: str,
) -> CampaignRegistry:
    registry = await session.scalar(
        select(CampaignRegistry).where(
            CampaignRegistry.vicidial_campaign_id == campaign_id,
            CampaignRegistry.campaign_code == tenant_id,
        )
    )
    if registry is None:
        raise HTTPException(404, "campaign not found for this tenant")
    return registry


def _campaign_out(registry: CampaignRegistry) -> dict[str, Any]:
    return {
        "campaign_id": registry.vicidial_campaign_id,
        "campaign_number": registry.campaign_number,
        "campaign_code": registry.campaign_code,
        "name": registry.name,
        "registry_status": registry.registry_status,
    }


@router.get("")
async def list_campaigns(
    tenant_id: str = Query(..., description="campaign_code to scope results to"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    stmt = (
        select(CampaignRegistry)
        .where(CampaignRegistry.campaign_code == tenant_id)
        .order_by(CampaignRegistry.campaign_number)
        .limit(limit)
        .offset(offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    total = int(
        await session.scalar(
            select(func.count())
            .select_from(CampaignRegistry)
            .where(CampaignRegistry.campaign_code == tenant_id)
        )
        or 0
    )
    return {
        "items": [_campaign_out(row) for row in rows],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(rows),
            "total": total,
        },
    }


@router.get("/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    tenant_id: str = Query(
        ..., description="campaign_code expected to own this campaign"
    ),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    registry = await _registry_row(session, campaign_id, tenant_id)
    return _campaign_out(registry)


@router.get("/{campaign_id}/members")
async def list_campaign_members(
    campaign_id: str,
    tenant_id: str = Query(
        ..., description="campaign_code expected to own this campaign"
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    await _registry_row(session, campaign_id, tenant_id)

    since = datetime.now(UTC) - RECENT_ACTIVE_WINDOW
    stmt = (
        select(AgentCallState.agent_id)
        .where(
            AgentCallState.campaign_id == campaign_id,
            AgentCallState.updated_at >= since,
        )
        .distinct()
        .order_by(AgentCallState.agent_id)
        .limit(limit + 1)
        .offset(offset)
    )
    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    agent_ids = rows[:limit]
    return {
        "recently_active_agents": agent_ids,
        "window_minutes": int(RECENT_ACTIVE_WINDOW.total_seconds() // 60),
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(agent_ids),
            "has_more": has_more,
        },
    }


@router.get("/{campaign_id}/channels")
async def get_campaign_channels(
    campaign_id: str,
    tenant_id: str = Query(
        ..., description="campaign_code expected to own this campaign"
    ),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    await _registry_row(session, campaign_id, tenant_id)

    latest = (
        select(
            AgentProvisioningRequest.employee_id,
            AgentProvisioningRequest.campaigns_json,
            AgentProvisioningRequest.channels_json,
            AgentProvisioningRequest.state,
            func.row_number()
            .over(
                partition_by=AgentProvisioningRequest.employee_id,
                order_by=(
                    AgentProvisioningRequest.created_at.desc(),
                    AgentProvisioningRequest.id.desc(),
                ),
            )
            .label("request_rank"),
        )
        .where(AgentProvisioningRequest.tenant_id == tenant_id)
        .subquery()
    )
    requests = list(
        (
            await session.execute(
                select(latest.c.channels_json).where(
                    latest.c.request_rank == 1,
                    latest.c.state.not_in(INACTIVE_PROVISIONING_STATES),
                    latest.c.campaigns_json.contains([{"campaign_id": campaign_id}]),
                )
            )
        ).scalars()
    )

    counts: dict[str, int] = {}
    for channels_json in requests:
        for channel, desired in (channels_json or {}).items():
            if desired:
                counts[channel] = counts.get(channel, 0) + 1

    return {
        "campaign_id": campaign_id,
        "provisioning_requests_referencing_campaign": len(requests),
        "desired_channel_counts": counts,
        "projection": "latest_desired_request_per_agent",
    }


@router.get("/{campaign_id}/health")
async def get_campaign_health(
    campaign_id: str,
    tenant_id: str = Query(
        ..., description="campaign_code expected to own this campaign"
    ),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    await set_transaction_tenant_context(session, tenant_id)
    await _registry_row(session, campaign_id, tenant_id)

    since = datetime.now(UTC) - RECENT_HEALTH_WINDOW
    matching_originate = (
        select(1)
        .select_from(AuditEvent)
        .where(
            AuditEvent.action == "telephony.calls.originate",
            AuditEvent.correlation_id == TelephonyCallLifecycle.correlation_id,
            _business_unit_column() == tenant_id,
        )
        .correlate(TelephonyCallLifecycle)
    )
    states = list(
        (
            await session.execute(
                select(TelephonyCallLifecycle.lifecycle_state).where(
                    TelephonyCallLifecycle.created_at >= since,
                    exists(matching_originate),
                )
            )
        ).scalars()
    )

    return {
        "campaign_id": campaign_id,
        "scope": "tenant",
        "calls_last_hour": len(states),
        "ended_last_hour": states.count("ENDED"),
    }
