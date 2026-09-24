"""Read-side API for the agent provisioning saga (Milestone 3 read endpoints).

Everything the saga writes (``AgentProvisioningRequest`` /
``AgentProvisioningStep``, see ``app.api.v1.agent_provisioning``) was, until
now, only reachable by already knowing a specific ``request_id`` - there was
no way to ask "what is this person's actual state" without one. This module
adds that surface, scoped by ``employee_id`` (the closest thing this schema
has to a durable "platform user id" - there is no separate platform-user
table; see ``AgentProvisioningRequest``'s own docstring) and by channel
(telephony/email/sms).

There is one ``AgentProvisioningRequest`` row per saga *run*, not one durable
"user" row - so "current state for a user" here means the most recently
created request for that ``(tenant_id, employee_id)`` pair. A second
Provision click for the same person creates a new row rather than mutating
the old one, matching the write side's own create-a-new-saga-per-command
design. Likewise, campaign membership has no independent effective/step
state in this schema (``AgentProvisioningStep``'s system check constraint has
no per-campaign row) - ``/users/{employee_id}/campaigns`` returns the
request's desired ``campaigns_json`` plus the saga's overall state, which is
the most precise signal actually available; a true per-campaign effective
projection would need a durable campaign-membership table this codebase
does not have yet (the same gap already flagged for Klyrow's tenant-only,
not per-campaign, workspace model).

Never returns provider secrets: only ``external_reference`` (an opaque id
Vicidialer-Codestra/Klyrow/Telnexa hand back on success), never the WebRTC
ticket, SIP credential, or provider API keys - those are issued once, at
mutation time, by the write-side routes and this codebase's existing
adapters, never re-readable here.
"""

from __future__ import annotations

import base64
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.agent_provisioning import (
    AgentProvisioningRequest,
    AgentProvisioningStep,
    ProvisioningPrincipal,
    _append_audit,
    _public_view,
    _steps_for,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.session import get_session

router = APIRouter(prefix="/platform/v1", tags=["agent-provisioning-reads"])

# channel -> (adapter "system" name in AgentProvisioningStep, its operations)
# taken directly from _run_channel_provisioning_step's actual _add_step calls
# in app.api.v1.agent_provisioning - not the spec's assumed names.
_CHANNEL_SYSTEMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "phone": ("vicidial", ("sync_agent", "reserve_extension", "adopt_extension", "provision_phone")),
    "webrtc": ("vicidial", ("provision_webrtc",)),
    "email": ("klyrow", ("provision_sender_identity",)),
    "sms": ("telnexa", ("provision_sender_profile",)),
    "odoo": ("keycloak", ("create_user",)),
}

DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# Sender-identity reads (email/sms) are the only reads in this module backed
# by a shared, tenant-wide, multi-campaign resource (Klyrow/Telnexa have no
# per-campaign workspace - see this module's docstring and
# KlyrowSenderIdentityAdapter's own docstring), so they get the same
# in-process rate-limit pattern already used for mutating telephony
# operations (app.api.v1.telephony._rate_limit_originate) rather than a new
# mechanism, to bound how fast a caller can enumerate campaign sender data.
_SENDER_IDENTITY_READS_PER_MINUTE = 30
_sender_identity_read_requests: dict[str, deque[float]] = defaultdict(deque)


def _rate_limit_sender_identity_read(key: str) -> None:
    now = time.monotonic()
    bucket = _sender_identity_read_requests[key]
    while bucket and bucket[0] < now - 60:
        bucket.popleft()
    if len(bucket) >= _SENDER_IDENTITY_READS_PER_MINUTE:
        raise HTTPException(429, "sender identity read rate limit exceeded")
    bucket.append(now)


async def _latest_request(
    session: AsyncSession, tenant_id: str, employee_id: str,
) -> AgentProvisioningRequest:
    stmt = (
        select(AgentProvisioningRequest)
        .where(
            AgentProvisioningRequest.tenant_id == tenant_id,
            AgentProvisioningRequest.employee_id == employee_id,
        )
        .order_by(AgentProvisioningRequest.created_at.desc(), AgentProvisioningRequest.id.desc())
        .limit(1)
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "no provisioning request found for this user")
    return row


def _channel_state(
    channel: str, request: AgentProvisioningRequest, steps: list[AgentProvisioningStep],
) -> dict[str, Any]:
    desired_enabled = bool(request.channels_json.get(channel))
    system, operations = _CHANNEL_SYSTEMS[channel]
    matching = [s for s in steps if s.system == system and s.operation in operations]
    # A retry after PARTIAL adds a new step row rather than mutating the old
    # one (see _run_channel_provisioning_step's reconciliation docstring),
    # and _steps_for orders by created_at ascending - so the last matching
    # row is this channel's current state.
    latest = matching[-1] if matching else None
    if latest is None:
        return {
            "channel": channel,
            "desired_enabled": desired_enabled,
            "requested_state": None,
            "provisioned_state": None,
            "effective_access": False,
            "provider": system if desired_enabled else None,
            "provider_reference": None,
            "last_error_code": None,
            "last_error_summary": None,
            "last_verified_at": None,
        }
    return {
        "channel": channel,
        "desired_enabled": desired_enabled,
        "requested_state": latest.operation,
        "provisioned_state": latest.state,
        "effective_access": latest.state == "succeeded",
        "provider": system,
        "provider_reference": latest.external_reference,
        "last_error_code": latest.error_code,
        "last_error_summary": latest.error_summary,
        "last_verified_at": latest.completed_at,
    }


def _encode_cursor(created_at: datetime, row_id: UUID) -> str:
    raw = f"{created_at.isoformat()}|{row_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts, _, rid = raw.partition("|")
        return datetime.fromisoformat(ts), UUID(rid)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "invalid cursor") from exc


def _channel_filter(channels: tuple[str, ...]):
    return or_(*(AgentProvisioningRequest.channels_json[c].astext == "true" for c in channels))


async def _list_by_channel(
    session: AsyncSession, *, tenant_id: str, channels: tuple[str, ...],
    employee_id: str | None, limit: int, cursor: str | None,
) -> tuple[list[AgentProvisioningRequest], str | None]:
    stmt = select(AgentProvisioningRequest).where(
        AgentProvisioningRequest.tenant_id == tenant_id, _channel_filter(channels),
    )
    if employee_id:
        stmt = stmt.where(AgentProvisioningRequest.employee_id == employee_id)
    if cursor:
        cursor_created_at, cursor_id = _decode_cursor(cursor)
        stmt = stmt.where(
            or_(
                AgentProvisioningRequest.created_at < cursor_created_at,
                and_(
                    AgentProvisioningRequest.created_at == cursor_created_at,
                    AgentProvisioningRequest.id < cursor_id,
                ),
            )
        )
    stmt = stmt.order_by(
        AgentProvisioningRequest.created_at.desc(), AgentProvisioningRequest.id.desc(),
    ).limit(limit + 1)
    rows = list((await session.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = _encode_cursor(rows[-1].created_at, rows[-1].id) if has_more and rows else None
    return rows, next_cursor


@router.get("/users/{employee_id}")
async def get_user(
    employee_id: str,
    tenant_id: str = Query(..., min_length=1, max_length=64),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    request = await _latest_request(session, tenant_id, employee_id)
    require_tenant_match(principal, request.tenant_id)
    steps = await _steps_for(session, request)
    view = _public_view(request, steps)
    view["employee_id"] = request.employee_id
    view["primary_email"] = request.primary_email
    return view


@router.get("/users/{employee_id}/campaigns")
async def get_user_campaigns(
    employee_id: str,
    tenant_id: str = Query(..., min_length=1, max_length=64),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    request = await _latest_request(session, tenant_id, employee_id)
    require_tenant_match(principal, request.tenant_id)
    return {
        "employee_id": request.employee_id,
        "tenant_id": request.tenant_id,
        "request_state": request.state,
        "campaigns": request.campaigns_json,
    }


@router.get("/users/{employee_id}/entitlements")
async def get_user_entitlements(
    employee_id: str,
    tenant_id: str = Query(..., min_length=1, max_length=64),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    request = await _latest_request(session, tenant_id, employee_id)
    require_tenant_match(principal, request.tenant_id)
    steps = await _steps_for(session, request)
    return {
        "employee_id": request.employee_id,
        "tenant_id": request.tenant_id,
        "request_state": request.state,
        "channels": [
            _channel_state(c, request, steps)
            for c in ("odoo", "phone", "webrtc", "sms", "email")
        ],
    }


@router.get("/telephony/assignments")
async def list_telephony_assignments(
    tenant_id: str = Query(..., min_length=1, max_length=64),
    employee_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    rows, next_cursor = await _list_by_channel(
        session, tenant_id=tenant_id, channels=("phone", "webrtc"),
        employee_id=employee_id, limit=limit, cursor=cursor,
    )
    items = []
    for request in rows:
        steps = await _steps_for(session, request)
        telephony = request.channels_json.get("_telephony", {})
        items.append({
            "employee_id": request.employee_id,
            "tenant_id": request.tenant_id,
            "incoming_allowed": telephony.get("incoming_allowed", True),
            "outgoing_allowed": telephony.get("outgoing_allowed", True),
            "desired_extension": telephony.get("existing_extension"),
            "extension_pool": telephony.get("extension_pool"),
            "phone": _channel_state("phone", request, steps),
            "webrtc": _channel_state("webrtc", request, steps),
        })
    return {"items": items, "next_cursor": next_cursor}


def _matching_campaign(
    request: AgentProvisioningRequest, campaign_id: str | None,
) -> dict[str, Any] | None:
    """The campaign entry a caller is actually allowed to see for this row.

    Klyrow/Telnexa have no per-campaign workspace, so multiple campaigns'
    sender identities can live in one request's ``campaigns_json``. Without a
    filter, list_email_identities/list_sms_identities used to always report
    ``campaigns_json[0]`` regardless of which campaign a caller actually
    asked about - effectively handing back whichever campaign happened to be
    first, even to a caller only entitled to see one specific campaign. When
    ``campaign_id`` is supplied, a row that does not actually contain that
    campaign is not a match at all (the caller gets nothing for it, not
    another campaign's data); when omitted, behavior is unchanged from
    before (first entry), since scoping is opt-in via the new parameter.
    """
    campaigns = request.campaigns_json or []
    if campaign_id is None:
        return campaigns[0] if campaigns else {}
    return next((c for c in campaigns if c.get("campaign_id") == campaign_id), None)


@router.get("/email/identities")
async def list_email_identities(
    tenant_id: str = Query(..., min_length=1, max_length=64),
    employee_id: str | None = Query(default=None, max_length=128),
    campaign_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    _rate_limit_sender_identity_read(f"{tenant_id}:{principal.subject}")
    rows, next_cursor = await _list_by_channel(
        session, tenant_id=tenant_id, channels=("email",),
        employee_id=employee_id, limit=limit, cursor=cursor,
    )
    items = []
    for request in rows:
        campaign = _matching_campaign(request, campaign_id)
        if campaign is None:
            continue
        steps = await _steps_for(session, request)
        state = _channel_state("email", request, steps)
        items.append({
            "employee_id": request.employee_id,
            "tenant_id": request.tenant_id,
            "campaign_id": campaign.get("campaign_id"),
            "campaign_email": campaign.get("campaign_email"),
            **state,
        })
        await _append_audit(
            session, request, from_state=request.state, to_state=request.state,
            action="email_identity.read", principal=principal,
        )
    if items:
        await session.commit()
    return {"items": items, "next_cursor": next_cursor}


@router.get("/sms/identities")
async def list_sms_identities(
    tenant_id: str = Query(..., min_length=1, max_length=64),
    employee_id: str | None = Query(default=None, max_length=128),
    campaign_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(default=None),
    principal: ProvisioningPrincipal = Depends(require_provisioning_scope("identity.request")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    require_tenant_match(principal, tenant_id)
    _rate_limit_sender_identity_read(f"{tenant_id}:{principal.subject}")
    rows, next_cursor = await _list_by_channel(
        session, tenant_id=tenant_id, channels=("sms",),
        employee_id=employee_id, limit=limit, cursor=cursor,
    )
    items = []
    for request in rows:
        campaign = _matching_campaign(request, campaign_id)
        if campaign is None:
            continue
        steps = await _steps_for(session, request)
        state = _channel_state("sms", request, steps)
        items.append({
            "employee_id": request.employee_id,
            "tenant_id": request.tenant_id,
            "campaign_id": campaign.get("campaign_id"),
            "sms_sender": campaign.get("sms_sender"),
            **state,
        })
        await _append_audit(
            session, request, from_state=request.state, to_state=request.state,
            action="sms_identity.read", principal=principal,
        )
    if items:
        await session.commit()
    return {"items": items, "next_cursor": next_cursor}
