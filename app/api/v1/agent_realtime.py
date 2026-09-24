"""Durable, tenant-scoped call events and the authenticated agent WebSocket."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal, cast
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.webphone import BrowserIdentity, browser_identity
from app.core.config import settings
from app.core.providers import get_redis_client
from app.core.provisioning_auth import (
    ProvisioningPrincipal,
    require_provisioning_scope,
    require_tenant_match,
)
from app.db.models import (
    AgentCallEvent,
    AgentCallState,
    AgentProvisioningRequest,
    AgentProvisioningStep,
    TelephonyExtensionReservation,
)
from app.db.session import SessionFactory, get_session

router = APIRouter(tags=["agent-realtime"])

EventType = Literal[
    "call.created",
    "call.offered",
    "call.queued",
    "call.dialing",
    "call.ringing",
    "call.answered",
    "call.connected",
    "call.held",
    "call.resumed",
    "call.transfer.started",
    "call.transfer.completed",
    "call.transfer.failed",
    "call.hangup",
    "call.completed",
    "call.failed",
    "call.busy",
    "call.no_answer",
    "call.rejected",
    "call.canceled",
    "call.disposition.updated",
    "call.recording.started",
    "call.recording.completed",
    "call.recording.available",
]

TERMINAL_EVENTS = frozenset(
    {
        "call.completed",
        "call.failed",
        "call.busy",
        "call.no_answer",
        "call.rejected",
        "call.canceled",
    }
)
STATE_RANK = {
    "call.created": 10,
    "call.offered": 15,
    "call.queued": 20,
    "call.dialing": 30,
    "call.ringing": 30,
    "call.answered": 40,
    "call.connected": 50,
    "call.held": 60,
    "call.resumed": 50,
    "call.transfer.started": 70,
    "call.transfer.completed": 80,
    "call.transfer.failed": 50,
    "call.hangup": 100,
    "call.completed": 100,
    "call.failed": 100,
    "call.busy": 100,
    "call.no_answer": 100,
    "call.rejected": 100,
    "call.canceled": 100,
    "call.disposition.updated": 110,
    "call.recording.started": 55,
    "call.recording.completed": 105,
    "call.recording.available": 110,
}


class AgentEventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    event_id: str = Field(min_length=8, max_length=128)
    event_type: EventType
    timestamp: datetime
    correlation_id: str = Field(min_length=8, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    business_unit_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=64)
    call_id: str = Field(min_length=1, max_length=128)
    asterisk_uniqueid: str = Field(min_length=1, max_length=128)
    linkedid: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    extension: str = Field(pattern=r"^[0-9]{4}$")
    sequence: int = Field(ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)


def _document(event: AgentEventEnvelope, applied: bool) -> dict[str, Any]:
    return {
        **event.model_dump(mode="json"),
        "transition_applied": applied,
    }


def transition_allowed(
    current_event_type: str | None,
    current_sequence: int | None,
    incoming_sequence: int,
) -> bool:
    return bool(
        current_event_type is None
        or (
            current_sequence is not None
            and incoming_sequence > current_sequence
            and current_event_type not in TERMINAL_EVENTS
        )
    )


async def _publish(redis: Redis, event: AgentEventEnvelope, applied: bool) -> None:
    await redis.xadd(
        f"agent-events:{event.extension}",
        {"event": json.dumps(_document(event, applied), separators=(",", ":"))},
        maxlen=10000,
        approximate=True,
    )


async def _authorize_agent_event(
    db: AsyncSession,
    principal: ProvisioningPrincipal,
    event: AgentEventEnvelope,
) -> None:
    """Reject an event whose campaign/extension the caller cannot prove.

    Two evidence paths:

    1. The staging fixture (``campaign_id``/``extension`` exactly matching
       the single hardcoded ``webphone_staging_campaign``/
       ``webphone_staging_endpoint`` pair) - preserved as-is so the existing
       staging flow this module was built for keeps working. Tenant binding
       is still enforced before this exception is evaluated.
    2. Every other campaign/extension: a real, per-caller check. The
       caller's own token must cover ``event.tenant_id`` (the same
       ``require_tenant_match`` every other provisioning-scoped endpoint in
       this codebase already uses), ``event.agent_id`` must have a
       desired-state campaign membership entry for ``event.campaign_id`` in
       its most recent ``AgentProvisioningRequest`` (the same durable
       source ``app.api.v1.agent_provisioning_reads.get_user_campaigns``
       already reads - not a second, parallel campaign-membership store),
       and ``event.extension`` must be proven either by this service's
       extension reservation ledger or by the successful reserve/adopt step
       written by the primary agent-provisioning saga.

    The event identity may use either the Odoo employee identifier or the
    campaign's VICIdial user identifier. Both resolve through the same
    provisioning request; reservation ownership is always checked against
    its canonical employee_id, preventing identifier-space confusion from
    granting another agent's extension.
    """
    require_tenant_match(principal, event.tenant_id)
    if (
        event.campaign_id == settings.webphone_staging_campaign
        and event.extension == settings.webphone_staging_endpoint
    ):
        return
    stmt = (
        select(AgentProvisioningRequest)
        .where(
            AgentProvisioningRequest.tenant_id == event.tenant_id,
            AgentProvisioningRequest.campaigns_json.contains(
                [{"campaign_id": event.campaign_id}]
            ),
            or_(
                AgentProvisioningRequest.employee_id == event.agent_id,
                AgentProvisioningRequest.campaigns_json.contains(
                    [
                        {
                            "campaign_id": event.campaign_id,
                            "vicidial_user_id": event.agent_id,
                        }
                    ]
                ),
            ),
        )
        .order_by(
            AgentProvisioningRequest.created_at.desc(),
            AgentProvisioningRequest.id.desc(),
        )
        .limit(1)
    )
    request = await db.scalar(stmt)
    if request is None or request.state in {"FAILED", "SUSPENDED", "REVOKED"}:
        raise HTTPException(403, "campaign denied")
    reservation = await db.scalar(
        select(TelephonyExtensionReservation).where(
            TelephonyExtensionReservation.employee_id == request.employee_id,
            TelephonyExtensionReservation.extension == int(event.extension),
            TelephonyExtensionReservation.state.in_(
                ("RESERVED", "DISABLED_READY", "ACTIVE")
            ),
        )
    )
    provisioning_step = await db.scalar(
        select(AgentProvisioningStep)
        .where(
            AgentProvisioningStep.request_id == request.id,
            AgentProvisioningStep.system == "vicidial",
            AgentProvisioningStep.operation.in_(
                ("reserve_extension", "adopt_extension")
            ),
            AgentProvisioningStep.state == "succeeded",
            AgentProvisioningStep.external_reference == event.extension,
        )
        .order_by(AgentProvisioningStep.created_at.desc())
        .limit(1)
    )
    if reservation is None and provisioning_step is None:
        raise HTTPException(403, "extension denied")


@router.post("/api/v1/agent/events", status_code=202)
async def ingest_agent_event(
    event: AgentEventEnvelope,
    request: Request,
    db: AsyncSession = Depends(get_session),
    principal: ProvisioningPrincipal = Depends(
        require_provisioning_scope("identity.request")
    ),
) -> dict[str, Any]:
    if not settings.agent_websocket_enabled:
        raise HTTPException(503, "agent realtime disabled")
    await _authorize_agent_event(db, principal, event)
    duplicate = await db.scalar(
        select(AgentCallEvent).where(
            (AgentCallEvent.event_id == event.event_id)
            | (AgentCallEvent.idempotency_key == event.idempotency_key)
        )
    )
    if duplicate:
        return {"status": "duplicate", "transition_applied": False}

    current = await db.get(AgentCallState, event.call_id, with_for_update=True)
    applied = transition_allowed(
        current.event_type if current else None,
        current.sequence if current else None,
        event.sequence,
    )
    if current is None:
        current = AgentCallState(
            call_id=event.call_id,
            tenant_id=event.tenant_id,
            business_unit_id=event.business_unit_id,
            campaign_id=event.campaign_id,
            agent_id=event.agent_id,
            extension=event.extension,
            correlation_id=event.correlation_id,
            asterisk_uniqueid=event.asterisk_uniqueid,
            linkedid=event.linkedid,
            event_type=event.event_type,
            state_rank=STATE_RANK[event.event_type],
            sequence=event.sequence,
            event_timestamp=event.timestamp,
            context_json=event.payload,
        )
        db.add(current)
    elif current is not None:
        if (
            current.tenant_id != event.tenant_id
            or current.business_unit_id != event.business_unit_id
            or current.campaign_id != event.campaign_id
            or current.agent_id != event.agent_id
            or current.extension != event.extension
            or current.correlation_id != event.correlation_id
            or current.asterisk_uniqueid != event.asterisk_uniqueid
            or current.linkedid != event.linkedid
        ):
            raise HTTPException(409, "call identity or scope is immutable")
    if current is not None and applied:
        current.event_type = event.event_type
        current.state_rank = STATE_RANK[event.event_type]
        current.sequence = event.sequence
        current.event_timestamp = event.timestamp
        current.context_json = {**current.context_json, **event.payload}
    db.add(
        AgentCallEvent(
            id=uuid4(),
            **event.model_dump(exclude={"timestamp", "payload"}),
            event_timestamp=event.timestamp,
            payload_json=event.payload,
            transition_applied=applied,
        )
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "event identity or sequence conflict") from exc
    try:
        await _publish(get_redis_client(request), event, applied)
    except RedisError:
        return {
            "status": "persisted",
            "transition_applied": applied,
            "realtime": "deferred",
        }
    return {"status": "accepted", "transition_applied": applied}


def _authorized(identity: BrowserIdentity, state: AgentCallState) -> bool:
    return (
        state.tenant_id == identity.tenant_id
        and state.business_unit_id == identity.business_unit_id
        and state.campaign_id in identity.campaigns
        and state.agent_id == identity.agent_id
        and state.extension == str(identity.endpoint)
    )


@router.websocket("/ws/agent")
async def agent_websocket(websocket: WebSocket) -> None:
    if not settings.agent_websocket_enabled:
        await websocket.close(code=1013, reason="agent realtime disabled")
        return
    try:
        identity = await browser_identity(websocket)
    except HTTPException as exc:
        await websocket.close(
            code=4400 + min(exc.status_code, 99), reason="authentication denied"
        )
        return
    redis = get_redis_client(cast(Request, websocket))
    lock_key = f"agent-socket:{identity.tenant_id}:{identity.agent_id}"
    socket_id = str(uuid4())
    try:
        if not await redis.set(lock_key, socket_id, ex=90, nx=True):
            await websocket.close(code=4409, reason="agent session already active")
            return
        await websocket.accept()
        async with SessionFactory() as db:
            states = (
                await db.scalars(
                    select(AgentCallState).where(
                        AgentCallState.extension == str(identity.endpoint),
                        AgentCallState.agent_id == identity.agent_id,
                        AgentCallState.tenant_id == identity.tenant_id,
                        AgentCallState.campaign_id.in_(identity.campaigns),
                    )
                )
            ).all()
            for state in states:
                if (
                    _authorized(identity, state)
                    and state.event_type not in TERMINAL_EVENTS
                ):
                    await websocket.send_json(
                        {
                            "type": "authoritative_state",
                            "call_id": state.call_id,
                            "event_type": state.event_type,
                            "sequence": state.sequence,
                            "context": state.context_json,
                        }
                    )
        stream = f"agent-events:{identity.endpoint}"
        cursor = "$"
        while True:
            await redis.expire(lock_key, 90)
            messages = await redis.xread({stream: cursor}, block=15000, count=20)
            for _, entries in messages:
                for cursor, fields in entries:
                    document = json.loads(fields["event"])
                    if (
                        document["tenant_id"] == identity.tenant_id
                        and document["business_unit_id"] == identity.business_unit_id
                        and document["campaign_id"] in identity.campaigns
                        and document["agent_id"] == identity.agent_id
                        and document["extension"] == str(identity.endpoint)
                    ):
                        await websocket.send_json(document)
    except (WebSocketDisconnect, RedisError):
        pass
    finally:
        try:
            if await redis.get(lock_key) == socket_id:
                await redis.delete(lock_key)
        except RedisError:
            pass
