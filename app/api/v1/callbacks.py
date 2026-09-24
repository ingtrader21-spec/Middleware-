"""Tenant/campaign-scoped callback control and agent queue API."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.callbacks import (
    CallbackConflict,
    canonical_time,
    compliance_state,
    normalized_phone,
    reminders,
    transition,
)
from app.core.callback_rls import set_callback_rls_context
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator
from app.db.models import CallbackDelivery, CallbackEvent, CallbackRecord
from app.db.session import get_session

router = APIRouter(prefix="/api/v1", tags=["callbacks"])


@dataclass(frozen=True)
class Principal:
    actor: str
    tenant: str
    campaigns: frozenset[str]
    role: str
    teams: frozenset[str]


def principal(
    request: Request,
    authorization: str = Header("", alias="Authorization"),
) -> Principal:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "callback bearer identity required")
    scope = "callbacks.read" if request.method == "GET" else "callbacks.write"
    validator = KeycloakValidator(
        issuer=settings.callback_jwt_issuer,
        audience=settings.callback_jwt_audience,
        jwks_url=settings.callback_jwt_jwks_url,
        authorized_parties=frozenset(
            filter(None, settings.callback_jwt_authorized_parties.split(","))
        ),
        required_scopes=frozenset({scope}),
    )
    try:
        claims = validator.validate(authorization[7:])
    except JWTAuthError as exc:
        status = (
            503
            if not settings.callback_jwt_issuer or not settings.callback_jwt_jwks_url
            else 403
        )
        raise HTTPException(status, "callback identity validation failed") from exc
    roles = set(claims.get("realm_access", {}).get("roles", []))
    role = next(
        (
            value
            for value in (
                "owner",
                "call_center_admin",
                "campaign_manager",
                "supervisor",
                "qa",
                "agent",
                "service",
            )
            if value in roles
        ),
        "",
    )
    tenant = str(claims.get("tenant_id", ""))
    campaigns = frozenset(map(str, claims.get("campaigns", [])))
    if not tenant or not campaigns or not role:
        raise HTTPException(403, "scoped callback identity required")
    return Principal(
        str(claims.get("preferred_username") or claims.get("sub")),
        tenant,
        campaigns,
        role,
        frozenset(map(str, claims.get("teams", []))),
    )


class Compliance(BaseModel):
    consent: bool
    dnc: bool = False
    suppressed: bool = False
    within_calling_hours: bool
    campaign_allowed: bool


class CreateCallback(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tenant_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    contact_id: str | None = None
    lead_id: str | None = None
    opportunity_id: str | None = None
    original_call_id: str | None = None
    original_linkedid: str | None = None
    assigned_agent_id: str | None = None
    assigned_user_id: str | None = None
    reminder_recipient_token: str | None = Field(
        default=None, pattern=r"^identity://[A-Za-z0-9._:/-]{8,240}$"
    )
    assigned_team_id: str | None = None
    supervisor_id: str | None = None
    phone_number: str = Field(min_length=7, max_length=32)
    scheduled_at: datetime
    customer_timezone: str = Field(min_length=1, max_length=64)
    priority: Literal["LOW", "NORMAL", "HIGH", "URGENT"] = "NORMAL"
    reason: str = Field(min_length=1, max_length=256)
    notes: str = Field(default="", max_length=8000)
    reminder_email_enabled: bool = True
    reminder_popup_enabled: bool = True
    max_attempts: int = Field(default=3, ge=1, le=20)
    compliance: Compliance
    customer_context: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def owner(self):
        if not self.assigned_agent_id and not self.assigned_team_id:
            raise ValueError("assigned agent or team is required")
        return self


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    scheduled_at: datetime | None = None
    customer_timezone: str | None = None
    assigned_agent_id: str | None = None
    assigned_team_id: str | None = None
    reason: str | None = Field(default=None, max_length=256)
    notes: str | None = Field(default=None, max_length=8000)
    completion_disposition: str | None = Field(default=None, max_length=64)
    completion_notes: str | None = Field(default=None, max_length=8000)
    snooze_minutes: int | None = Field(default=None, ge=5, le=1440)


class DeliveryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    callback_version: int = Field(ge=1)
    channel: Literal["EMAIL", "POPUP"]
    stage: str = Field(min_length=1, max_length=32)
    status: Literal["QUEUED", "ACCEPTED", "DELIVERED", "BOUNCED", "FAILED"]
    message_id: UUID | None = None
    provider_message_id: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=64)


def _hash(body: BaseModel) -> str:
    return hashlib.sha256(
        json.dumps(
            body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def _scope(p: Principal, tenant: str, campaign: str) -> None:
    if tenant != p.tenant or campaign not in p.campaigns:
        raise HTTPException(403, "callback scope denied")


def _view(row: CallbackRecord) -> dict:
    return {
        "id": str(row.id),
        "tenant_id": row.tenant_id,
        "campaign_id": row.campaign_id,
        "assigned_agent_id": row.assigned_agent_id,
        "assigned_user_id": row.assigned_user_id,
        "assigned_team_id": row.assigned_team_id,
        "scheduled_at": row.scheduled_at,
        "customer_timezone": row.customer_timezone,
        "priority": row.priority,
        "reason": row.reason,
        "notes": row.notes,
        "state": row.state,
        "version": row.version,
        "correlation_id": row.correlation_id,
        "completion_disposition": row.completion_disposition,
        "completion_notes": row.completion_notes,
        "customer_context": row.context_json,
    }


async def _load(
    db: AsyncSession, callback_id: UUID, p: Principal, lock: bool = False
) -> CallbackRecord:
    stmt = select(CallbackRecord).where(CallbackRecord.id == callback_id)
    if lock:
        stmt = stmt.with_for_update()
    row = await db.scalar(stmt)
    if not row:
        raise HTTPException(404, "callback not found")
    _scope(p, row.tenant_id, row.campaign_id)
    if (
        p.role == "agent"
        and row.assigned_agent_id != p.actor
        and row.assigned_team_id not in p.teams
    ):
        raise HTTPException(403, "callback assignment denied")
    return row


async def _tenant_context(db: AsyncSession, p: Principal) -> None:
    await set_callback_rls_context(
        db,
        tenant_id=p.tenant,
        campaign_ids=p.campaigns,
        actor_id=p.actor,
        role=p.role,
        team_ids=p.teams,
    )


def _event(
    row: CallbackRecord,
    kind: str,
    key: str,
    p: Principal,
    payload: dict,
    correlation: str,
) -> CallbackEvent:
    return CallbackEvent(
        id=uuid4(),
        callback_id=row.id,
        tenant_id=row.tenant_id,
        campaign_id=row.campaign_id,
        event_type=kind,
        version=row.version,
        idempotency_key=key,
        correlation_id=correlation,
        actor_id=p.actor,
        payload_json=payload,
    )


async def _queue_email_command(
    db: AsyncSession, row: CallbackRecord, body: CreateCallback, p: Principal
) -> None:
    if not row.reminder_email_enabled or not settings.callback_email_command_enabled:
        return
    if not body.reminder_recipient_token:
        raise HTTPException(422, "internal reminder recipient identity required")
    if (
        not settings.callback_email_sender_profile_id
        or len(settings.callback_email_policy_hash) != 64
    ):
        raise HTTPException(503, "COD callback email identity is not configured")
    now = datetime.now(UTC)
    variables = {
        "callback_uuid": str(row.id),
        "callback_version": row.version,
        "tenant": row.tenant_id,
        "campaign": row.campaign_id,
        "assigned_agent": row.assigned_agent_id,
        "scheduled_at": row.scheduled_at.isoformat(),
        "customer_timezone": row.customer_timezone,
        "reason": row.reason,
        "correlation_id": row.correlation_id,
    }
    payload_hash = hashlib.sha256(
        json.dumps(variables, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for stage, not_before in (
        ("REMINDER_24H", row.email_reminder_1_at),
        ("REMINDER_1H", row.email_reminder_2_at),
    ):
        notification_id = uuid4()
        command_id = f"callback-email-{notification_id}"
        idempotency = f"callback:{row.id}:v{row.version}:email:{stage.lower()}"
        await db.execute(
            text("""INSERT INTO notification_command
      (id,schema_version,command_id,command_type,idempotency_key,correlation_id,causation_id,organization_id,business_unit_id,campaign_id,
       lead_id,customer_id,channel,template_id,template_version,sender_profile_id,destination_token,destination_classification,
       consent_evidence_id,suppression_version,policy_version,policy_hash,requested_by,approved_by,requested_at,not_before,expires_at,
       timezone,quiet_hours_policy,rate_limit_bucket,cost_limit_bucket,pii_classification,payload_hash,template_variables,status,version,attempt_count)
      VALUES (:id,'codestra.notification.v1',:command,'email.send',:idem,:corr,:cause,:org,:bu,:campaign,:lead,:customer,'EMAIL',
       :template,1,:sender,:destination,'INTERNAL_AGENT',:consent,'callback-v1','callback-v1',:policy,:requested,:approved,:now,:not_before,
       :expires,:timezone,'internal-agent','callback-email-cod','callback-email-cod','INTERNAL_OPERATIONAL',:payload,CAST(:variables AS jsonb),'REQUESTED',1,0)"""),
            {
                "id": notification_id,
                "command": command_id,
                "idem": idempotency,
                "corr": row.correlation_id,
                "cause": str(row.id),
                "org": row.tenant_id,
                "bu": row.tenant_id,
                "campaign": row.campaign_id,
                "lead": row.lead_id,
                "customer": row.contact_id or "INTERNAL",
                "template": settings.callback_email_template_id,
                "sender": settings.callback_email_sender_profile_id,
                "destination": body.reminder_recipient_token,
                "consent": f"callback:{row.id}:compliance",
                "policy": settings.callback_email_policy_hash,
                "requested": p.actor,
                "approved": p.actor,
                "now": now,
                "not_before": not_before,
                "expires": row.scheduled_at + timedelta(hours=1),
                "timezone": row.customer_timezone,
                "payload": payload_hash,
                "variables": json.dumps(variables, separators=(",", ":")),
            },
        )
        db.add(
            CallbackDelivery(
                id=uuid4(),
                callback_id=row.id,
                callback_version=row.version,
                channel="EMAIL",
                stage=stage,
                idempotency_key=idempotency,
                status="QUEUED",
                message_id=notification_id,
                next_attempt_at=not_before,
            )
        )


@router.post("/control/callbacks", status_code=201)
async def create(
    body: CreateCallback,
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
    key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=180),
    correlation: str = Header(
        ..., alias="X-Correlation-ID", min_length=1, max_length=180
    ),
):
    _scope(p, body.tenant_id, body.campaign_id)
    await _tenant_context(db, p)
    digest = _hash(body)
    prior = await db.scalar(
        select(CallbackRecord).where(
            CallbackRecord.tenant_id == p.tenant, CallbackRecord.idempotency_key == key
        )
    )
    if prior:
        if prior.request_hash != digest:
            raise HTTPException(409, "idempotency payload conflict")
        return _view(prior)
    try:
        scheduled = canonical_time(body.scheduled_at, body.customer_timezone)
        phone = normalized_phone(body.phone_number)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    state, checks = compliance_state(**body.compliance.model_dump())
    r1, r2, pop = reminders(scheduled)
    row = CallbackRecord(
        id=uuid4(),
        **body.model_dump(
            exclude={
                "compliance",
                "customer_context",
                "reminder_recipient_token",
                "scheduled_at",
                "phone_number",
            }
        ),
        phone_number=body.phone_number,
        normalized_phone=phone,
        scheduled_at=scheduled,
        state=state,
        desired_state=state,
        actual_state=state,
        compliance_json=checks,
        context_json=body.customer_context,
        email_reminder_1_at=r1,
        email_reminder_2_at=r2,
        popup_reminder_at=pop,
        next_attempt_at=r1,
        correlation_id=correlation,
        idempotency_key=key,
        request_hash=digest,
        version=1,
        sync_state="PENDING",
        created_by=p.actor,
    )
    db.add(row)
    # Establish the aggregate before inserting the append-only event.  The
    # explicit flush also makes a duplicate aggregate fail inside this unit of
    # work rather than leaving ordering to mapper relationship discovery.
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "callback identity conflict") from exc
    db.add(
        _event(
            row,
            "callback.created",
            f"{key}:created",
            p,
            {"state": state, "scheduled_at": scheduled.isoformat()},
            correlation,
        )
    )
    await _queue_email_command(db, row, body, p)
    if row.reminder_popup_enabled:
        db.add(
            CallbackDelivery(
                id=uuid4(),
                callback_id=row.id,
                callback_version=row.version,
                channel="POPUP",
                stage="WARNING_15M",
                idempotency_key=f"callback:{row.id}:v{row.version}:popup:warning-15m",
                status="QUEUED",
                next_attempt_at=row.popup_reminder_at,
            )
        )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "callback event identity conflict") from exc
    return _view(row)


@router.get("/callbacks/due")
async def due_callbacks(
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
):
    await _tenant_context(db, p)
    stmt = select(CallbackRecord).where(
        CallbackRecord.tenant_id == p.tenant,
        CallbackRecord.campaign_id.in_(p.campaigns),
        CallbackRecord.state.in_(["DUE", "MISSED", "ESCALATED"]),
    )
    if p.role == "agent":
        stmt = stmt.where(
            or_(
                CallbackRecord.assigned_agent_id == p.actor,
                CallbackRecord.assigned_team_id.in_(p.teams),
            )
        )
    rows = (
        await db.scalars(stmt.order_by(CallbackRecord.scheduled_at).limit(100))
    ).all()
    return {"items": [_view(row) for row in rows]}


@router.get("/callbacks/dashboard/supervisor")
async def supervisor_dashboard(
    db: AsyncSession = Depends(get_session), p: Principal = Depends(principal)
):
    if p.role not in {"supervisor", "campaign_manager", "call_center_admin", "owner"}:
        raise HTTPException(403, "supervisor callback visibility denied")
    await _tenant_context(db, p)
    rows = (
        await db.scalars(
            select(CallbackRecord)
            .where(
                CallbackRecord.tenant_id == p.tenant,
                CallbackRecord.campaign_id.in_(p.campaigns),
            )
            .limit(5000)
        )
    ).all()
    now = datetime.now(UTC)
    states = {
        name: 0
        for name in (
            "TODAY",
            "UPCOMING",
            "DUE",
            "MISSED",
            "OVERDUE",
            "ESCALATED",
            "COMPLETED",
        )
    }
    agents: dict[str, dict[str, float | int | str]] = {}
    for row in rows:
        if row.scheduled_at.date() == now.date():
            states["TODAY"] += 1
        if row.scheduled_at > now and row.state not in {"COMPLETED", "CANCELLED"}:
            states["UPCOMING"] += 1
        if row.state in states:
            states[row.state] += 1
        if row.scheduled_at < now and row.state in {
            "SCHEDULED",
            "REMINDER_PENDING",
            "READY",
            "DUE",
        }:
            states["OVERDUE"] += 1
        key = row.assigned_agent_id or f"team:{row.assigned_team_id}"
        item = agents.setdefault(
            key,
            {
                "agent_id": key,
                "scheduled": 0,
                "completed": 0,
                "missed": 0,
                "overdue": 0,
                "lateness_seconds": 0.0,
            },
        )
        item["scheduled"] = int(item["scheduled"]) + 1
        if row.state == "COMPLETED":
            item["completed"] = int(item["completed"]) + 1
        if row.state in {"MISSED", "ESCALATED"}:
            item["missed"] = int(item["missed"]) + 1
        if row.scheduled_at < now and row.state not in {"COMPLETED", "CANCELLED"}:
            item["overdue"] = int(item["overdue"]) + 1
        if row.completed_at:
            item["lateness_seconds"] = float(item["lateness_seconds"]) + max(
                0.0, (row.completed_at - row.scheduled_at).total_seconds()
            )
    for item in agents.values():
        scheduled = max(1, int(item["scheduled"]))
        completed = int(item["completed"])
        item["completion_rate"] = completed / scheduled
        item["average_lateness_seconds"] = float(item.pop("lateness_seconds")) / max(
            1, completed
        )
    return {"counts": states, "agents": list(agents.values())}


@router.get("/callbacks/dashboard/campaigns")
async def campaign_dashboard(
    db: AsyncSession = Depends(get_session), p: Principal = Depends(principal)
):
    if p.role not in {"campaign_manager", "call_center_admin", "owner", "supervisor"}:
        raise HTTPException(403, "campaign callback visibility denied")
    await _tenant_context(db, p)
    rows = (
        await db.scalars(
            select(CallbackRecord)
            .where(
                CallbackRecord.tenant_id == p.tenant,
                CallbackRecord.campaign_id.in_(p.campaigns),
            )
            .limit(5000)
        )
    ).all()
    now = datetime.now(UTC)
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = output.setdefault(
            row.campaign_id,
            {
                "campaign_id": row.campaign_id,
                "scheduled": 0,
                "due": 0,
                "completed": 0,
                "missed": 0,
                "cancelled": 0,
                "rescheduled": 0,
                "escalated": 0,
                "overdue": 0,
                "outcomes": {},
            },
        )
        state = row.state.lower()
        if state in item:
            item[state] += 1
        else:
            item["scheduled"] += 1
        if row.scheduled_at < now and row.state not in {"COMPLETED", "CANCELLED"}:
            item["overdue"] += 1
        if row.completion_disposition:
            item["outcomes"][row.completion_disposition] = (
                item["outcomes"].get(row.completion_disposition, 0) + 1
            )
    return {"campaigns": list(output.values())}


@router.get("/callbacks/{callback_id}")
async def get(
    callback_id: UUID,
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
):
    await _tenant_context(db, p)
    return _view(await _load(db, callback_id, p))


@router.get("/callbacks")
async def queue(
    state: list[str] = Query(default=[]),
    due_before: datetime | None = None,
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
):
    await _tenant_context(db, p)
    stmt = select(CallbackRecord).where(
        CallbackRecord.tenant_id == p.tenant,
        CallbackRecord.campaign_id.in_(p.campaigns),
    )
    if p.role == "agent":
        stmt = stmt.where(
            or_(
                CallbackRecord.assigned_agent_id == p.actor,
                CallbackRecord.assigned_team_id.in_(p.teams),
            )
        )
    if state:
        stmt = stmt.where(CallbackRecord.state.in_(state))
    if due_before:
        stmt = stmt.where(CallbackRecord.scheduled_at <= due_before)
    rows = (
        await db.scalars(
            stmt.order_by(
                CallbackRecord.priority.desc(), CallbackRecord.scheduled_at
            ).limit(500)
        )
    ).all()
    return {"items": [_view(r) for r in rows]}


@router.patch("/control/callbacks/{callback_id}")
async def patch_callback(
    callback_id: UUID,
    body: Change,
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
    key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=180),
    correlation: str = Header(
        ..., alias="X-Correlation-ID", min_length=1, max_length=180
    ),
):
    return await mutate(callback_id, "UPDATED", body, key, correlation, db, p)


@router.post("/results/callbacks/{callback_id}")
async def callback_result(
    callback_id: UUID,
    body: DeliveryResult,
    db: AsyncSession = Depends(get_session),
    p: Principal = Depends(principal),
):
    if p.role != "service":
        raise HTTPException(403, "service identity required")
    await _tenant_context(db, p)
    row = await _load(db, callback_id, p, True)
    if body.callback_version != row.version:
        raise HTTPException(409, "stale callback delivery result")
    delivery = await db.scalar(
        select(CallbackDelivery)
        .where(
            CallbackDelivery.callback_id == callback_id,
            CallbackDelivery.callback_version == body.callback_version,
            CallbackDelivery.channel == body.channel,
            CallbackDelivery.stage == body.stage,
        )
        .with_for_update()
    )
    if not delivery:
        raise HTTPException(404, "callback delivery not found")
    delivery.status = body.status
    delivery.message_id = body.message_id
    delivery.provider_message_id = body.provider_message_id
    delivery.last_error_code = body.error_code
    if body.status == "FAILED":
        delivery.attempt_count += 1
        delivery.next_attempt_at = datetime.now(UTC) + timedelta(
            minutes=min(60, 2**delivery.attempt_count)
        )
    else:
        delivery.next_attempt_at = None
    await db.commit()
    return {
        "callback_id": str(callback_id),
        "callback_version": row.version,
        "status": delivery.status,
    }


async def mutate(
    callback_id: UUID,
    target: str,
    body: Change,
    key: str,
    correlation: str,
    db: AsyncSession,
    p: Principal,
):
    await _tenant_context(db, p)
    row = await _load(db, callback_id, p, True)
    duplicate = await db.scalar(
        select(CallbackEvent).where(
            CallbackEvent.tenant_id == p.tenant, CallbackEvent.idempotency_key == key
        )
    )
    if duplicate:
        return _view(row)
    if row.version != body.expected_version:
        raise HTTPException(409, "stale callback version")
    if target == "REASSIGNED" and p.role not in {
        "supervisor",
        "campaign_manager",
        "call_center_admin",
        "owner",
    }:
        raise HTTPException(403, "reassignment role denied")
    if target == "REASSIGNED":
        if body.assigned_agent_id is None and body.assigned_team_id is None:
            raise HTTPException(422, "new agent or team is required")
        if (
            body.assigned_team_id is not None
            and p.role == "supervisor"
            and body.assigned_team_id not in p.teams
        ):
            raise HTTPException(403, "reassignment team scope denied")
        previous_assignment = {
            "agent_id": row.assigned_agent_id,
            "team_id": row.assigned_team_id,
        }
    effective = target
    if target == "SNOOZED":
        row.scheduled_at = datetime.now(UTC) + timedelta(
            minutes=body.snooze_minutes or 5
        )
    elif target == "RESCHEDULED":
        if not body.scheduled_at or not body.customer_timezone:
            raise HTTPException(422, "schedule and timezone required")
        try:
            row.scheduled_at = canonical_time(body.scheduled_at, body.customer_timezone)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        row.customer_timezone = body.customer_timezone
    elif target == "REASSIGNED":
        effective = row.state
    try:
        if target not in {"REASSIGNED", "UPDATED"}:
            transition(row.state, target)
    except CallbackConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    if body.assigned_agent_id is not None:
        row.assigned_agent_id = body.assigned_agent_id
        if target == "REASSIGNED":
            row.assigned_team_id = body.assigned_team_id
    if body.assigned_team_id is not None:
        row.assigned_team_id = body.assigned_team_id
        if target == "REASSIGNED" and body.assigned_agent_id is None:
            row.assigned_agent_id = None
    if not row.assigned_agent_id and not row.assigned_team_id:
        raise HTTPException(422, "callback cannot be orphaned")
    if body.notes is not None:
        row.notes = body.notes
    if body.reason is not None:
        row.reason = body.reason
    if target in {"SNOOZED", "RESCHEDULED"}:
        row.email_reminder_1_at, row.email_reminder_2_at, row.popup_reminder_at = (
            reminders(row.scheduled_at)
        )
    if target in {"SNOOZED", "RESCHEDULED", "REASSIGNED", "COMPLETED", "CANCELLED"}:
        stale = (
            await db.scalars(
                select(CallbackDelivery)
                .where(
                    CallbackDelivery.callback_id == row.id,
                    CallbackDelivery.callback_version <= body.expected_version,
                    CallbackDelivery.status.in_(["QUEUED", "RETRY_PENDING"]),
                )
                .with_for_update()
            )
        ).all()
        for delivery in stale:
            delivery.status = "STALE_CANCELLED"
            delivery.next_attempt_at = None
    if target == "COMPLETED":
        row.completed_at = datetime.now(UTC)
        row.completion_disposition = body.completion_disposition
        row.completion_notes = body.completion_notes
    if target == "CANCELLED":
        row.cancelled_at = datetime.now(UTC)
    if target == "UPDATED":
        effective = row.state
    row.state = row.desired_state = row.actual_state = effective
    row.version += 1
    row.sync_state = "PENDING"
    db.add(
        _event(
            row,
            f"callback.{target.lower()}",
            key,
            p,
            {
                "from_version": body.expected_version,
                "state": effective,
                **(
                    {
                        "previous_assignment": previous_assignment,
                        "new_assignment": {
                            "agent_id": row.assigned_agent_id,
                            "team_id": row.assigned_team_id,
                        },
                    }
                    if target == "REASSIGNED"
                    else {}
                ),
            },
            correlation,
        )
    )
    await db.commit()
    return _view(row)


def endpoint(path: str, target: str):
    async def handler(
        callback_id: UUID,
        body: Change,
        db: AsyncSession = Depends(get_session),
        p: Principal = Depends(principal),
        key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=180),
        correlation: str = Header(
            ..., alias="X-Correlation-ID", min_length=1, max_length=180
        ),
    ):
        return await mutate(callback_id, target, body, key, correlation, db, p)

    router.add_api_route(path, handler, methods=["POST"], status_code=200)


for path, target in (
    ("/control/callbacks/{callback_id}/snooze", "SNOOZED"),
    ("/control/callbacks/{callback_id}/reschedule", "RESCHEDULED"),
    ("/control/callbacks/{callback_id}/cancel", "CANCELLED"),
    ("/control/callbacks/{callback_id}/complete", "COMPLETED"),
    ("/control/callbacks/{callback_id}/start", "IN_PROGRESS"),
    ("/control/callbacks/{callback_id}/call-now", "IN_PROGRESS"),
    ("/control/callbacks/{callback_id}/reassign", "REASSIGNED"),
):
    endpoint(path, target)
