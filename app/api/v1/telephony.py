"""Database-authoritative telephony allocation and lifecycle API."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode, urlsplit
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.vicidial.mtls_client import VicidialMtlsClient, VicidialMtlsError
from app.core.config import settings
from app.core.providers import get_http_client
from app.core.telephony import AUTHORITATIVE_SOURCES, ExtensionState, audit_extension
from app.core.webrtc_production_policy import (
    E164,
    CallRequest as PolicyCallRequest,
    Consent as PolicyConsent,
    Decision,
    Policy,
    authorize as authorize_call,
)
from app.db.models import (
    AuditEvent,
    IdempotencyRecord,
    OutboxEvent,
    TelephonyCallLifecycle,
    TelephonyExtensionPool,
    TelephonyExtensionReservation,
    TelephonyProvisioningSaga,
)
from app.db.session import get_session

router = APIRouter(prefix="/v1/telephony", tags=["telephony"])
logger = logging.getLogger("codestra.telephony_originate")
_originate_requests: dict[str, deque[float]] = defaultdict(deque)


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    extension: int = Field(ge=1000, le=9999)
    evidence: dict[str, str]


class ReserveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    employee_id: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=128)
    business_unit: str = Field(min_length=1, max_length=64)
    role_class: str = Field(min_length=1, max_length=32)
    idempotency_key: str = Field(min_length=16, max_length=256)
    evidence_by_extension: dict[int, dict[str, str]]
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


class ProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=128)
    employee_id: str = Field(min_length=1, max_length=128)
    business_unit: str = Field(min_length=1, max_length=64)
    campaign: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=16, max_length=256)
    approved_odoo_request: bool
    record_environment: Literal["PRODUCTION", "STAGING", "TEST"] = "PRODUCTION"
    test_run_id: str | None = Field(default=None, min_length=1, max_length=128)
    causation_id: str | None = Field(default=None, min_length=1, max_length=128)
    policy_hash: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def validate_trace_binding(payload: ProvisionRequest) -> None:
    if payload.record_environment in {"TEST", "STAGING"}:
        if payload.business_unit != "BU-400-COD" or payload.campaign != "CMP-400-COD":
            raise HTTPException(422, "test trace scope mismatch")
        if (
            not payload.test_run_id
            or not payload.causation_id
            or not payload.policy_hash
        ):
            raise HTTPException(422, "complete test trace binding required")
    elif any((payload.test_run_id, payload.causation_id, payload.policy_hash)):
        raise HTTPException(422, "test trace binding is prohibited in production")


@router.post("/extensions/audit")
async def audit(payload: AuditRequest):
    result = audit_extension(payload.extension, payload.evidence)
    return {
        "extension": result.extension,
        "classification": result.classification,
        "evidence_hash": result.evidence_hash,
        "missing_sources": result.missing_sources,
        "collision_sources": result.collision_sources,
    }


@router.get("/extensions/pools")
async def pools(session: AsyncSession = Depends(get_session)):
    rows = (
        await session.execute(
            select(TelephonyExtensionPool)
            .where(TelephonyExtensionPool.active.is_(True))
            .order_by(TelephonyExtensionPool.range_start)
        )
    ).scalars()
    return [
        {
            "code": row.code,
            "business_unit": row.business_unit,
            "role_class": row.role_class,
            "start": row.range_start,
            "end": row.range_end,
        }
        for row in rows
    ]


@router.get("/extensions/availability")
async def availability(extension: int, evidence_complete: bool = False):
    # A bare range check is never availability evidence.
    if extension in {1001, 6101}:
        classification = ExtensionState.EXCLUDED
    else:
        classification = ExtensionState.UNKNOWN_REQUIRES_REVIEW
    return {
        "extension": extension,
        "classification": classification,
        "evidence_complete": evidence_complete and False,
    }


@router.post("/extensions/reserve", status_code=201)
async def reserve(
    payload: ReserveRequest, session: AsyncSession = Depends(get_session)
):
    key_hash = _hash(payload.idempotency_key)
    replay = (
        await session.execute(
            select(TelephonyExtensionReservation).where(
                TelephonyExtensionReservation.idempotency_hash == key_hash
            )
        )
    ).scalar_one_or_none()
    if replay:
        return {
            "reservation_id": replay.id,
            "extension": replay.extension,
            "state": replay.state,
            "replayed": True,
        }
    pool = (
        await session.execute(
            select(TelephonyExtensionPool)
            .where(
                TelephonyExtensionPool.business_unit == payload.business_unit,
                TelephonyExtensionPool.role_class == payload.role_class,
                TelephonyExtensionPool.active.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if not pool:
        raise HTTPException(422, "no matching active extension pool")
    active = set(
        (
            await session.execute(
                select(TelephonyExtensionReservation.extension)
                .where(
                    TelephonyExtensionReservation.extension.between(
                        pool.range_start, pool.range_end
                    ),
                    TelephonyExtensionReservation.state.in_(
                        (
                            "RESERVED",
                            "DISABLED_READY",
                            "ACTIVE",
                            "SUSPENDED",
                            "COOLDOWN",
                        )
                    ),
                )
                .with_for_update()
            )
        ).scalars()
    )
    selected = None
    evidence_hash = None
    for extension in range(pool.range_start, pool.range_end + 1):
        if extension in active or extension in {1001, 6101}:
            continue
        result = audit_extension(
            extension, payload.evidence_by_extension.get(extension, {})
        )
        if result.classification == ExtensionState.AVAILABLE:
            selected, evidence_hash = extension, result.evidence_hash
            break
    if selected is None:
        raise HTTPException(409, "no fully-audited extension is available")
    row = TelephonyExtensionReservation(
        extension=selected,
        employee_id=payload.employee_id,
        request_id=payload.request_id,
        pool_id=pool.id,
        idempotency_hash=key_hash,
        evidence_hash=evidence_hash,
        expires_at=datetime.now(UTC) + timedelta(seconds=payload.ttl_seconds),
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            409, "concurrent reservation conflict; retry safely"
        ) from exc
    return {
        "reservation_id": row.id,
        "extension": selected,
        "state": row.state,
        "replayed": False,
    }


@router.post("/provisioning", status_code=202)
async def provision(
    payload: ProvisionRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    if not payload.approved_odoo_request:
        raise HTTPException(403, "approved Odoo request required")
    validate_trace_binding(payload)
    key_hash = _hash(payload.idempotency_key)
    existing = (
        await session.execute(
            select(TelephonyProvisioningSaga).where(
                TelephonyProvisioningSaga.idempotency_hash == key_hash
            )
        )
    ).scalar_one_or_none()
    if existing:
        return {
            "request_id": existing.request_id,
            "state": existing.state,
            "correlation_id": existing.correlation_id,
            "replayed": True,
        }
    row = TelephonyProvisioningSaga(
        request_id=payload.request_id,
        employee_id=payload.employee_id,
        business_unit=payload.business_unit,
        campaign=payload.campaign,
        role=payload.role,
        state="APPROVED",
        idempotency_hash=key_hash,
        correlation_id=getattr(request.state, "correlation_id", str(uuid4())),
        record_environment=payload.record_environment,
        test_run_id=payload.test_run_id,
        causation_id=payload.causation_id,
        policy_hash=payload.policy_hash,
        approved_odoo_request=True,
        completed_steps=[],
    )
    session.add(row)
    await session.commit()
    return {
        "request_id": row.request_id,
        "state": row.state,
        "correlation_id": row.correlation_id,
        "replayed": False,
        "production_mutation": settings.live_writes_enabled,
    }


@router.get("/provisioning/{request_id}")
async def status(request_id: str, session: AsyncSession = Depends(get_session)):
    row = (
        await session.execute(
            select(TelephonyProvisioningSaga).where(
                TelephonyProvisioningSaga.request_id == request_id
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "provisioning request not found")
    return {
        "request_id": row.request_id,
        "employee_id": row.employee_id,
        "extension": row.extension,
        "state": row.state,
        "correlation_id": row.correlation_id,
        "completed_steps": row.completed_steps,
        "version": row.version,
    }


async def _fail_closed_action(
    request_id: str, action: str, session: AsyncSession
) -> dict:
    row = (
        await session.execute(
            select(TelephonyProvisioningSaga)
            .where(TelephonyProvisioningSaga.request_id == request_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "provisioning request not found")
    if action in {"activate", "deprovision"} and not settings.live_writes_enabled:
        raise HTTPException(503, f"{action} kill switch is closed")
    return {
        "request_id": request_id,
        "state": row.state,
        "action": action,
        "accepted": False,
    }


@router.post("/provisioning/{request_id}/activate")
async def activate(request_id: str, session: AsyncSession = Depends(get_session)):
    return await _fail_closed_action(request_id, "activate", session)


@router.post("/provisioning/{request_id}/suspend")
async def suspend(request_id: str, session: AsyncSession = Depends(get_session)):
    return await _fail_closed_action(request_id, "suspend", session)


@router.post("/provisioning/{request_id}/deprovision")
async def deprovision(request_id: str, session: AsyncSession = Depends(get_session)):
    return await _fail_closed_action(request_id, "deprovision", session)


@router.post("/provisioning/{request_id}/rollback")
async def rollback(request_id: str, session: AsyncSession = Depends(get_session)):
    return await _fail_closed_action(request_id, "rollback", session)


@router.post("/reconcile")
async def reconcile():
    return {
        "mode": "report-only",
        "state": "accepted",
        "authoritative_sources": sorted(AUTHORITATIVE_SOURCES),
    }


# --- Click-to-call origination -------------------------------------------
#
# Odoo CRM -> (this endpoint) -> VicidialMtlsClient.originate -> VICIdial
# edge adapter -> Asterisk -> agent endpoint -> PSTN.
#
# Fails closed at three independent layers so the whole path is safe to
# exercise end-to-end while external_dial_enabled/live_writes_enabled are
# false: (1) the campaign guard below, (2) the default-deny WebRTC
# production policy (config/webrtc-production-policy.default-deny.json),
# and (3) VicidialMtlsClient.originate's own flag check. No layer trusts
# the others.

_ORIGINATE_RATE_LIMIT_PER_MINUTE = 10


class ConsentInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    scope: str
    timestamp: datetime | None = None
    expiration: datetime | None = None
    source: str
    reference: str


class OriginateCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=16, max_length=256)
    employee_id: str = Field(min_length=1, max_length=128)
    campaign: str = Field(min_length=1, max_length=64)
    business_unit: str = Field(min_length=1, max_length=64)
    destination: str = Field(min_length=8, max_length=32)
    destination_class: str = Field(default="mobile", max_length=32)
    destination_country: str = Field(min_length=2, max_length=2)
    destination_timezone: str = Field(min_length=1, max_length=64)
    caller_id: str = Field(min_length=1, max_length=32)
    lead_model: str = Field(min_length=1, max_length=64)
    lead_id: int
    recording_requested: bool = False
    consent: ConsentInfo | None = None


def _rate_limit_originate(key: str) -> None:
    now = time.monotonic()
    bucket = _originate_requests[key]
    while bucket and bucket[0] < now - 60:
        bucket.popleft()
    if len(bucket) >= _ORIGINATE_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(429, "call origination rate limit exceeded")
    bucket.append(now)


async def _lookup_agent_assignment(employee_id: str, campaign: str, http: httpx.AsyncClient) -> dict:
    """Authoritative Odoo-side lookup of the agent's permitted VICIdial identity.

    Deliberately independent of app.api.v1.webphone._odoo_identity (that
    module is an isolated staging gate per its own docstring) even though
    both call the same identity service with the same HMAC scheme -- this
    endpoint must not depend on that router's framing or lifecycle.
    """
    if (
        not settings.odoo_identity_lookup_url
        or not settings.odoo_identity_lookup_hmac_file
    ):
        raise HTTPException(503, "identity service unavailable")
    try:
        secret = Path(settings.odoo_identity_lookup_hmac_file).read_text().strip()
    except OSError as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    url = (
        f"{settings.odoo_identity_lookup_url.rstrip('/')}/{quote(employee_id, safe='')}"
    )
    url += "?" + urlencode({"campaign_id": campaign})
    parts = urlsplit(url)
    canonical = str(int(time.time())) + "." + parts.path
    if parts.query:
        canonical += "?" + parts.query
    timestamp = canonical.split(".", 1)[0]
    signature = hmac.new(
        secret.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    try:
        response = await http.get(
            url,
            headers={
                "X-Codestra-Identity-Timestamp": timestamp,
                "X-Codestra-Identity-Signature": f"sha256={signature}",
            },
            timeout=8,
        )
        if response.status_code >= 400:
            raise HTTPException(
                response.status_code if response.status_code in {401, 403} else 503,
                "employee identity not authorized",
            )
        payload = response.json()
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "identity service unavailable") from exc
    if not isinstance(payload, dict):
        raise HTTPException(503, "invalid identity response")
    return payload


def _load_call_policy() -> Policy:
    return Policy.from_file(Path(settings.webrtc_production_policy_path))


async def originate_call(
    payload: OriginateCallRequest,
    session: AsyncSession = Depends(get_session),
    x_correlation_id: str | None = Header(default=None, alias="X-Correlation-ID"),
    http: httpx.AsyncClient = Depends(get_http_client),
):
    """Agent-UI originate admission on the ORM lifecycle ledger.

    Not routed: ``POST /v1/telephony/calls/originate`` is owned by the
    documented Odoo calling contract (``app.telephony_api``, service-JWT
    ``telephony.calls.originate``), which the single application factory
    mounts. Registering this handler on the same operation would shadow one
    of the two silently. The handler stays callable for the lifecycle tests
    and for a future explicitly routed agent-UI surface.
    """
    correlation_id = x_correlation_id or str(uuid4())

    # Idempotent replay short-circuits everything else -- the caller
    # already paid the authorization/rate-limit cost once.
    key_hash = _hash(payload.idempotency_key)
    replay = (
        await session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.scope == "telephony/calls/originate",
                IdempotencyRecord.key_hash == key_hash,
            )
        )
    ).scalar_one_or_none()
    if replay:
        return replay.response

    # Record "requested" the moment a de-duplicated request is accepted for
    # processing -- before rate limiting, campaign gating, agent-identity
    # lookup, or destination validation. This is Middleware's own
    # control-plane transaction, not an AMI/VICIdial-sourced signal: a call
    # that never reaches VICIdial must still leave evidence that it was
    # requested. source_extension is unknown until identity lookup succeeds
    # below, so it starts blank and is filled in once known.
    call_id = uuid4()
    now = datetime.now(UTC)
    audit_payload = {
        "employee_id": payload.employee_id,
        "campaign": payload.campaign,
        "business_unit": payload.business_unit,
        "lead_model": payload.lead_model,
        "lead_id": payload.lead_id,
        "destination_reference": hashlib.sha256(
            payload.destination.encode()
        ).hexdigest()[:16],
    }
    lifecycle = TelephonyCallLifecycle(
        id=call_id,
        correlation_id=correlation_id,
        primary_unique_id=f"click-to-call:{call_id}",
        lifecycle_state="STARTED",
        fine_state="requested",
        fine_state_at=now,
        last_event_sequence=0,
        started_at=now,
        source_extension="",
        destination=payload.destination,
        dialplan_context="click-to-call",
        lead_model=payload.lead_model,
        lead_id=payload.lead_id,
    )
    session.add(lifecycle)
    await session.commit()

    async def _reject_before_dispatch(reason: str) -> None:
        rejected_at = datetime.now(UTC)
        lifecycle.lifecycle_state = "ENDED"
        lifecycle.fine_state = "rejected"
        lifecycle.fine_state_at = rejected_at
        lifecycle.disposition = "REJECTED"
        lifecycle.ended_at = rejected_at
        lifecycle.hangup_cause = reason
        session.add(
            AuditEvent(
                action="telephony.calls.originate",
                subject=str(call_id),
                correlation_id=correlation_id,
                decision="DENY",
                redacted_payload={**audit_payload, "rejection_reason": reason},
            )
        )
        await session.commit()

    try:
        _rate_limit_originate(payload.employee_id)

        # Production campaigns remain hard-blocked at the application layer,
        # matching the existing house convention (see
        # /api/v1/transfers/requests in app/api/v1/control.py).
        if payload.campaign != "TEST_SYN" and not settings.allow_non_test_campaigns:
            raise HTTPException(403, "production campaigns are disabled")

        # The request body's campaign/business_unit/caller_id are claims from
        # Odoo; only the identity service's answer is trusted for
        # authorization.
        identity = await _lookup_agent_assignment(payload.employee_id, payload.campaign, http)
        campaigns = identity.get("campaign_ids")
        endpoint = identity.get("endpoint")
        vicidial_username = identity.get("vicidial_username")
        business_unit_id = identity.get("business_unit_id")
        if (
            not isinstance(campaigns, list)
            or payload.campaign not in campaigns
            or not isinstance(endpoint, str)
            or not endpoint.isdigit()
            or not isinstance(vicidial_username, str)
            or not vicidial_username
            or not business_unit_id
            or str(business_unit_id) != payload.business_unit
        ):
            raise HTTPException(403, "agent is not authorized for this campaign")

        # The real extension is known as soon as identity lookup succeeds --
        # record it immediately so a later rejection (e.g. bad destination)
        # still leaves an accurate row, not the placeholder.
        lifecycle.source_extension = endpoint

        if not E164.fullmatch(payload.destination):
            raise HTTPException(422, "destination must be a valid E.164 number")
    except HTTPException as exc:
        await _reject_before_dispatch(f"pre_dial_validation:{exc.status_code}")
        raise

    # Evaluate the default-deny production policy. While it stays
    # disabled/kill-switched (the checked-in default), this always returns
    # DENY -- the endpoint is fully exercisable end-to-end without ever
    # being able to place a real call.
    policy = _load_call_policy()
    consent = None
    if payload.consent is not None:
        consent = PolicyConsent(
            status=payload.consent.status,
            scope=payload.consent.scope,
            timestamp=payload.consent.timestamp,
            expiration=payload.consent.expiration,
            source=payload.consent.source,
            reference=payload.consent.reference,
        )
    decision = authorize_call(
        policy,
        PolicyCallRequest(
            correlation_id=correlation_id,
            agent_subject=vicidial_username,
            tenant=business_unit_id,
            business_unit=payload.business_unit,
            campaign=payload.campaign,
            extension=endpoint,
            caller_id=payload.caller_id,
            destination=payload.destination,
            destination_class=payload.destination_class,
            destination_country=payload.destination_country,
            destination_timezone=payload.destination_timezone,
            recording_requested=payload.recording_requested,
            consent=consent,
            requested_at=now,
        ),
    )

    # The lifecycle row (with fine_state="requested") was already created and
    # committed above, before rate limiting/campaign/identity/E.164
    # validation, so that a call rejected at any of those gates still leaves
    # persisted evidence. Only the audit event is new here.
    session.add(
        AuditEvent(
            action="telephony.calls.originate",
            subject=str(call_id),
            correlation_id=correlation_id,
            decision=decision.value,
            redacted_payload=audit_payload,
        )
    )

    dialing_status = "blocked"
    dial_reason = f"policy_decision:{decision.value}"
    if decision != Decision.ALLOW:
        lifecycle.lifecycle_state = "ENDED"
        lifecycle.fine_state = "rejected"
        lifecycle.fine_state_at = datetime.now(UTC)
        lifecycle.disposition = "REJECTED"
        lifecycle.ended_at = lifecycle.fine_state_at
    if decision == Decision.ALLOW:
        adapter = VicidialMtlsClient(settings)
        try:
            adapter.originate(
                {
                    "call_id": str(call_id),
                    "correlation_id": correlation_id,
                    "extension": endpoint,
                    "vicidial_username": vicidial_username,
                    "campaign": payload.campaign,
                    "destination": payload.destination,
                    "caller_id": payload.caller_id,
                },
                correlation_id=correlation_id,
                request_id=str(call_id),
            )
            dialing_status = "attempting"
            dial_reason = "accepted"
            lifecycle.fine_state = "accepted"
            lifecycle.fine_state_at = datetime.now(UTC)
        except VicidialMtlsError:
            dialing_status = "blocked"
            # Adapter details can include internal transport information.
            dial_reason = "adapter_error"
            lifecycle.lifecycle_state = "ENDED"
            lifecycle.fine_state = "failed"
            lifecycle.fine_state_at = datetime.now(UTC)
            lifecycle.ended_at = lifecycle.fine_state_at
            lifecycle.disposition = "FAILED"
            lifecycle.hangup_cause = "adapter_error"
        finally:
            adapter.close()

    session.add(
        OutboxEvent(
            topic="call.state.started",
            payload={
                "call_id": str(call_id),
                "correlation_id": correlation_id,
                "lead_model": payload.lead_model,
                "lead_id": payload.lead_id,
                "business_unit": payload.business_unit,
                "campaign": payload.campaign,
                "state": lifecycle.lifecycle_state,
                "fine_state": lifecycle.fine_state,
                "last_event_sequence": lifecycle.last_event_sequence,
                "dialing": dialing_status,
            },
            correlation_id=correlation_id,
        )
    )

    response = {
        "call_id": str(call_id),
        "correlation_id": correlation_id,
        "lifecycle_state": lifecycle.lifecycle_state,
        "fine_state": lifecycle.fine_state,
        "last_event_sequence": lifecycle.last_event_sequence,
        "dialing": dialing_status,
        "reason": dial_reason,
        "policy_decision": decision.value,
    }
    logger.info(
        "telephony_originate_completed",
        extra={
            "call_id": str(call_id),
            "correlation_id": correlation_id,
            "campaign": payload.campaign,
            "policy_decision": decision.value,
            "dialing": dialing_status,
        },
    )
    session.add(
        IdempotencyRecord(
            scope="telephony/calls/originate",
            key_hash=key_hash,
            request_hash=hashlib.sha256(
                json.dumps(
                    payload.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            response=response,
            status_code=200,
        )
    )
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            409, "concurrent origination conflict; retry safely"
        ) from exc
    return response
