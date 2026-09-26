import hashlib
import json
from typing import Any
from uuid import uuid4
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.integration_admin_auth import IntegrationAdminPrincipal, require_integration_admin
from app.db.session import get_session
from app.db.models import (
    AuditEvent,
    EventInbox,
    IdempotencyRecord,
    OutboxEvent,
    PolicyDecision,
    ReconciliationCheckpoint,
    TransferPolicyDecision,
)
from app.core.reliability import authorize_transfer, redact, sanitize_for_storage

router = APIRouter(prefix="/api/v1", tags=["control-plane"])
# TEST_SYN-only synthetic event aliases. They are served by the in-process
# monolith only (behind its bearer guard); the deployed application serves
# provider events through the signed ingress routes instead.
legacy_events_router = APIRouter(prefix="/api/v1", tags=["control-plane-legacy-events"])


class Envelope(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str | None = None
    campaign_id: str | None = None
    payload: dict[str, Any] = {}


class Callback(BaseModel):
    phone: str = Field(min_length=7, max_length=32)
    lead_id: int
    scheduled_for: str
    note: str | None = None


class Transfer(BaseModel):
    lead_id: int
    target: str
    reason: str | None = None
    campaign_id: str = "TEST_SYN"
    do_not_call: bool = False


class Compliance(BaseModel):
    event_type: str
    lead_id: int | None = None
    payload: dict[str, Any] = {}


class Recommendation(BaseModel):
    recommendation: str
    reason: str | None = None


class Idem:
    @staticmethod
    async def check(db, key, scope, body):
        if not key:
            raise HTTPException(400, "Idempotency-Key is required")
        h = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        kh = hashlib.sha256(key.encode()).hexdigest()
        row = await db.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.scope == scope, IdempotencyRecord.key_hash == kh
            )
        )
        if row and row.request_hash != h:
            raise HTTPException(409, "idempotency key conflict")
        return row, h, kh


async def persist(
    db, action, subject, correlation, payload, allowed=True, reason="accepted"
):
    redacted = redact(payload)
    db.add(
        AuditEvent(
            action=action,
            subject=subject,
            correlation_id=correlation,
            decision="allow" if allowed else "deny",
            redacted_payload=redacted,
        )
    )
    db.add(
        PolicyDecision(
            policy=action,
            allowed=allowed,
            reason=reason,
            correlation_id=correlation,
            context=redacted,
        )
    )
    await db.flush()


# /events/vicidial is owned by the signed HMAC ingress (app.api.v1.events);
# the former alias here was always shadowed by it and is not registered.
@legacy_events_router.post("/events/odoo", status_code=202)
async def event(
    request: Request,
    body: Envelope,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    if body.campaign_id and body.campaign_id != "TEST_SYN":
        raise HTTPException(403, "production campaigns are disabled")
    corr = x_correlation_id or str(uuid4())
    raw = body.model_dump()
    stored = sanitize_for_storage(raw)
    key = idempotency_key or body.event_id
    row, h, kh = await Idem.check(db, key, "events", raw)
    if row:
        return row.response
    eid = body.event_id or str(uuid4())
    stored["event_id"] = eid
    stored["correlation_id"] = corr
    db.add(
        EventInbox(
            event_id=eid,
            source="odoo" if request.url.path.endswith("odoo") else "vicidial",
            event_type="event",
            payload=stored,
            correlation_id=corr,
        )
    )
    db.add(OutboxEvent(topic="event.accepted", payload=stored, correlation_id=corr))
    await persist(db, "event.ingest", eid, corr, stored)
    response = {
        "accepted": True,
        "event_id": eid,
        "status": "queued",
        "correlation_id": corr,
    }
    db.add(
        IdempotencyRecord(
            scope="events",
            key_hash=kh,
            request_hash=h,
            response=response,
            status_code=202,
        )
    )
    await db.commit()
    return response


@legacy_events_router.get("/events/{event_id}")
async def event_status(event_id: str, db: AsyncSession = Depends(get_session)):
    row = await db.scalar(select(EventInbox).where(EventInbox.event_id == event_id))
    if not row:
        raise HTTPException(404, "event not found")
    return {
        "event_id": row.event_id,
        "status": row.status,
        "correlation_id": row.correlation_id,
    }


async def mutation(path, body, db, key, corr):
    raw = body.model_dump()
    row, h, kh = await Idem.check(db, key, path, raw)
    if row:
        return row.response
    ident = str(uuid4())
    await persist(db, path, ident, corr, raw)
    response = {"id": ident, "status": "accepted", "correlation_id": corr}
    db.add(
        IdempotencyRecord(
            scope=path, key_hash=kh, request_hash=h, response=response, status_code=202
        )
    )
    await db.commit()
    return response


@router.post("/callbacks", status_code=202)
async def callback(
    body: Callback,
    request: Request,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    return await mutation(
        "callbacks", body, db, idempotency_key, x_correlation_id or str(uuid4())
    )


@router.patch("/callbacks/{id}", status_code=202)
async def callback_patch(
    id: str,
    body: Callback,
    request: Request,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    return await mutation(
        f"callbacks/{id}", body, db, idempotency_key, x_correlation_id or str(uuid4())
    )


@router.post("/transfers/requests", status_code=202)
async def transfer(
    body: Transfer,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    if body.do_not_call:
        raise HTTPException(403, "do-not-call policy denies transfer")
    if body.campaign_id != "TEST_SYN":
        raise HTTPException(403, "production telephony is disabled")
    return await mutation(
        "transfers/requests",
        body,
        db,
        idempotency_key,
        x_correlation_id or str(uuid4()),
    )


@router.post("/transfers/{id}/{decision}", status_code=202)
async def transfer_decision(
    id: str,
    decision: str,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
    principal: IntegrationAdminPrincipal = Depends(require_integration_admin),
    x_do_not_call: bool = Header(False, alias="X-Do-Not-Call"),
):
    if decision not in ("approve", "deny"):
        raise HTTPException(404, "unknown decision")
    corr = x_correlation_id or str(uuid4())
    allowed, reason = authorize_transfer(
        dnc=x_do_not_call,
        authenticated=True,
        role=principal.role,
        campaign_id="TEST_SYN",
        live_enabled=False,
    )
    db.add(
        TransferPolicyDecision(
            transfer_id=id, allowed=allowed, reason=reason, correlation_id=corr
        )
    )
    await persist(db, "transfer." + decision, id, corr, {"id": id}, allowed, reason)
    await db.commit()
    return {"id": id, "decision": "denied", "reason": reason, "correlation_id": corr}


@router.post("/compliance/events", status_code=202)
async def compliance(
    body: Compliance,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    return await mutation(
        "compliance/events", body, db, idempotency_key, x_correlation_id or str(uuid4())
    )


@router.post("/ai/recommendations/{id}/{decision}", status_code=202)
async def ai_decision(
    id: str,
    decision: str,
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    if decision not in ("accept", "reject"):
        raise HTTPException(404, "unknown decision")
    return await mutation(
        f"ai/{decision}/{id}",
        Recommendation(recommendation=decision),
        db,
        idempotency_key,
        x_correlation_id or str(uuid4()),
    )


@router.post("/reconciliation/run", status_code=202)
async def reconciliation(
    db: AsyncSession = Depends(get_session),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    x_correlation_id: str | None = Header(None, alias="X-Correlation-ID"),
):
    return await mutation(
        "reconciliation/run",
        Envelope(),
        db,
        idempotency_key,
        x_correlation_id or str(uuid4()),
    )


@router.get("/reconciliation/status")
async def reconciliation_status(db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(ReconciliationCheckpoint))).scalars().all()
    return {
        "checkpoints": [
            {"source": x.source, "status": x.status, "cursor": x.cursor} for x in rows
        ]
    }
