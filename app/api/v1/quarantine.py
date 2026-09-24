"""Privileged reviewer surface; immutable raw payloads are never returned."""

from datetime import datetime, time, timezone
import hashlib
import hmac
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from prometheus_client import Counter
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.publisher import QUARANTINE_OLDEST, QUARANTINE_PENDING, validate_event
from app.core.config import settings
from app.core.policy_engine import PolicyRequest, evaluate
from app.core.quarantine import (
    EncryptedPayload,
    decrypt_payload,
    encrypt_payload,
    fingerprint,
    sanitized_preview,
    transition,
)
from app.db.models import (
    AuditEvent,
    IntegrationDelivery,
    IntegrationEvent,
    InvalidEventQuarantine,
    QuarantineCorrection,
    PolicyDecision,
)
from app.db.session import get_session


router = APIRouter(prefix="/api/v1/quarantine", tags=["invalid-event-quarantine"])
REPROCESSING = Counter(
    "quarantine_reprocessing_total",
    "Authorized quarantine reprocessing",
    ["result"],
)
REPROCESSING_FAILURES = Counter(
    "quarantine_reprocessing_failures_total",
    "Quarantine reprocessing failures",
    ["reason_code"],
)


def _authorize(
    required: str,
    scopes: str,
    reviewer: str,
    requested_unit: str | None,
    authorized_units: str,
    authorization_context: str,
) -> None:
    canonical = "\n".join((reviewer, scopes, authorized_units)).encode()
    expected = hmac.new(
        settings.quarantine_reviewer_secret, canonical, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, authorization_context):
        raise HTTPException(403, "quarantine authorization context denied")
    granted = frozenset(value for value in scopes.split() if value)
    if required not in granted or not reviewer or len(reviewer) > 128:
        raise HTTPException(403, "quarantine access denied")
    units = frozenset(value for value in authorized_units.split(",") if value)
    if requested_unit and requested_unit not in units:
        raise HTTPException(403, "business-unit access denied")


def _view(record: InvalidEventQuarantine) -> dict[str, object]:
    return {
        "id": str(record.id),
        "server_correlation_id": record.server_correlation_id,
        "client_correlation_id": record.client_correlation_id,
        "claimed_source": record.claimed_source,
        "claimed_publisher_identity": record.claimed_publisher_identity,
        "authenticated_publisher_id": record.authenticated_publisher_id,
        "authentication_state": record.authentication_state,
        "authentication_key_id": record.authentication_key_id,
        "original_signature_verification": record.original_signature_verification,
        "payload_fingerprint": record.payload_fingerprint,
        "encryption_key_version": record.encryption_key_version,
        "sanitized_preview": record.sanitized_preview,
        "reason_code": record.reason_code,
        "business_unit": record.business_unit,
        "status": record.status,
        "occurrence_count": record.occurrence_count,
        "replay_count": record.replay_count,
        "legal_hold": record.legal_hold,
        "record_version": record.record_version,
        "received_at": record.received_at,
        "retention_deadline": record.retention_deadline,
        "replayed_event_id": record.replayed_event_id,
    }


@router.get("")
async def list_records(
    business_unit: str | None = None,
    scopes: str = Header(default="", alias="X-Codestra-Scopes"),
    reviewer: str = Header(default="", alias="X-Reviewer-ID"),
    authorized_units: str = Header(default="", alias="X-Authorized-Business-Units"),
    authorization_context: str = Header(default="", alias="X-Quarantine-Authorization"),
    db: AsyncSession = Depends(get_session),
):
    _authorize(
        "quarantine:read",
        scopes,
        reviewer,
        business_unit,
        authorized_units,
        authorization_context,
    )
    statement = (
        select(InvalidEventQuarantine)
        .order_by(InvalidEventQuarantine.received_at.desc())
        .limit(100)
    )
    if business_unit:
        statement = statement.where(
            InvalidEventQuarantine.business_unit == business_unit
        )
    records = (await db.scalars(statement)).all()
    pending_count, oldest = (
        await db.execute(
            select(
                func.count(InvalidEventQuarantine.id),
                func.min(InvalidEventQuarantine.received_at),
            ).where(InvalidEventQuarantine.status == "PENDING_REVIEW")
        )
    ).one()
    QUARANTINE_PENDING.set(pending_count)
    QUARANTINE_OLDEST.set(
        max(
            0,
            (datetime.now(timezone.utc) - oldest).total_seconds() if oldest else 0,
        )
    )
    return {"items": [_view(record) for record in records]}


@router.get("/{record_id:uuid}")
async def detail(
    record_id: UUID,
    scopes: str = Header(default="", alias="X-Codestra-Scopes"),
    reviewer: str = Header(default="", alias="X-Reviewer-ID"),
    authorized_units: str = Header(default="", alias="X-Authorized-Business-Units"),
    authorization_context: str = Header(default="", alias="X-Quarantine-Authorization"),
    db: AsyncSession = Depends(get_session),
):
    record = await db.get(InvalidEventQuarantine, record_id)
    if not record:
        raise HTTPException(404, "quarantine record not found")
    _authorize(
        "quarantine:read",
        scopes,
        reviewer,
        record.business_unit,
        authorized_units,
        authorization_context,
    )
    return _view(record)


@router.post("/{record_id:uuid}/review")
async def review(
    record_id: UUID,
    target_state: str,
    record_version: int,
    scopes: str = Header(default="", alias="X-Codestra-Scopes"),
    reviewer: str = Header(default="", alias="X-Reviewer-ID"),
    authorized_units: str = Header(default="", alias="X-Authorized-Business-Units"),
    authorization_context: str = Header(default="", alias="X-Quarantine-Authorization"),
    db: AsyncSession = Depends(get_session),
):
    record = await db.scalar(
        select(InvalidEventQuarantine)
        .where(InvalidEventQuarantine.id == record_id)
        .with_for_update()
    )
    if not record:
        raise HTTPException(404, "quarantine record not found")
    _authorize(
        "quarantine:review",
        scopes,
        reviewer,
        record.business_unit,
        authorized_units,
        authorization_context,
    )
    if record.record_version != record_version:
        raise HTTPException(409, "record version conflict")
    try:
        transition(record.status, target_state)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    now = datetime.now(timezone.utc)
    record.status = target_state
    record.review_owner = reviewer
    record.reviewed_at = now
    record.record_version += 1
    if target_state in {"RESOLVED_NO_REPLAY", "REJECTED"}:
        record.resolved_by = reviewer
        record.resolved_at = now
    db.add(
        AuditEvent(
            action="quarantine.review",
            subject=str(record.id),
            correlation_id=record.server_correlation_id,
            decision=target_state,
            redacted_payload={
                "reviewer": reviewer,
                "record_version": record.record_version,
            },
        )
    )
    await db.commit()
    return _view(record)


@router.post("/{record_id:uuid}/corrections")
async def create_correction(
    record_id: UUID,
    corrected_payload: dict = Body(...),
    correction_reason: str = Header(..., alias="X-Correction-Reason"),
    scopes: str = Header(default="", alias="X-Codestra-Scopes"),
    reviewer: str = Header(default="", alias="X-Reviewer-ID"),
    authorized_units: str = Header(default="", alias="X-Authorized-Business-Units"),
    authorization_context: str = Header(default="", alias="X-Quarantine-Authorization"),
    db: AsyncSession = Depends(get_session),
):
    import json

    record = await db.scalar(
        select(InvalidEventQuarantine)
        .where(InvalidEventQuarantine.id == record_id)
        .with_for_update()
    )
    if not record:
        raise HTTPException(404, "quarantine record not found")
    _authorize(
        "quarantine:review",
        scopes,
        reviewer,
        record.business_unit,
        authorized_units,
        authorization_context,
    )
    if record.status != "CORRECTABLE":
        raise HTTPException(409, "record is not correctable")
    if not correction_reason.strip() or len(correction_reason) > 512:
        raise HTTPException(422, "correction reason is invalid")
    raw = json.dumps(corrected_payload, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > settings.request_max_bytes:
        raise HTTPException(413, "corrected payload too large")
    digest = fingerprint(raw, settings.quarantine_fingerprint_secret)
    encrypted = encrypt_payload(
        raw,
        settings.quarantine_encryption_key,
        settings.quarantine_encryption_key_version,
        digest,
    )
    prior = await db.scalar(
        select(QuarantineCorrection)
        .where(QuarantineCorrection.quarantine_id == record.id)
        .order_by(QuarantineCorrection.correction_version.desc())
        .limit(1)
    )
    version = (prior.correction_version if prior else 0) + 1
    before = record.sanitized_preview
    after = sanitized_preview(raw)
    correction = QuarantineCorrection(
        quarantine_id=record.id,
        correction_version=version,
        correction_reason=correction_reason.strip(),
        reviewer=reviewer,
        derived_correlation_id=str(uuid4()),
        payload_fingerprint=digest,
        encrypted_payload=encrypted.ciphertext,
        encryption_nonce=encrypted.nonce,
        encryption_key_version=encrypted.key_version,
        sanitized_diff={"before": before, "after": after},
    )
    db.add(correction)
    record.record_version += 1
    db.add(
        AuditEvent(
            action="quarantine.correction.created",
            subject=str(record.id),
            correlation_id=correction.derived_correlation_id,
            decision="CORRECTED",
            redacted_payload={
                "reviewer": reviewer,
                "correction_version": version,
                "correction_reason": correction_reason.strip(),
                "sanitized_diff": correction.sanitized_diff,
            },
        )
    )
    await db.commit()
    return {
        "correction_id": str(correction.id),
        "correction_version": version,
        "derived_correlation_id": correction.derived_correlation_id,
        "payload_fingerprint": digest,
        "sanitized_diff": correction.sanitized_diff,
    }


@router.post("/{record_id:uuid}/reprocess")
async def reprocess(
    record_id: UUID,
    scopes: str = Header(default="", alias="X-Codestra-Scopes"),
    reviewer: str = Header(default="", alias="X-Reviewer-ID"),
    authorized_units: str = Header(default="", alias="X-Authorized-Business-Units"),
    authorization_context: str = Header(default="", alias="X-Quarantine-Authorization"),
    db: AsyncSession = Depends(get_session),
):
    record = await db.scalar(
        select(InvalidEventQuarantine)
        .where(InvalidEventQuarantine.id == record_id)
        .with_for_update()
    )
    if not record:
        raise HTTPException(404, "quarantine record not found")
    business_unit = record.business_unit
    _authorize(
        "quarantine:replay",
        scopes,
        reviewer,
        business_unit,
        authorized_units,
        authorization_context,
    )
    if business_unit is None:
        raise HTTPException(409, "quarantine business unit unavailable")
    if record.status == "REPLAYED":
        return {
            "status": "REPLAYED",
            "event_id": record.replayed_event_id,
            "duplicate": True,
        }
    if (
        record.status != "REPLAY_APPROVED"
        or record.authentication_state != "VERIFIED"
        or record.original_signature_verification != "VERIFIED"
    ):
        raise HTTPException(409, "record is not replay eligible")
    if not all(
        (
            record.encrypted_payload,
            record.encryption_nonce,
            record.encryption_key_version,
        )
    ):
        raise HTTPException(409, "immutable payload unavailable")
    record.status = "REPLAYING"
    await db.flush()
    try:
        correction = await db.scalar(
            select(QuarantineCorrection)
            .where(QuarantineCorrection.quarantine_id == record.id)
            .order_by(QuarantineCorrection.correction_version.desc())
            .limit(1)
        )
        ciphertext = (
            correction.encrypted_payload if correction else record.encrypted_payload
        )
        nonce = correction.encryption_nonce if correction else record.encryption_nonce
        key_version = (
            correction.encryption_key_version
            if correction
            else record.encryption_key_version
        )
        if ciphertext is None or nonce is None or key_version is None:
            raise HTTPException(409, "immutable payload unavailable")
        encrypted_value = EncryptedPayload(ciphertext, nonce, key_version)
        expected_fingerprint = (
            correction.payload_fingerprint if correction else record.payload_fingerprint
        )
        raw = decrypt_payload(
            encrypted_value,
            settings.quarantine_encryption_key,
            expected_fingerprint,
            settings.quarantine_fingerprint_secret,
        )
        import json

        value = json.loads(raw)
        validate_event(value)
        now = datetime.now(timezone.utc)
        policy = evaluate(
            PolicyRequest(
                correlation_id=str(uuid4()),
                action="sync",
                subject=str(value.get("agent_id") or "publisher"),
                resource=str(value.get("event_id")),
                evaluated_at=now,
                consent_allowed=not value["privacy"]["contains_customer_data"],
                consent_observed_at=now,
                dnc_suppressed=False,
                dnc_observed_at=now,
                customer_timezone="America/Santo_Domingo",
                jurisdiction="DO",
                calling_window_start=time(0),
                calling_window_end=time(23, 59, 59),
                attempts=0,
                max_attempts=1,
                minimum_spacing_seconds=0,
                channel_eligible=True,
                business_unit=value["business_unit"],
                allowed_business_units=[business_unit],
                campaign=value["campaign"],
                allowed_campaigns=["TEST_SYN"],
                agent=value["agent_id"],
                allowed_agents=[value["agent_id"]],
                callback_allowed=False,
                transfer_allowed=False,
                recording_required=False,
                disclosure_present=True,
                emergency_kill_switch=False,
                shadow_mode=False,
            )
        )
        db.add(
            PolicyDecision(
                id=UUID(policy.decision_id),
                policy=policy.policy_version,
                allowed=policy.allow,
                reason=",".join(policy.reason_codes),
                correlation_id=policy.correlation_id,
                context=policy.model_dump(mode="json"),
            )
        )
        if not policy.allow:
            record.status = "REJECTED"
            record.resolved_by = reviewer
            record.resolved_at = now
            record.record_version += 1
            db.add(
                AuditEvent(
                    action="quarantine.authorized_reprocessing",
                    subject=str(record.id),
                    correlation_id=record.server_correlation_id,
                    decision="POLICY_DENIED",
                    redacted_payload={
                        "reviewer": reviewer,
                        "policy_decision_id": policy.decision_id,
                        "reason_codes": policy.reason_codes,
                    },
                )
            )
            await db.commit()
            REPROCESSING_FAILURES.labels("policy_denied").inc()
            raise HTTPException(403, "current policy denied reprocessing")
        existing = await db.scalar(
            select(IntegrationEvent).where(
                IntegrationEvent.original_event_id == value["event_id"]
            )
        )
        if existing:
            incoming = existing
        else:
            incoming = IntegrationEvent(
                idempotency_key=f"quarantine:{record.id}",
                event_type=value["event_type"],
                schema_version="2.0",
                original_event_id=value["event_id"],
                entity_key="synthetic:publisher-canary",
                source_system="authorized-reprocessing",
                correlation_id=str(uuid4()),
                payload_json=value,
                payload_hash=expected_fingerprint,
                state="accepted",
            )
            db.add(incoming)
            await db.flush()
            for target in ("odoo", "n8n"):
                db.add(
                    IntegrationDelivery(
                        event_id=incoming.id,
                        target=target,
                        status="disabled",
                        max_attempts=settings.outbox_max_attempts,
                    )
                )
        record.status = "REPLAYED"
        record.replayed_event_id = incoming.id
        record.replay_count += 1
        record.record_version += 1
        record.resolved_by = reviewer
        record.resolved_at = now
        db.add(
            AuditEvent(
                action="quarantine.authorized_reprocessing",
                subject=str(record.id),
                correlation_id=record.server_correlation_id,
                decision="REPLAYED",
                redacted_payload={
                    "reviewer": reviewer,
                    "canonical_event_id": incoming.id,
                    "original_timestamp_freshness_reused": False,
                    "correction_id": str(correction.id) if correction else None,
                },
            )
        )
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        await db.rollback()
        REPROCESSING_FAILURES.labels("validation_or_integrity").inc()
        raise HTTPException(409, "authorized reprocessing failed") from exc
    REPROCESSING.labels("success").inc()
    return {
        "status": "REPLAYED",
        "event_id": incoming.id,
        "duplicate": existing is not None,
    }
