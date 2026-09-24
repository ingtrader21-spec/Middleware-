import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.automation import (
    AutomationSecurityError,
    canonical_hash,
    redact,
    verify_exact_body,
    verify_timestamp,
)
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator
from app.db.models import AuditEvent, IdempotencyRecord
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/automation", tags=["automation"])
BUSINESS_UNITS = frozenset(
    {"GLOBAL", "MOY", "COD", "SCP", "MBL", "SRP", "RLP", "FTP", "TRX", "CAL"}
)


def _claim_values(claims: dict[str, Any], plural: str, singular: str) -> set[str]:
    values = claims.get(plural, claims.get(singular, []))
    if isinstance(values, str):
        return {item for item in values.replace(",", " ").split() if item}
    return {str(item) for item in values or []}


def _authenticate_campaign_policy(authorization: str) -> dict[str, Any]:
    """n8n service JWT, pinned to the deployment's own environment claim.

    The token's ``environment`` must equal ``settings.environment``: a token
    minted for another environment is rejected even when every other claim
    is valid (previously this route accepted production tokens only, which
    made it unreachable from a staging n8n).
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
    try:
        return KeycloakValidator(
            issuer=settings.n8n_service_issuer,
            audience=settings.n8n_service_audience,
            jwks_url=settings.n8n_service_jwks_url,
            authorized_parties=frozenset({settings.n8n_campaign_service_client_id}),
            required_scopes=frozenset({"n8n.policy.check"}),
            required_environment=settings.environment,
        ).validate(authorization.removeprefix("Bearer ").strip())
    except JWTAuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = Field(
        pattern=r"^1(?:\.\d+)?$",
        validation_alias=AliasChoices("schema_version", "event_version"),
    )
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    event_time: datetime = Field(
        validation_alias=AliasChoices("event_time", "occurred_at")
    )
    environment: Literal["test", "staging", "integration", "production"]
    source_system: str = Field(
        min_length=1,
        max_length=64,
        validation_alias=AliasChoices("source_system", "source"),
    )
    business_unit: str = Field(default="GLOBAL", max_length=16)
    campaign_id: str = Field(min_length=1, max_length=64)
    entity_type: str = Field(default="unspecified", max_length=128)
    entity_id: str = Field(default="unspecified", max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    causation_id: str | None = Field(default=None, max_length=128)
    idempotency_key: str = Field(default="legacy-unspecified", max_length=255)
    payload: dict[str, Any]
    workflow_code: str | None = Field(
        default=None, pattern=r"^(?:WF|N8)-[A-Za-z0-9_.-]+$"
    )
    workflow_version: str | None = Field(default=None, max_length=32)
    data_minimized: bool = False


class CRMEventEnvelope(BaseModel):
    """Strict campaign CRM envelope; identity is never inferred from payload."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"]
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    correlation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=255)
    tenant_id: str = Field(min_length=1, max_length=128)
    business_unit_id: str = Field(pattern=r"^(?:GLOBAL|MOY|COD|SCP|MBL|SRP|RLP|FTP|TRX|CAL)$")
    campaign_id: str = Field(min_length=1, max_length=64)
    entity_type: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=128)
    actor_type: Literal["HUMAN", "AI", "SYSTEM"]
    actor_id: str = Field(min_length=1, max_length=128)
    previous_status: str | None = Field(default=None, max_length=128)
    current_status: str | None = Field(default=None, max_length=128)
    occurred_at: datetime
    automation_key: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]


def enforce_crm_scope(envelope: CRMEventEnvelope) -> None:
    if envelope.business_unit_id not in BUSINESS_UNITS:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "business unit not permitted")
    if envelope.campaign_id not in settings.allowed_campaigns:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "campaign not permitted")


def enforce_scope(envelope: EventEnvelope) -> None:
    if envelope.environment != settings.automation_environment:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "environment not permitted")
    if envelope.business_unit not in BUSINESS_UNITS:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "business unit not permitted")
    if envelope.campaign_id not in settings.allowed_campaigns:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "campaign not permitted")


class IdempotencyReservation(BaseModel):
    environment: Literal["test", "staging", "integration", "production"]
    workflow_code: str = Field(pattern=r"^(?:WF|N8)-[A-Za-z0-9_.-]+$")
    event_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)
    business_unit: str = Field(default="GLOBAL", max_length=16)
    campaign_id: str = Field(default="TEST_SYN", min_length=1, max_length=64)


@router.post("/idempotency/check")
async def reserve_idempotency(
    body: IdempotencyReservation,
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if body.environment != settings.automation_environment:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "environment not permitted")
    scope = f"n8n:{body.environment}:{body.workflow_code}"
    key_hash = hashlib.sha256(body.idempotency_key.encode()).hexdigest()
    request_hash = canonical_hash(redact(body.payload))
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:value, 0))"),
        {"value": f"{scope}:{key_hash}"},
    )
    existing = await db.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if existing:
        if existing.request_hash != request_hash:
            await db.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT, "idempotency key conflict")
        await db.commit()
        return {
            "allowed": False,
            "duplicate": True,
            "conflict": False,
            "environment": body.environment,
            "workflow_code": body.workflow_code,
            "event_id": body.event_id,
            "correlation_id": body.correlation_id,
            "idempotency_key": body.idempotency_key,
            "payload": body.payload,
            "business_unit": body.business_unit,
            "campaign_id": body.campaign_id,
        }
    response = {
        "allowed": True,
        "duplicate": False,
        "conflict": False,
        "environment": body.environment,
        "workflow_code": body.workflow_code,
        "event_id": body.event_id,
        "correlation_id": body.correlation_id,
        "idempotency_key": body.idempotency_key,
        "payload": body.payload,
        "business_unit": body.business_unit,
        "campaign_id": body.campaign_id,
    }
    db.add(
        IdempotencyRecord(
            scope=scope,
            key_hash=key_hash,
            request_hash=request_hash,
            response=response,
            status_code=202,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
    )
    db.add(
        AuditEvent(
            action="n8n.idempotency.reserved",
            subject=body.event_id,
            correlation_id=body.correlation_id,
            decision="accepted",
            redacted_payload={
                "workflow_code": body.workflow_code,
                "environment": body.environment,
            },
        )
    )
    await db.commit()
    return response


class AutomationAuditResult(BaseModel):
    workflow_code: str = Field(pattern=r"^(?:WF|N8)-[A-Za-z0-9_.-]+$")
    workflow_version: str = Field(min_length=1, max_length=32)
    execution_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=255)
    business_unit: str = Field(pattern=r"^(?:GLOBAL|MOY|COD|SCP|MBL|SRP|RLP|FTP|TRX|CAL)$")
    campaign_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    status: Literal["accepted", "completed", "failed", "dead_lettered", "duplicate"]
    error_category: str | None = Field(default=None, max_length=64)
    details: dict[str, Any] = Field(default_factory=dict)


@router.post("/audit/result", status_code=202)
async def record_audit_result(
    body: AutomationAuditResult,
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    db.add(
        AuditEvent(
            action=f"n8n.{body.action}",
            subject=body.event_id,
            correlation_id=body.correlation_id,
            decision=body.status,
            redacted_payload=redact(
                {
                    "workflow_code": body.workflow_code,
                    "workflow_version": body.workflow_version,
                    "execution_id": body.execution_id,
                    "business_unit": body.business_unit,
                    "campaign_id": body.campaign_id,
                    "provider": body.provider,
                    "error_category": body.error_category,
                    "details": body.details,
                }
            ),
        )
    )
    await db.commit()
    return {
        "accepted": True,
        "event_id": body.event_id,
        "correlation_id": body.correlation_id,
        "status": body.status,
    }


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def receive_event(
    request: Request,
    x_codestra_event_id: str = Header(alias="X-Codestra-Event-ID"),
    x_codestra_workflow_id: str = Header(alias="X-Codestra-Workflow-ID"),
    x_codestra_timestamp: str = Header(alias="X-Codestra-Timestamp"),
    x_codestra_signature: str = Header(alias="X-Codestra-Signature"),
) -> dict[str, Any]:
    body = await request.body()
    try:
        verify_timestamp(
            x_codestra_timestamp, ttl_seconds=settings.signature_ttl_seconds
        )
        verify_exact_body(body, x_codestra_signature, settings.webhook_shared_secret)
        envelope = EventEnvelope.model_validate_json(body)
    except AutomationSecurityError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid event schema"
        ) from exc
    if envelope.event_id != x_codestra_event_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "event identifier mismatch"
        )
    if not x_codestra_workflow_id.startswith("WF-"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "workflow not permitted")
    enforce_scope(envelope)
    if not settings.n8n_event_delivery_enabled:
        return {
            "accepted": True,
            "event_id": envelope.event_id,
            "status": "delivery_disabled",
        }
    return {"accepted": True, "event_id": envelope.event_id, "status": "queued"}


@router.post("/policy-check")
async def policy_check(
    body: dict[str, Any],
    authorization: str = Header(alias="Authorization"),
) -> dict[str, Any]:
    claims = _authenticate_campaign_policy(authorization)
    try:
        if "tenant_id" in body or "actor_type" in body:
            crm_envelope = CRMEventEnvelope.model_validate(body)
            enforce_crm_scope(crm_envelope)
            if (
                crm_envelope.campaign_id
                not in _claim_values(claims, "campaigns", "campaign_scope")
                or crm_envelope.business_unit_id
                not in _claim_values(claims, "business_units", "business_unit_scope")
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "campaign policy scope denied")
            response_body = crm_envelope.model_dump(mode="json")
        else:
            legacy_envelope = EventEnvelope.model_validate(body)
            enforce_scope(legacy_envelope)
            if (
                legacy_envelope.campaign_id
                not in _claim_values(claims, "campaigns", "campaign_scope")
                or legacy_envelope.business_unit
                not in _claim_values(claims, "business_units", "business_unit_scope")
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "campaign policy scope denied")
            response_body = legacy_envelope.model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid automation event schema") from exc
    return {
        **response_body,
        "allowed": True,
        "workflow_id": "validated-by-router",
    }


class Lifecycle(BaseModel):
    event_id: str
    workflow_id: str
    execution_reference: str
    attempt_number: int = Field(ge=1)
    details: dict[str, Any] = Field(default_factory=dict)


@router.post("/executions/{transition}", status_code=202)
async def execution_transition(
    transition: Literal["start", "complete", "fail", "retry"], body: Lifecycle
) -> dict[str, Any]:
    return {
        "accepted": True,
        "transition": transition,
        "event_id": body.event_id,
        "details": redact(body.details),
    }


@router.post("/events/dead-letter", status_code=202)
async def dead_letter(body: Lifecycle) -> dict[str, Any]:
    return {
        "accepted": True,
        "status": "dead_lettered",
        "event_id": body.event_id,
        "details": redact(body.details),
    }


@router.get("/events/{event_id}")
async def event_status(
    event_id: str, db: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    row = (
        await db.execute(
            text(
                "SELECT r.status FROM n8n_execution_registration r "
                "JOIN broad_event_delivery d ON d.delivery_id=r.delivery_id "
                "JOIN integration_event e ON e.id=d.event_id "
                "WHERE e.original_event_id=:event_id"
            ),
            {"event_id": event_id},
        )
    ).scalar_one_or_none()
    return {"event_id": event_id, "status": row or "NOT_FOUND"}


CONTEXT_RESOURCES = {"calls", "leads", "agents", "campaigns", "timeline"}


@router.get("/context/{resource}/{identifier}")
async def context(resource: str, identifier: str) -> dict[str, Any]:
    if resource not in CONTEXT_RESOURCES:
        raise HTTPException(404, "unknown context resource")
    if not settings.vicidial_read_enabled:
        raise HTTPException(503, "VICIDIAL_READ_ENABLED is false")
    return {"resource": resource, "identifier": identifier, "data": {}}


@router.get("/callbacks/{state}")
async def callbacks(state: Literal["due", "overdue"]) -> dict[str, Any]:
    return {"state": state, "timezone": "America/Santo_Domingo", "items": []}


@router.get("/queues/status")
async def queue_status() -> dict[str, Any]:
    return {"campaigns": [], "generated_at": datetime.now(UTC)}


ACTION_NAMES = {
    "lead-enrichment",
    "callbacks",
    "notifications",
    "lead-priority",
    "lead-assignment",
    "qa-review",
    "contact-suppression",
    "report-delivery",
}


@router.post("/actions/{action}", status_code=202)
async def authorized_action(action: str, body: dict[str, Any]) -> dict[str, Any]:
    if action not in ACTION_NAMES:
        raise HTTPException(404, "unknown action")
    if not settings.automation_actions_enabled:
        raise HTTPException(503, "AUTOMATION_ACTIONS_ENABLED is false")
    campaign = body.get("campaign_id")
    if campaign not in settings.allowed_campaigns:
        raise HTTPException(403, "campaign not permitted")
    return {**redact(body), "accepted": True, "action_result": action}
