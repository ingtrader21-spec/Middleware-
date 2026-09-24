"""JWT-authenticated durable n8n registration and acknowledgement contracts."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.automation import (
    AutomationSecurityError,
    canonical_hash,
    verify_timestamp,
)
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator
from app.db.models import (
    AuditEvent,
    BroadEventDelivery,
    IntegrationEvent,
    N8nAcknowledgement,
    N8nExecutionRegistration,
    N8nExecutionTransition,
    OdooResultDelivery,
    OutboxEvent,
    PublisherNonce,
)
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/n8n", tags=["n8n-production-transport"])
SHA256 = r"^(?:sha256:)?[0-9a-f]{64}$"


class ExecutionRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    registration_id: UUID
    delivery_id: UUID
    event_id: str = Field(min_length=1, max_length=128)
    workflow_key: str = Field(
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices("workflow_key", "workflow_id"),
    )
    workflow_version: str = Field(min_length=1, max_length=128)
    execution_id: str = Field(min_length=1, max_length=128)
    environment: Literal["production"]
    idempotency_key: str = Field(min_length=1, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=128)
    payload_hash: str = Field(pattern=SHA256)
    request_hash: str = Field(pattern=SHA256)
    policy_hash: str = Field(pattern=SHA256)
    attempt_number: int = Field(ge=1, le=8)
    received_at: datetime
    registered_at: datetime


class AcknowledgementMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duration_ms: int = Field(ge=0)


class AcknowledgementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    acknowledgement_id: UUID
    registration_id: UUID
    delivery_id: UUID
    event_id: str = Field(min_length=1, max_length=128)
    workflow_key: str = Field(
        min_length=1,
        max_length=128,
        validation_alias=AliasChoices("workflow_key", "workflow_id"),
    )
    workflow_version: str = Field(min_length=1, max_length=128)
    execution_id: str = Field(min_length=1, max_length=128)
    execution_status: Literal["SUCCEEDED", "FAILED", "DEAD_LETTERED"]
    result_classification: str = Field(min_length=1, max_length=64)
    result_hash: str = Field(pattern=SHA256)
    attempt_number: int = Field(ge=1)
    correlation_id: str = Field(min_length=1, max_length=128)
    policy_hash: str = Field(pattern=SHA256)
    started_at: datetime
    completed_at: datetime
    metrics: AcknowledgementMetrics


class ExecutionTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    transition_id: UUID
    state: Literal["RUNNING", "SUCCEEDED", "FAILED", "DEAD_LETTERED"]
    correlation_id: str = Field(min_length=1, max_length=128)
    attempt_number: int = Field(ge=1, le=8)
    occurred_at: datetime


def _without_prefix(value: str) -> str:
    return value.removeprefix("sha256:")


async def authenticate_service(
    request: Request,
    db: AsyncSession,
    authorization: str,
    timestamp: str,
    nonce: str,
    body_sha256: str,
    required_scope: str,
) -> bytes:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
    body = await request.body()
    if _without_prefix(body_sha256) != canonical_hash_bytes(body):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "body hash mismatch")
    try:
        verify_timestamp(timestamp, ttl_seconds=settings.signature_ttl_seconds)
        KeycloakValidator(
            issuer=settings.n8n_service_issuer,
            audience=settings.n8n_service_audience,
            jwks_url=settings.n8n_service_jwks_url,
            authorized_parties=frozenset({settings.n8n_service_client_id}),
            required_scopes=frozenset({required_scope}),
            required_environment="production",
            required_business_unit="BU-400-COD",
            required_campaign="CMP-400-COD",
        ).validate(authorization.removeprefix("Bearer ").strip())
    except (AutomationSecurityError, JWTAuthError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    if not nonce or len(nonce) > 128:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid nonce")
    key_id = settings.n8n_service_client_id
    if await db.get(PublisherNonce, (key_id, nonce)):
        raise HTTPException(status.HTTP_409_CONFLICT, "replayed request")
    db.add(
        PublisherNonce(
            key_id=key_id,
            nonce=nonce,
            signed_at=int(timestamp),
            expires_at=datetime.now(UTC)
            + timedelta(seconds=settings.signature_ttl_seconds),
        )
    )
    return body


def canonical_hash_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


@router.post("/executions")
@router.post("/executions/register", include_in_schema=False)
async def register_execution(
    request: Request,
    response: Response,
    authorization: Annotated[str, Header(alias="Authorization")],
    x_codestra_timestamp: Annotated[str, Header(alias="X-Codestra-Timestamp")],
    x_codestra_nonce: Annotated[str, Header(alias="X-Codestra-Nonce")],
    x_codestra_body_sha256: Annotated[str, Header(alias="X-Codestra-Body-SHA256")],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    raw = await authenticate_service(
        request,
        db,
        authorization,
        x_codestra_timestamp,
        x_codestra_nonce,
        x_codestra_body_sha256,
        "n8n.executions.register",
    )
    try:
        body = ExecutionRegistrationRequest.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(422, "invalid execution registration") from exc
    delivery = await db.get(BroadEventDelivery, body.delivery_id, with_for_update=True)
    event = await db.get(IntegrationEvent, delivery.event_id) if delivery else None
    if (
        delivery is None
        or event is None
        or event.original_event_id != body.event_id
        or delivery.workflow_id != body.workflow_key
        or delivery.workflow_version != body.workflow_version
        or delivery.payload_hash != _without_prefix(body.payload_hash)
        or delivery.target_environment != body.environment
        or delivery.policy_hash != _without_prefix(body.policy_hash)
        or delivery.attempt_number != body.attempt_number
        or body.registered_at < body.received_at
        or delivery.status not in {"SUBMITTED", "ACCEPTED", "EXECUTION_REGISTERED"}
    ):
        await db.rollback()
        raise HTTPException(409, "execution registration binding mismatch")
    prior = await db.scalar(
        select(N8nExecutionRegistration).where(
            (N8nExecutionRegistration.registration_id == body.registration_id)
            | (N8nExecutionRegistration.delivery_id == body.delivery_id)
        )
    )
    immutable = {
        "delivery_id": body.delivery_id,
        "event_id": body.event_id,
        "workflow_id": body.workflow_key,
        "workflow_version": body.workflow_version,
        "execution_id": body.execution_id,
        "payload_hash": _without_prefix(body.payload_hash),
        "request_hash": _without_prefix(body.request_hash),
    }
    if prior:
        if any(getattr(prior, key) != value for key, value in immutable.items()):
            await db.rollback()
            raise HTTPException(409, "execution registration conflict")
        response.status_code = status.HTTP_200_OK
        registration = prior
        idempotency_status = "DUPLICATE"
    else:
        registration = N8nExecutionRegistration(
            registration_id=body.registration_id,
            idempotency_key=body.idempotency_key,
            correlation_id=body.correlation_id,
            environment=body.environment,
            policy_hash=_without_prefix(body.policy_hash),
            attempt_number=body.attempt_number,
            received_at=body.received_at,
            registered_at=body.registered_at,
            status="REGISTERED",
            response_hash="0" * 64,
            **immutable,
        )
        db.add(registration)
        delivery.status = "EXECUTION_REGISTERED"
        delivery.response_received_at = datetime.now(UTC)
        response.status_code = status.HTTP_201_CREATED
        idempotency_status = "NEW"
    persisted_at = registration.registered_at
    result = {
        "schema_version": "1.0",
        "registration_id": str(registration.registration_id),
        "delivery_id": str(registration.delivery_id),
        "event_id": registration.event_id,
        "workflow_key": registration.workflow_id,
        "workflow_version": registration.workflow_version,
        "execution_id": registration.execution_id,
        "persisted": True,
        "idempotency_status": idempotency_status,
        "delivery_status": "EXECUTION_REGISTERED",
        "persisted_at": persisted_at.isoformat(),
    }
    result["response_hash"] = f"sha256:{canonical_hash(result)}"
    registration.response_hash = _without_prefix(str(result["response_hash"]))
    delivery.response_hash = registration.response_hash
    await db.commit()
    return result


@router.get("/executions/{registration_id}")
async def read_execution(
    registration_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    registration = await db.scalar(
        select(N8nExecutionRegistration).where(
            N8nExecutionRegistration.registration_id == registration_id
        )
    )
    if registration is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "execution not found")
    return _registration_response(registration)


@router.post("/executions/{registration_id}/transitions")
async def transition_execution(
    registration_id: UUID,
    request: Request,
    response: Response,
    authorization: Annotated[str, Header(alias="Authorization")],
    x_codestra_timestamp: Annotated[str, Header(alias="X-Codestra-Timestamp")],
    x_codestra_nonce: Annotated[str, Header(alias="X-Codestra-Nonce")],
    x_codestra_body_sha256: Annotated[str, Header(alias="X-Codestra-Body-SHA256")],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    raw = await authenticate_service(
        request,
        db,
        authorization,
        x_codestra_timestamp,
        x_codestra_nonce,
        x_codestra_body_sha256,
        "n8n.executions.transition",
    )
    try:
        body = ExecutionTransitionRequest.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(422, "invalid execution transition") from exc
    registration = await db.scalar(
        select(N8nExecutionRegistration)
        .where(N8nExecutionRegistration.registration_id == registration_id)
        .with_for_update()
    )
    if registration is None:
        await db.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "execution not found")
    if (
        registration.correlation_id != body.correlation_id
        or registration.attempt_number != body.attempt_number
    ):
        await db.rollback()
        raise HTTPException(409, "IMMUTABLE_BINDING_CONFLICT")
    prior = await db.scalar(
        select(N8nExecutionTransition).where(
            (N8nExecutionTransition.transition_id == body.transition_id)
            | (
                (N8nExecutionTransition.registration_id == registration_id)
                & (N8nExecutionTransition.to_status == body.state)
            )
        )
    )
    request_hash = canonical_hash(body.model_dump(mode="json"))
    if prior:
        if (
            prior.registration_id != registration_id
            or prior.to_status != body.state
            or prior.correlation_id != body.correlation_id
            or prior.attempt_number != body.attempt_number
            or prior.request_hash != request_hash
        ):
            await db.rollback()
            raise HTTPException(409, "IMMUTABLE_BINDING_CONFLICT")
        response.status_code = status.HTTP_200_OK
        transition = prior
        idempotency_status = "DUPLICATE"
    else:
        allowed = {
            "REGISTERED": {"RUNNING"},
            "RUNNING": {"SUCCEEDED", "FAILED", "DEAD_LETTERED"},
        }
        if body.state not in allowed.get(registration.status, set()):
            await db.rollback()
            raise HTTPException(409, "INVALID_EXECUTION_TRANSITION")
        transition = N8nExecutionTransition(
            transition_id=body.transition_id,
            registration_id=registration_id,
            from_status=registration.status,
            to_status=body.state,
            correlation_id=body.correlation_id,
            attempt_number=body.attempt_number,
            request_hash=request_hash,
            occurred_at=body.occurred_at,
        )
        db.add(transition)
        registration.status = body.state
        delivery = await db.get(
            BroadEventDelivery, registration.delivery_id, with_for_update=True
        )
        if delivery is None:
            await db.rollback()
            raise HTTPException(409, "IMMUTABLE_BINDING_CONFLICT")
        if body.state == "RUNNING":
            delivery.status = "RUNNING"
        response.status_code = status.HTTP_201_CREATED
        idempotency_status = "NEW"
    await db.commit()
    return {
        "schema_version": "1.0",
        "transition_id": str(transition.transition_id),
        "registration_id": str(transition.registration_id),
        "from_state": transition.from_status,
        "state": transition.to_status,
        "persisted": True,
        "idempotency_status": idempotency_status,
        "persisted_at": transition.persisted_at.isoformat(),
    }


@router.post("/acknowledgements")
async def acknowledge_execution(
    request: Request,
    response: Response,
    authorization: Annotated[str, Header(alias="Authorization")],
    x_codestra_timestamp: Annotated[str, Header(alias="X-Codestra-Timestamp")],
    x_codestra_nonce: Annotated[str, Header(alias="X-Codestra-Nonce")],
    x_codestra_body_sha256: Annotated[str, Header(alias="X-Codestra-Body-SHA256")],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    raw = await authenticate_service(
        request,
        db,
        authorization,
        x_codestra_timestamp,
        x_codestra_nonce,
        x_codestra_body_sha256,
        "n8n.executions.acknowledge",
    )
    try:
        body = AcknowledgementRequest.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(422, "invalid acknowledgement") from exc
    delivery = await db.get(BroadEventDelivery, body.delivery_id, with_for_update=True)
    registration = await db.scalar(
        select(N8nExecutionRegistration).where(
            N8nExecutionRegistration.registration_id == body.registration_id
        )
    )
    event = await db.get(IntegrationEvent, delivery.event_id) if delivery else None
    if (
        delivery is None
        or registration is None
        or event is None
        or registration.delivery_id != body.delivery_id
        or event.original_event_id != body.event_id
        or delivery.workflow_id != body.workflow_key
        or delivery.workflow_version != body.workflow_version
        or delivery.policy_hash != _without_prefix(body.policy_hash)
        or delivery.attempt_number != body.attempt_number
        or registration.execution_id != body.execution_id
        or registration.environment != delivery.target_environment
        or registration.payload_hash != delivery.payload_hash
        or registration.policy_hash != delivery.policy_hash
        or registration.correlation_id != body.correlation_id
        or body.completed_at < body.started_at
    ):
        await db.rollback()
        raise HTTPException(409, "acknowledgement binding mismatch")
    prior = await db.scalar(
        select(N8nAcknowledgement).where(
            (N8nAcknowledgement.acknowledgement_id == body.acknowledgement_id)
            | (N8nAcknowledgement.delivery_id == body.delivery_id)
        )
    )
    immutable = {
        "registration_id": body.registration_id,
        "delivery_id": body.delivery_id,
        "event_id": body.event_id,
        "workflow_id": body.workflow_key,
        "workflow_version": body.workflow_version,
        "execution_id": body.execution_id,
        "execution_status": body.execution_status,
        "result_classification": body.result_classification,
        "result_hash": _without_prefix(body.result_hash),
        "attempt_number": body.attempt_number,
        "correlation_id": body.correlation_id,
        "policy_hash": _without_prefix(body.policy_hash),
        "started_at": body.started_at,
        "completed_at": body.completed_at,
    }
    if prior:
        if any(getattr(prior, key) != value for key, value in immutable.items()):
            await db.rollback()
            raise HTTPException(409, "acknowledgement conflict")
        response.status_code = status.HTTP_200_OK
        acknowledgement = prior
        idempotency_status = "DUPLICATE"
    else:
        if delivery.status != "RUNNING" or registration.status not in {
            "RUNNING",
            body.execution_status,
        }:
            await db.rollback()
            raise HTTPException(409, "delivery is not execution registered")
        acknowledgement = N8nAcknowledgement(
            acknowledgement_id=body.acknowledgement_id,
            **immutable,
            metrics=body.metrics.model_dump(),
        )
        db.add(acknowledgement)
        registration.status = body.execution_status
        delivery.status = (
            "ACKNOWLEDGED"
            if body.execution_status == "SUCCEEDED"
            else "RECONCILIATION_REQUIRED"
        )
        delivery.acknowledged_at = datetime.now(UTC)
        result_payload = body.model_dump(mode="json")
        result_payload["originating_outbox_public_id"] = event.original_event_id
        result_payload["result_hash"] = body.result_hash
        result_payload["policy_hash"] = body.policy_hash
        outbox = OutboxEvent(
            topic="odoo.integration.result",
            payload=result_payload,
            correlation_id=body.correlation_id,
            status="pending",
            attempts=0,
        )
        db.add(outbox)
        await db.flush()
        db.add(
            OdooResultDelivery(
                acknowledgement_id=body.acknowledgement_id,
                originating_outbox_public_id=event.original_event_id,
                request_hash=canonical_hash(result_payload),
                status="PENDING",
            )
        )
        db.add(
            AuditEvent(
                action="n8n.acknowledgement.persisted",
                subject=body.event_id,
                correlation_id=body.correlation_id,
                decision=body.execution_status,
                redacted_payload={
                    "delivery_id": str(body.delivery_id),
                    "workflow_key": body.workflow_key,
                    "execution_id": body.execution_id,
                    "result_hash": body.result_hash,
                },
            )
        )
        response.status_code = status.HTTP_201_CREATED
        idempotency_status = "NEW"
    await db.commit()
    result = {
        "schema_version": "1.0",
        "acknowledgement_id": str(acknowledgement.acknowledgement_id),
        "delivery_id": str(acknowledgement.delivery_id),
        "event_id": acknowledgement.event_id,
        "persisted": True,
        "idempotency_status": idempotency_status,
        "final_delivery_status": delivery.status,
        "persisted_at": acknowledgement.persisted_at.isoformat(),
    }
    result["response_hash"] = f"sha256:{canonical_hash(result)}"
    return result


@router.get("/acknowledgements/{acknowledgement_id}")
async def read_acknowledgement(
    acknowledgement_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, object]:
    acknowledgement = await db.get(N8nAcknowledgement, acknowledgement_id)
    if acknowledgement is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "acknowledgement not found")
    return {
        "schema_version": "1.0",
        "acknowledgement_id": str(acknowledgement.acknowledgement_id),
        "registration_id": str(acknowledgement.registration_id),
        "delivery_id": str(acknowledgement.delivery_id),
        "event_id": acknowledgement.event_id,
        "workflow_key": acknowledgement.workflow_id,
        "workflow_version": acknowledgement.workflow_version,
        "execution_id": acknowledgement.execution_id,
        "execution_status": acknowledgement.execution_status,
        "result_hash": f"sha256:{acknowledgement.result_hash}",
        "correlation_id": acknowledgement.correlation_id,
        "policy_hash": f"sha256:{acknowledgement.policy_hash}",
        "attempt_number": acknowledgement.attempt_number,
        "persisted_at": acknowledgement.persisted_at.isoformat(),
    }


@router.get("/deliveries/{delivery_id}")
async def delivery_status(
    delivery_id: UUID, db: Annotated[AsyncSession, Depends(get_session)]
) -> dict[str, object]:
    delivery = await db.get(BroadEventDelivery, delivery_id)
    if delivery is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "delivery not found")
    registration = await db.scalar(
        select(N8nExecutionRegistration).where(
            N8nExecutionRegistration.delivery_id == delivery_id
        )
    )
    return {
        "delivery_id": str(delivery.delivery_id),
        "status": delivery.status,
        "registration_id": (
            str(registration.registration_id) if registration else None
        ),
        "execution_status": registration.status if registration else None,
    }


def _registration_response(
    registration: N8nExecutionRegistration,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "registration_id": str(registration.registration_id),
        "delivery_id": str(registration.delivery_id),
        "event_id": registration.event_id,
        "workflow_key": registration.workflow_id,
        "workflow_version": registration.workflow_version,
        "execution_id": registration.execution_id,
        "environment": registration.environment,
        "payload_hash": f"sha256:{registration.payload_hash}",
        "policy_hash": f"sha256:{registration.policy_hash}",
        "correlation_id": registration.correlation_id,
        "attempt_number": registration.attempt_number,
        "status": registration.status,
        "persisted": True,
        "registered_at": registration.registered_at.isoformat(),
    }
