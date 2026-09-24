"""Durable telephony command and operation journals.

POST creates a command only.  Dispatch remains an asynchronous, policy-gated
worker concern; the API never writes directly to telephony systems.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.telephony_commands import (
    TelephonyCommandRequest,
    new_command_record,
    payload_hash,
)
from app.db.models import (
    PolicyDecision,
    TelephonyCommandJournal,
    TelephonyOperationJournal,
    TelephonyOperationTransition,
    TelephonyReconciliationRun,
    TelephonyTerminalResult,
)
from app.db.session import get_session

router = APIRouter(prefix="/api/v1", tags=["commands"])


def _command_view(row: TelephonyCommandJournal, *, replayed: bool = False) -> dict:
    return {
        "command_id": str(row.command_id),
        "command_public_id": row.command_public_id,
        "command_type": row.command_type,
        "aggregate_public_id": row.aggregate_public_id,
        "aggregate_version": row.aggregate_version,
        "state": row.state,
        "correlation_id": row.correlation_id,
        "replayed": replayed,
    }


@router.post("/commands", status_code=202)
@router.post("/telephony/commands", status_code=202)
async def create_command(
    body: TelephonyCommandRequest,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    session: AsyncSession = Depends(get_session),
):
    if idempotency_key != body.idempotency_key:
        raise HTTPException(400, "header and command idempotency keys must match")
    decision = (
        await session.get(PolicyDecision, UUID(body.policy_decision_id))
        if body.policy_decision_id
        else await session.scalar(
            select(PolicyDecision)
            .where(PolicyDecision.correlation_id == body.correlation_id)
            .order_by(PolicyDecision.created_at.desc())
            .limit(1)
        )
    )
    if not decision:
        raise HTTPException(422, "policy decision not found")
    if body.policy_decision_id is None:
        body = body.model_copy(update={"policy_decision_id": str(decision.id)})
    values = new_command_record(body)
    existing = await session.scalar(
        select(TelephonyCommandJournal).where(
            TelephonyCommandJournal.idempotency_hash == values["idempotency_hash"]
        )
    )
    if existing:
        if existing.request_hash != values["request_hash"]:
            raise HTTPException(409, "idempotency key conflict")
        return _command_view(existing, replayed=True)
    if decision.correlation_id != body.correlation_id:
        raise HTTPException(409, "policy correlation mismatch")
    if payload_hash(decision.context) != body.policy_decision_hash:
        raise HTTPException(409, "policy decision hash mismatch")
    if decision.context.get("authorization_scope") != body.policy_scope():
        raise HTTPException(409, "policy authorization scope mismatch")
    expiration = decision.context.get("expiration")
    if not isinstance(expiration, str):
        raise HTTPException(409, "policy expiration is invalid")
    try:
        expires_at = datetime.fromisoformat(expiration)
    except (TypeError, ValueError):
        raise HTTPException(409, "policy expiration is invalid") from None
    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
        raise HTTPException(409, "policy decision expired")
    aggregate_lock_key = "\x1f".join(
        (body.environment, body.aggregate_type, body.aggregate_public_id)
    )
    await session.execute(
        select(func.pg_advisory_xact_lock(func.hashtextextended(aggregate_lock_key, 0)))
    )
    latest_version = await session.scalar(
        select(func.max(TelephonyCommandJournal.aggregate_version)).where(
            TelephonyCommandJournal.environment == body.environment,
            TelephonyCommandJournal.aggregate_type == body.aggregate_type,
            TelephonyCommandJournal.aggregate_public_id == body.aggregate_public_id,
        )
    )
    if latest_version is not None and body.aggregate_version <= latest_version:
        raise HTTPException(409, "stale or duplicate aggregate version")
    values["state"] = (
        "AUTHORIZED"
        if decision.allowed and decision.context.get("enforced") is True
        else "POLICY_DENIED"
    )
    row = TelephonyCommandJournal(**values)
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        existing = await session.scalar(
            select(TelephonyCommandJournal).where(
                TelephonyCommandJournal.idempotency_hash == values["idempotency_hash"]
            )
        )
        if not existing or existing.request_hash != values["request_hash"]:
            latest_version = await session.scalar(
                select(func.max(TelephonyCommandJournal.aggregate_version)).where(
                    TelephonyCommandJournal.environment == body.environment,
                    TelephonyCommandJournal.aggregate_type == body.aggregate_type,
                    TelephonyCommandJournal.aggregate_public_id
                    == body.aggregate_public_id,
                )
            )
            if latest_version is not None and body.aggregate_version <= latest_version:
                raise HTTPException(
                    409, "stale or duplicate aggregate version"
                ) from None
            raise HTTPException(409, "concurrent command conflict") from None
        return _command_view(existing, replayed=True)
    return _command_view(row)


@router.get("/commands/{command_public_id}")
@router.get("/telephony/commands/{command_public_id}")
async def get_command(
    command_public_id: str, session: AsyncSession = Depends(get_session)
):
    row = await session.scalar(
        select(TelephonyCommandJournal).where(
            TelephonyCommandJournal.command_public_id == command_public_id
        )
    )
    if not row:
        raise HTTPException(404, "command not found")
    return _command_view(row)


@router.post("/telephony/commands/{command_public_id}/cancel")
async def cancel_command(
    command_public_id: str, session: AsyncSession = Depends(get_session)
):
    row = await session.scalar(
        select(TelephonyCommandJournal)
        .where(TelephonyCommandJournal.command_public_id == command_public_id)
        .with_for_update()
    )
    if not row:
        raise HTTPException(404, "command not found")
    if row.state in {"SUCCEEDED", "RECONCILED", "FAILED_PERMANENT"}:
        raise HTTPException(409, "terminal command cannot be cancelled")
    row.state = "CANCELLED"
    row.lease_owner = None
    row.next_attempt_at = None
    row.updated_at = datetime.now(UTC)
    await session.commit()
    return _command_view(row)


class OperationRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    operation_public_id: str = Field(min_length=4, max_length=144)
    command_public_id: str = Field(min_length=4, max_length=144)
    adapter_service_key: str = Field(min_length=1, max_length=144)
    adapter_operation_id: str = Field(min_length=1, max_length=144)
    target_system: Literal["ASTERISK", "VICIDIAL"]
    target_resource_type: str = Field(min_length=1, max_length=32)
    target_public_id: str = Field(min_length=4, max_length=144)
    desired_state_version: int = Field(ge=1)
    desired_state_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=128)
    registered_at: datetime


@router.post("/telephony/operations", status_code=202)
async def register_operation(
    body: OperationRegistration,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    command = await session.scalar(
        select(TelephonyCommandJournal)
        .where(TelephonyCommandJournal.command_public_id == body.command_public_id)
        .with_for_update()
    )
    if not command:
        raise HTTPException(404, "command not found")
    if (
        command.correlation_id != body.correlation_id
        or command.payload_json.get("desired_state_version")
        != body.desired_state_version
        or str(command.payload_json.get("desired_state_hash", "")).removeprefix(
            "sha256:"
        )
        not in {"", body.desired_state_hash.removeprefix("sha256:")}
    ):
        raise HTTPException(409, "operation correlation binding mismatch")
    prior = await session.scalar(
        select(TelephonyOperationJournal).where(
            (TelephonyOperationJournal.operation_public_id == body.operation_public_id)
            | (TelephonyOperationJournal.command_id == command.command_id)
            | (
                TelephonyOperationJournal.idempotency_hash
                == payload_hash(body.idempotency_key)
            )
        )
    )
    immutable = {
        "operation_public_id": body.operation_public_id,
        "adapter_service_key": body.adapter_service_key,
        "adapter_operation_id": body.adapter_operation_id,
        "target_system": body.target_system,
        "target_resource_type": body.target_resource_type,
        "target_public_id": body.target_public_id,
        "desired_state_version": body.desired_state_version,
        "desired_hash": body.desired_state_hash.removeprefix("sha256:"),
        "correlation_id": body.correlation_id,
    }
    if prior:
        if any(getattr(prior, key) != value for key, value in immutable.items()):
            raise HTTPException(409, "immutable operation binding conflict")
        response.status_code = status.HTTP_200_OK
        return {
            "operation_public_id": prior.operation_public_id,
            "idempotency_status": "DUPLICATE",
        }
    row = TelephonyOperationJournal(
        **immutable,
        command_id=command.command_id,
        state="REGISTERED",
        endpoint_key="telephony.operation.registered",
        readback_endpoint_key="telephony.operation.readback",
        target_configuration_checksum="pending",
        target_attested=True,
        idempotency_hash=payload_hash(body.idempotency_key),
        response_json={},
    )
    session.add(row)
    command.state = "OPERATION_REGISTERED"
    command.updated_at = datetime.now(UTC)
    await session.commit()
    response.status_code = status.HTTP_201_CREATED
    return {"operation_public_id": row.operation_public_id, "idempotency_status": "NEW"}


@router.get("/telephony/operations/{operation_public_id}")
async def get_operation(
    operation_public_id: str, session: AsyncSession = Depends(get_session)
):
    row = await session.scalar(
        select(TelephonyOperationJournal).where(
            TelephonyOperationJournal.operation_public_id == operation_public_id
        )
    )
    if not row:
        raise HTTPException(404, "operation not found")
    return {
        "operation_public_id": row.operation_public_id,
        "command_id": str(row.command_id),
        "state": row.state,
        "endpoint_key": row.endpoint_key,
        "readback_endpoint_key": row.readback_endpoint_key,
        "target_attested": row.target_attested,
        "desired_hash": row.desired_hash,
        "actual_hash": row.actual_hash,
        "readback_matches": row.readback_matches,
        "correlation_id": row.correlation_id,
        "completed_at": row.completed_at,
    }


class OperationTransition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    command_public_id: str = Field(min_length=4, max_length=144)
    state: Literal[
        "REGISTERED",
        "APPLYING",
        "APPLIED",
        "READBACK_PENDING",
        "READBACK_VERIFIED",
        "READBACK_MISMATCH",
        "SUCCEEDED",
        "FAILED",
        "COMPENSATION_REQUIRED",
        "COMPENSATED",
    ]
    target_system: Literal["ASTERISK", "VICIDIAL"]
    target_resource_type: str = Field(min_length=1, max_length=32)
    target_public_id: str = Field(min_length=4, max_length=144)
    desired_state_version: int = Field(ge=1)
    adapter_service_key: str = Field(min_length=1, max_length=144)
    environment: Literal["staging", "test", "production"]
    correlation_id: str = Field(min_length=1, max_length=128)
    transition_sequence: int = Field(ge=1)
    transition_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    occurred_at: datetime


_TRANSITIONS = {
    "REGISTERED": {"APPLYING", "FAILED"},
    "APPLYING": {"APPLIED", "FAILED", "COMPENSATION_REQUIRED"},
    "APPLIED": {"READBACK_PENDING", "COMPENSATION_REQUIRED"},
    "READBACK_PENDING": {"READBACK_VERIFIED", "READBACK_MISMATCH", "FAILED"},
    "READBACK_VERIFIED": {"SUCCEEDED"},
    "READBACK_MISMATCH": {"COMPENSATION_REQUIRED", "FAILED"},
    "COMPENSATION_REQUIRED": {"COMPENSATED", "FAILED"},
}


@router.post("/telephony/operations/{operation_public_id}/transitions")
async def transition_operation(
    operation_public_id: str,
    body: OperationTransition,
    session: AsyncSession = Depends(get_session),
):
    row = await session.scalar(
        select(TelephonyOperationJournal)
        .where(TelephonyOperationJournal.operation_public_id == operation_public_id)
        .with_for_update()
    )
    if not row:
        raise HTTPException(404, "operation not found")
    command = await session.get(TelephonyCommandJournal, row.command_id)
    binding = body.model_dump(mode="json", exclude={"transition_hash"})
    expected_hash = payload_hash(binding)
    if (
        not command
        or command.command_public_id != body.command_public_id
        or command.environment != body.environment
        or row.correlation_id != body.correlation_id
        or row.target_system != body.target_system
        or row.target_resource_type != body.target_resource_type
        or row.target_public_id != body.target_public_id
        or row.desired_state_version != body.desired_state_version
        or row.adapter_service_key != body.adapter_service_key
        or expected_hash != body.transition_hash.removeprefix("sha256:")
    ):
        raise HTTPException(409, "operation transition binding mismatch")
    prior = await session.scalar(
        select(TelephonyOperationTransition).where(
            TelephonyOperationTransition.operation_id == row.operation_id,
            (TelephonyOperationTransition.sequence == body.transition_sequence)
            | (
                TelephonyOperationTransition.transition_hash
                == body.transition_hash.removeprefix("sha256:")
            ),
        )
    )
    if prior:
        if prior.binding_json != binding:
            raise HTTPException(409, "conflicting operation transition")
        return {
            "operation_public_id": row.operation_public_id,
            "state": prior.to_state,
            "idempotency_status": "DUPLICATE",
        }
    if body.transition_sequence != row.transition_sequence + 1:
        raise HTTPException(409, "out-of-order operation transition")
    if body.state not in _TRANSITIONS.get(row.state, set()):
        raise HTTPException(409, "invalid operation transition")
    session.add(
        TelephonyOperationTransition(
            operation_id=row.operation_id,
            command_id=row.command_id,
            sequence=body.transition_sequence,
            from_state=row.state,
            to_state=body.state,
            transition_hash=body.transition_hash.removeprefix("sha256:"),
            binding_json=binding,
            occurred_at=body.occurred_at,
        )
    )
    row.state = body.state
    row.transition_sequence = body.transition_sequence
    if body.state in {"SUCCEEDED", "FAILED", "COMPENSATED"}:
        row.completed_at = datetime.now(UTC)
    await session.commit()
    return {
        "operation_public_id": row.operation_public_id,
        "state": row.state,
        "idempotency_status": "NEW",
    }


class TerminalResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    result_public_id: str = Field(min_length=4, max_length=144)
    operation_public_id: str = Field(min_length=4, max_length=144)
    command_public_id: str = Field(min_length=4, max_length=144)
    target_system: Literal["ASTERISK", "VICIDIAL"]
    target_resource_type: str = Field(min_length=1, max_length=32)
    target_public_id: str = Field(min_length=4, max_length=144)
    application_status: Literal["APPLIED", "FAILED", "STALE"]
    readback_status: Literal["READBACK_VERIFIED", "READBACK_MISMATCH", "FAILED"]
    requested_state_version: int = Field(ge=1)
    applied_state_version: int = Field(ge=1)
    observed_state_version: int = Field(ge=1)
    result_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    application_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    readback_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    adapter_service_key: str = Field(min_length=1, max_length=144)
    adapter_configuration_checksum: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    applied_at: datetime
    readback_at: datetime
    safe_summary: str = Field(min_length=1, max_length=512)
    policy_hash: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    correlation_id: str = Field(min_length=1, max_length=128)


def _result_view(row: TelephonyTerminalResult, duplicate: bool = False) -> dict:
    return {
        "result_public_id": row.result_public_id,
        "operation_public_id": row.immutable_json["operation_public_id"],
        "command_public_id": row.immutable_json["command_public_id"],
        "application_status": row.application_status,
        "readback_status": row.readback_status,
        "reconciliation_status": row.reconciliation_status,
        "correlation_id": row.correlation_id,
        "idempotency_status": "DUPLICATE" if duplicate else "NEW",
    }


@router.post("/telephony/results", status_code=202)
async def create_terminal_result(
    body: TerminalResultRequest, session: AsyncSession = Depends(get_session)
):
    immutable = body.model_dump(mode="json")
    prior = await session.scalar(
        select(TelephonyTerminalResult).where(
            (TelephonyTerminalResult.result_public_id == body.result_public_id)
        )
    )
    if prior:
        if prior.immutable_json != immutable:
            raise HTTPException(409, "IMMUTABLE_RESULT_BINDING_CONFLICT")
        return _result_view(prior, duplicate=True)
    operation = await session.scalar(
        select(TelephonyOperationJournal)
        .where(
            TelephonyOperationJournal.operation_public_id == body.operation_public_id
        )
        .with_for_update()
    )
    command = await session.scalar(
        select(TelephonyCommandJournal).where(
            TelephonyCommandJournal.command_public_id == body.command_public_id
        )
    )
    if (
        not operation
        or not command
        or operation.command_id != command.command_id
        or command.correlation_id != body.correlation_id
        or command.policy_decision_hash != body.policy_hash.removeprefix("sha256:")
        or operation.target_system != body.target_system
        or operation.target_resource_type != body.target_resource_type
        or operation.target_public_id != body.target_public_id
        or operation.desired_state_version != body.requested_state_version
        or operation.adapter_service_key != body.adapter_service_key
    ):
        raise HTTPException(409, "terminal result binding mismatch")
    row = TelephonyTerminalResult(
        result_public_id=body.result_public_id,
        operation_id=operation.operation_id,
        command_id=command.command_id,
        result_hash=body.result_hash.removeprefix("sha256:"),
        application_hash=body.application_hash.removeprefix("sha256:"),
        readback_hash=body.readback_hash.removeprefix("sha256:"),
        policy_hash=body.policy_hash.removeprefix("sha256:"),
        target_system=body.target_system,
        target_resource_type=body.target_resource_type,
        target_public_id=body.target_public_id,
        requested_state_version=body.requested_state_version,
        applied_state_version=body.applied_state_version,
        observed_state_version=body.observed_state_version,
        application_status=body.application_status,
        readback_status=body.readback_status,
        adapter_service_key=body.adapter_service_key,
        adapter_configuration_checksum=body.adapter_configuration_checksum,
        safe_summary=body.safe_summary,
        applied_at=body.applied_at,
        readback_at=body.readback_at,
        status=body.application_status,
        reconciliation_status=(
            "IN_SYNC"
            if body.readback_status == "READBACK_VERIFIED"
            else "RECONCILIATION_REQUIRED"
        ),
        correlation_id=body.correlation_id,
        immutable_json=immutable,
    )
    session.add(row)
    operation.state = (
        "ODOO_RESULT_PENDING"
        if body.readback_status == "READBACK_VERIFIED"
        else "READBACK_MISMATCH"
    )
    await session.commit()
    return _result_view(row)


@router.get("/telephony/results/{result_public_id}")
async def get_terminal_result(
    result_public_id: str, session: AsyncSession = Depends(get_session)
):
    row = await session.scalar(
        select(TelephonyTerminalResult).where(
            TelephonyTerminalResult.result_public_id == result_public_id
        )
    )
    if not row:
        raise HTTPException(404, "result not found")
    return _result_view(row)


class ReconciliationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_public_id: str = Field(
        default_factory=lambda: f"REC-{uuid4().hex}", min_length=4, max_length=144
    )
    command_public_id: str | None = Field(default=None, max_length=144)
    environment: Literal["staging", "test", "production"]
    aggregate_type: str = Field(min_length=1, max_length=64)
    aggregate_public_id: str = Field(min_length=1, max_length=144)
    target_system: Literal["VICIDIAL", "ASTERISK"]
    classification: str = Field(min_length=1, max_length=64)
    correlation_id: str = Field(min_length=1, max_length=128)
    evidence: dict = Field(default_factory=dict)


@router.post("/telephony/reconciliation/runs", status_code=202)
async def create_reconciliation_run(
    body: ReconciliationRunRequest, session: AsyncSession = Depends(get_session)
):
    prior = await session.scalar(
        select(TelephonyReconciliationRun).where(
            TelephonyReconciliationRun.run_public_id == body.run_public_id
        )
    )
    if prior:
        return {
            "run_public_id": prior.run_public_id,
            "status": prior.status,
            "idempotency_status": "DUPLICATE",
        }
    command_id = None
    if body.command_public_id:
        command = await session.scalar(
            select(TelephonyCommandJournal).where(
                TelephonyCommandJournal.command_public_id == body.command_public_id
            )
        )
        if not command:
            raise HTTPException(404, "command not found")
        command_id = command.command_id
    row = TelephonyReconciliationRun(
        run_public_id=body.run_public_id,
        command_id=command_id,
        environment=body.environment,
        aggregate_type=body.aggregate_type,
        aggregate_public_id=body.aggregate_public_id,
        target_system=body.target_system,
        status="REQUESTED",
        classification=body.classification,
        correlation_id=body.correlation_id,
        evidence_json=body.evidence,
    )
    session.add(row)
    await session.commit()
    return {
        "run_public_id": row.run_public_id,
        "status": row.status,
        "idempotency_status": "NEW",
    }


@router.get("/telephony/reconciliation/runs/{run_public_id}")
async def get_reconciliation_run(
    run_public_id: str, session: AsyncSession = Depends(get_session)
):
    row = await session.scalar(
        select(TelephonyReconciliationRun).where(
            TelephonyReconciliationRun.run_public_id == run_public_id
        )
    )
    if not row:
        raise HTTPException(404, "reconciliation run not found")
    return {
        "run_public_id": row.run_public_id,
        "status": row.status,
        "classification": row.classification,
        "correlation_id": row.correlation_id,
    }
