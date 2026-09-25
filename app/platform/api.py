"""The canonical V3 kernel surface: six routes under ``/platform/v1``.

Served by every application profile through the router registry, so the
deployed integration API (8095) exposes them behind Kong. Every handler
verifies the Keycloak JWT (issuer, audience, azp, scope) as its first
statement, derives the principal from verified claims only, re-authorizes
the tenant, and delegates to the one command kernel. Domain errors are
rendered by the registry's error envelope (``error.code`` / ``message`` /
``correlation_id`` / ``retryable`` / ``details``).

Scopes: ``platform.command`` (submit, cancel), ``platform.command.read``
(operation, timeline, describe), ``platform.command.replay`` + role
``platform-operator`` (replay).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api_inputs import optional_header, required_header
from app.db.session import get_session
from app.commands import API_OPERATION_STATES, CommandCapabilityDisabled, CommandEnvelope, CommandNotFound, CommandOperation, OperationEvent, redact_metadata
from app.platform.adapter import AdapterContext
from app.platform.kernel import SCOPE_COMMAND, SCOPE_COMMAND_READ, SCOPE_COMMAND_REPLAY
from app.platform.principal import KernelPrincipal, authenticate
from app.platform.resilience import ReplayMode
from app.security import AuthorizationError, RequestValidationError
from app.storage import RUNTIME_SCHEMA_VERSION, StorageError
from app.workers.dead_letter import get_dead_letter, list_dead_letters, redrive_dead_letter
from app.workers.reconciliation import get_reconciliation_status, reconcile_internal_outbox

router = APIRouter(prefix="/platform/v1", tags=["platform-command-kernel"])

COMMAND_CONTRACT_VERSION = "command-envelope.v1"
_SAFE_ERROR_CODE = re.compile(r"[^a-z0-9_.:-]+")
TRACE_HEADERS = ("traceparent", "tracestate")


class KernelCommandRequest(BaseModel):
    """The public, provider-blind submit body.

    Same fields and bounds as the durable :class:`~app.commands.CommandEnvelope`;
    ``target`` (the connector id) and ``capability`` may be omitted — the
    command registry binds both to the command family — and must match the
    registry when supplied. Authentication-derived fields (tenant, actor) are
    verified against the token, never trusted from the body.
    """

    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    command_type: str = Field(pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$", max_length=180)
    command_version: Literal["1.0"] = "1.0"
    target: str | None = Field(default=None, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)
    tenant_id: str = Field(min_length=1, max_length=128)
    requested_by: str = Field(min_length=1, max_length=300)
    correlation_id: str = Field(min_length=1, max_length=180)
    idempotency_key: str = Field(min_length=8, max_length=180)
    capability: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{2,100}$")
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return CommandEnvelope.bound_payload(value)

    def envelope(self, *, target: str, capability: str) -> CommandEnvelope:
        return CommandEnvelope(
            command_id=self.command_id,
            command_type=self.command_type,
            command_version=self.command_version,
            target=target,
            tenant_id=self.tenant_id,
            requested_by=self.requested_by,
            correlation_id=self.correlation_id,
            idempotency_key=self.idempotency_key,
            capability=capability,
            payload=self.payload,
        )


class OperationAccepted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    command_id: UUID
    state: str
    correlation_id: str
    duplicate: bool


class OperationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    command_id: UUID
    tenant_id: str
    command_type: str
    target: str
    capability: str
    state: str
    resource_version: int
    correlation_id: str
    created_at: datetime
    updated_at: datetime
    provider_operation_id: str | None = None
    readback_status: str | None = None
    readback_evidence_sha256: str | None = None
    error_code: str | None = None
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = None
    reconciliation: dict[str, Any] | None = None


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: int
    operation_id: UUID
    event_type: str
    previous_state: str | None
    new_state: str
    actor_id: str
    reason: str
    correlation_id: str
    causation_id: int | None
    attempt: int
    safe_metadata: dict[str, Any]
    created_at: datetime


class Timeline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    items: list[TimelineEvent]


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$")


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["REPROCESS", "REEXECUTE"]
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$")
    new_idempotency_key: str | None = Field(default=None, min_length=8, max_length=180)


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    platform = getattr(runtime, "platform", None)
    if runtime is None or platform is None or runtime.commands is None:
        raise StorageError("command kernel is unavailable")
    return runtime, platform


def _tenant_for_read(request: Request, principal: KernelPrincipal) -> str:
    header = optional_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    if header is not None:
        if not principal.authorized_for(header):
            raise AuthorizationError("token is not authorized for the requested tenant")
        return header
    if len(principal.tenants) != 1:
        raise RequestValidationError("X-Tenant-ID is required for a multi-tenant principal")
    return principal.tenants[0]


def _error_code(operation: CommandOperation) -> str | None:
    if operation.last_error is None or operation.state not in {"failed", "reconciliation_required", "dead_lettered"}:
        return None
    head = operation.last_error.strip().split(" ", 1)[0].lower()[:64]
    return _SAFE_ERROR_CODE.sub("_", head) or None


def _readback_status(operation: CommandOperation) -> str | None:
    evidence = operation.readback_evidence
    if isinstance(evidence, dict):
        status = evidence.get("status")
        if isinstance(status, str):
            return status.upper()[:32]
    return None


def _status(operation: CommandOperation) -> OperationStatus:
    reconciliation = None
    if operation.reconciliation_requested_at is not None or operation.state == "reconciliation_required":
        reconciliation = {
            "requested_at": operation.reconciliation_requested_at.isoformat() if operation.reconciliation_requested_at else None,
            "reason": _SAFE_ERROR_CODE.sub("_", (operation.reconciliation_reason or "").lower()[:64]) or None,
            "status": "pending" if operation.state == "reconciliation_required" else "resolved",
        }
    return OperationStatus(
        operation_id=operation.command_id,
        command_id=operation.command_id,
        tenant_id=operation.tenant_id,
        command_type=operation.command_type,
        target=operation.target,
        capability=operation.capability,
        state=API_OPERATION_STATES[operation.state],
        resource_version=operation.resource_version,
        correlation_id=operation.correlation_id,
        created_at=operation.created_at,
        updated_at=operation.updated_at,
        provider_operation_id=operation.provider_operation_id,
        readback_status=_readback_status(operation),
        readback_evidence_sha256=operation.readback_evidence_sha256,
        error_code=_error_code(operation),
        cancelled_at=operation.cancelled_at,
        cancellation_reason=operation.cancellation_reason,
        reconciliation=reconciliation,
    )


def _event_type(event: OperationEvent) -> str:
    metadata = event.safe_metadata or {}
    if event.previous_state is None:
        return "operation.accepted"
    if "reconciliation_status" in metadata:
        return "operation.reconciliation"
    if "action" in metadata:
        return f"operation.mutation.{metadata['action']}"
    if "replay_mode" in metadata:
        return "operation.replay"
    return "operation.transition"


def _timeline(operation: CommandOperation, events: list[OperationEvent]) -> list[TimelineEvent]:
    """Stable, append-only ordering; ``causation_id`` is the preceding event,
    ``attempt`` counts the dispatch attempts opened so far."""
    rows: list[TimelineEvent] = []
    attempt = 0
    previous_id: int | None = None
    for event in events:
        if event.new_state == "dispatching":
            attempt += 1
        rows.append(
            TimelineEvent(
                event_id=event.event_id,
                operation_id=event.operation_id,
                event_type=_event_type(event),
                previous_state=API_OPERATION_STATES.get(event.previous_state, event.previous_state) if event.previous_state else None,
                new_state=API_OPERATION_STATES.get(event.new_state, event.new_state),
                actor_id=event.actor_id,
                reason=event.reason,
                correlation_id=operation.correlation_id,
                causation_id=previous_id,
                attempt=attempt,
                safe_metadata=redact_metadata(event.safe_metadata),
                created_at=event.created_at,
            )
        )
        previous_id = event.event_id
    return rows


def _respond(status_code: int, model: BaseModel, *, correlation_id: str, location: str | None = None) -> JSONResponse:
    headers = {"X-Correlation-ID": correlation_id}
    if location:
        headers["Location"] = location
    return JSONResponse(status_code=status_code, content=model.model_dump(mode="json"), headers=headers)


def _trace(request: Request) -> dict[str, str]:
    trace: dict[str, str] = {}
    for name in TRACE_HEADERS:
        value = optional_header(request, name, minimum=1, maximum=512)
        if value is not None:
            trace[name] = value
    return trace


# ----------------------------------------------------------------------
# POST /platform/v1/commands
# ----------------------------------------------------------------------
@router.post(
    "/commands",
    status_code=202,
    response_model=OperationAccepted,
    responses={200: {"model": OperationAccepted, "description": "Exact replay of an existing operation"}, 202: {"model": OperationAccepted, "description": "Command accepted"}},
)
async def submit_command(body: KernelCommandRequest, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND)
    runtime, platform = _runtime(request)
    # Provider-blind body: the registry binds the command family to its
    # connector and capability; a supplied value must agree with the registry.
    policy = runtime.commands.policies.resolve(body.command_type)
    if policy is None:
        raise CommandCapabilityDisabled("command type does not have exactly one owning policy")
    if body.target is not None and body.target != policy.target:
        raise CommandCapabilityDisabled("command target does not own the command type")
    if body.capability is not None and body.capability != policy.capability:
        raise CommandCapabilityDisabled("command capability does not match the owning policy")
    command = body.envelope(target=policy.target, capability=policy.capability)
    # Authentication-derived facts are never trusted from the body.
    if not principal.authorized_for(command.tenant_id):
        raise AuthorizationError("token is not authorized for the command tenant")
    tenant_header = optional_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    if tenant_header is not None and tenant_header != command.tenant_id:
        raise RequestValidationError("X-Tenant-ID does not match command tenant")
    correlation_id = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    if correlation_id != command.correlation_id:
        raise RequestValidationError("X-Correlation-ID does not match command correlation_id")
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    if idempotency_key != command.idempotency_key:
        raise RequestValidationError("Idempotency-Key does not match command idempotency_key")
    if command.requested_by != principal.subject:
        raise AuthorizationError("requested_by must equal the authenticated token subject")
    request.state.trace_context = _trace(request)

    result = await platform.kernel.submit(command, principal, trace=request.state.trace_context)
    operation = result.operation
    accepted = OperationAccepted(
        operation_id=operation.command_id,
        command_id=operation.command_id,
        state=API_OPERATION_STATES[operation.state],
        correlation_id=operation.correlation_id,
        duplicate=operation.duplicate,
    )
    return _respond(
        200 if operation.duplicate else 202,
        accepted,
        correlation_id=operation.correlation_id,
        location=f"/platform/v1/operations/{operation.command_id}",
    )


# ----------------------------------------------------------------------
# GET /platform/v1/operations/{operation_id}
# ----------------------------------------------------------------------
@router.get("/operations/{operation_id}", response_model=OperationStatus)
async def get_operation(operation_id: UUID, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    operation = await platform.kernel.get(tenant_id, operation_id)
    return _respond(200, _status(operation), correlation_id=operation.correlation_id)


# ----------------------------------------------------------------------
# GET /platform/v1/operations/{operation_id}/timeline
# ----------------------------------------------------------------------
@router.get("/operations/{operation_id}/timeline", response_model=Timeline)
async def get_timeline(operation_id: UUID, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    operation = await platform.kernel.get(tenant_id, operation_id)
    events = await platform.kernel.timeline(tenant_id, operation_id)
    return _respond(200, Timeline(operation_id=operation_id, items=_timeline(operation, events)), correlation_id=operation.correlation_id)


# ----------------------------------------------------------------------
# POST /platform/v1/operations/{operation_id}/cancel
# ----------------------------------------------------------------------
@router.post("/operations/{operation_id}/cancel", response_model=OperationStatus)
async def cancel_operation(operation_id: UUID, body: CancelRequest, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    operation = await platform.kernel.cancel(
        tenant_id,
        operation_id,
        principal=principal,
        idempotency_key=idempotency_key,
        expected_version=body.expected_version,
        reason=body.reason,
    )
    return _respond(200, _status(operation), correlation_id=operation.correlation_id)


# ----------------------------------------------------------------------
# POST /platform/v1/operations/{operation_id}/replay
# ----------------------------------------------------------------------
@router.post("/operations/{operation_id}/replay", response_model=OperationStatus, status_code=202)
async def replay_operation(operation_id: UUID, body: ReplayRequest, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_REPLAY)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    operation = await platform.kernel.replay(
        tenant_id,
        operation_id,
        principal=principal,
        mode=ReplayMode(body.mode),
        idempotency_key=idempotency_key,
        expected_version=body.expected_version,
        reason=body.reason,
        new_idempotency_key=body.new_idempotency_key,
    )
    return _respond(
        202,
        _status(operation),
        correlation_id=operation.correlation_id,
        location=f"/platform/v1/operations/{operation.command_id}",
    )



class RetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$")
    new_idempotency_key: str | None = Field(default=None, min_length=8, max_length=180)


class CommandResultView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    state: Literal["pending", "available", "failed", "partial", "unknown"]
    result_available: bool
    correlation_id: str
    provider_operation_id: str | None = None
    safe_result: dict[str, Any] | None = None
    reconciliation_required: bool = False
    error_code: str | None = None


def _bind_command_header(request: Request, command_id: UUID) -> None:
    header = optional_header(request, "X-Command-ID", minimum=1, maximum=180)
    if header is not None and header != str(command_id):
        raise RequestValidationError("X-Command-ID does not match path command identity")


def _result_view(operation: CommandOperation) -> CommandResultView:
    state = API_OPERATION_STATES.get(operation.state, operation.state)
    evidence = redact_metadata(operation.readback_evidence or {})
    if state in {"succeeded", "completed"}:
        result_state: Literal["pending", "available", "failed", "partial", "unknown"] = "available"
    elif state in {"failed", "dead_lettered", "cancelled"}:
        result_state = "failed"
    elif state == "reconciliation_required":
        result_state = "unknown"
    elif evidence:
        result_state = "partial"
    else:
        result_state = "pending"
    return CommandResultView(
        command_id=operation.command_id,
        state=result_state,
        result_available=bool(evidence) or result_state == "available",
        correlation_id=operation.correlation_id,
        provider_operation_id=operation.provider_operation_id,
        safe_result=evidence or None,
        reconciliation_required=state == "reconciliation_required",
        error_code=_error_code(operation),
    )


@router.get("/commands/{command_id}", response_model=OperationStatus)
async def get_command(command_id: UUID, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    return await get_operation(command_id, request)


@router.get("/commands/{command_id}/history", response_model=Timeline)
async def get_command_history(command_id: UUID, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    return await get_timeline(command_id, request)


@router.get("/commands/{command_id}/result", response_model=CommandResultView)
async def get_command_result(command_id: UUID, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    _, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    operation = await platform.kernel.get(tenant_id, command_id)
    return _respond(200, _result_view(operation), correlation_id=operation.correlation_id)


@router.post("/commands/{command_id}/cancel", response_model=OperationStatus)
async def cancel_command(command_id: UUID, body: CancelRequest, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    return await cancel_operation(command_id, body, request)


@router.post("/commands/{command_id}/replay", response_model=OperationStatus, status_code=202)
async def replay_command(command_id: UUID, body: ReplayRequest, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    return await replay_operation(command_id, body, request)


@router.post("/commands/{command_id}/retry", response_model=OperationStatus, status_code=202)
async def retry_command(command_id: UUID, body: RetryRequest, request: Request) -> JSONResponse:
    _bind_command_header(request, command_id)
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_REPLAY)
    _, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    idempotency_key = required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    operation = await platform.kernel.replay(
        tenant_id,
        command_id,
        principal=principal,
        mode=ReplayMode.REPROCESS,
        idempotency_key=idempotency_key,
        expected_version=body.expected_version,
        reason=body.reason,
        new_idempotency_key=body.new_idempotency_key,
    )
    return _respond(
        202,
        _status(operation),
        correlation_id=operation.correlation_id,
        location=f"/platform/v1/commands/{operation.command_id}",
    )



@router.get("/commands")
async def list_commands(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    status: str | None = Query(default=None, max_length=64),
    operation: str | None = Query(default=None, max_length=180),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, _ = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    rows = await runtime.commands.list_operations(
        tenant_id,
        limit=limit,
        state=status,
        command_type=operation,
    )
    items = [_status(row).model_dump(mode="json") for row in rows]
    return JSONResponse(
        status_code=200,
        content={
            "items": items,
            "limit": limit,
            "count": len(items),
            "request_id": getattr(request.state, "request_id", None),
            "correlation_id": getattr(request.state, "correlation_id", None),
        },
    )



class DeadLetterRedriveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=500, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]*$")


class ReconciliationScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=100, ge=1, le=1000)
    dry_run: Literal[True] = True


def _require_operator(principal: KernelPrincipal) -> None:
    if "platform-operator" not in principal.roles:
        raise AuthorizationError("platform-operator role is required")


@router.get("/dead-letters")
async def canonical_dead_letters(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    tenant_id = _tenant_for_read(request, principal)
    items = await list_dead_letters(db, limit, tenant_id=tenant_id)
    return JSONResponse(
        status_code=200,
        content={
            "items": jsonable_encoder(items),
            "count": len(items),
            "limit": limit,
            "tenant_id": tenant_id,
        },
    )


@router.get("/dead-letters/{item_id}")
async def canonical_dead_letter(
    item_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    tenant_id = _tenant_for_read(request, principal)
    item = await get_dead_letter(db, item_id, tenant_id=tenant_id)
    if item is None:
        raise CommandNotFound("dead letter not found")
    return JSONResponse(status_code=200, content=jsonable_encoder(item))


@router.post("/dead-letters/{item_id}/redrive", status_code=202)
async def canonical_redrive_dead_letter(
    item_id: UUID,
    body: DeadLetterRedriveRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_REPLAY)
    _require_operator(principal)
    tenant_id = _tenant_for_read(request, principal)
    required_header(request, "Idempotency-Key", minimum=8, maximum=180)
    result = await redrive_dead_letter(db, item_id, tenant_id=tenant_id)
    if result is None:
        raise CommandNotFound("dead letter not found or not redriveable")
    return JSONResponse(
        status_code=202,
        content={
            **result,
            "status": "pending",
            "tenant_id": tenant_id,
            "reason": body.reason,
        },
        headers={"Location": f"/platform/v1/dead-letters/{item_id}"},
    )


@router.post("/reconciliation/scan", status_code=202)
async def canonical_reconciliation_scan(
    body: ReconciliationScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_REPLAY)
    _require_operator(principal)
    tenant_id = _tenant_for_read(request, principal)
    result = await reconcile_internal_outbox(db, body.limit, tenant_id=tenant_id)
    return JSONResponse(
        status_code=202,
        content=jsonable_encoder(result),
        headers={"Location": f"/platform/v1/reconciliation/{result['reconciliation_id']}"},
    )


@router.get("/reconciliation/{run_id}")
async def canonical_reconciliation_status(
    run_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    tenant_id = _tenant_for_read(request, principal)
    result = await get_reconciliation_status(db, run_id, tenant_id=tenant_id)
    if result is None:
        raise CommandNotFound("reconciliation run not found")
    return JSONResponse(
        status_code=200,
        content=jsonable_encoder(result),
    )


class ConnectorOperationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID


async def _connector_operation(
    connector_id: str,
    body: ConnectorOperationRequest,
    request: Request,
    *,
    operation: Literal["readback", "reconcile"],
) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    command = await runtime.commands.get(tenant_id, body.command_id)
    envelope = await runtime.commands.load_envelope(tenant_id, body.command_id)
    ownership = platform.registry.ownership(command.command_type)
    if ownership is None:
        raise CommandCapabilityDisabled("command has no connector owner")
    row = _connector_row(platform, connector_id)
    if row is None or row["adapter_id"] != ownership.adapter_id:
        raise CommandNotFound("connector not found")
    adapter = platform.registry.adapter(ownership.adapter_id)
    advertised = platform.registry.advertised(ownership.adapter_id)
    if operation == "readback" and not advertised.supports_readback:
        raise CommandCapabilityDisabled("connector readback is unsupported")
    attempt = await runtime.commands.latest_attempt(tenant_id, body.command_id)
    context = AdapterContext(
        tenant_id=tenant_id,
        command_id=str(body.command_id),
        correlation_id=command.correlation_id,
        attempt=attempt,
        timeout_seconds=platform.dispatch.timeout_for(ownership),
        environment=platform.settings.app_env,
        deployment_sha=platform.settings.source_sha,
        http=runtime.http,
        trace_context=_trace(request),
        test_syn=command.target == "test-syn",
        payload=envelope.payload,
    )
    result = (
        await adapter.readback(command, context)
        if operation == "readback"
        else await adapter.reconcile(command, context)
    )
    return JSONResponse(
        status_code=200,
        content={
            "connector_id": connector_id,
            "command_id": str(body.command_id),
            "operation": operation,
            "status": result.status.value,
            "provider_operation_id": result.provider_operation_id,
            "evidence": redact_metadata(dict(result.evidence)),
            "error_code": result.safe_error_code,
            "correlation_id": command.correlation_id,
        },
        headers={"X-Correlation-ID": command.correlation_id},
    )


@router.post("/connectors/{connector_id}/readback")
async def connector_readback(
    connector_id: str,
    body: ConnectorOperationRequest,
    request: Request,
) -> JSONResponse:
    return await _connector_operation(connector_id, body, request, operation="readback")


@router.post("/connectors/{connector_id}/reconcile")
async def connector_reconcile(
    connector_id: str,
    body: ConnectorOperationRequest,
    request: Request,
) -> JSONResponse:
    return await _connector_operation(connector_id, body, request, operation="reconcile")


def _connector_row(platform: Any, connector_id: str) -> dict[str, Any] | None:
    for row in platform.registry.describe():
        if connector_id == row["adapter_id"] or connector_id in row["connector_ids"]:
            enabled = row["adapter_id"] in platform.registry.enabled_adapter_ids()
            return {
                "connector_id": connector_id,
                "adapter_id": row["adapter_id"],
                "version": row["version"],
                "provider": row["provider_family"],
                "capabilities": row["capabilities"],
                "command_prefixes": row["command_prefixes"],
                "supports_readback": row["supports_readback"],
                "supports_cancel": row["supports_cancel"],
                "supports_status": row["supports_status"],
                "safe_reexecution": row["safe_reexecution"],
                "external_effect": row["external_effect"],
                "enabled": enabled,
            }
    return None


@router.get("/connectors")
async def list_connectors(request: Request) -> JSONResponse:
    await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    _, platform = _runtime(request)
    rows = []
    for described in platform.registry.describe():
        for connector_id in described["connector_ids"]:
            row = _connector_row(platform, connector_id)
            if row is not None:
                rows.append(row)
    return JSONResponse(status_code=200, content={"items": rows, "limit": len(rows)})


@router.get("/connectors/{connector_id}")
async def get_connector(connector_id: str, request: Request) -> JSONResponse:
    await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    _, platform = _runtime(request)
    row = _connector_row(platform, connector_id)
    if row is None:
        raise CommandNotFound("connector not found")
    return JSONResponse(status_code=200, content=row)


@router.get("/connectors/{connector_id}/capabilities")
async def get_connector_capabilities(connector_id: str, request: Request) -> JSONResponse:
    row_response = await get_connector(connector_id, request)
    row = json.loads(row_response.body)
    return JSONResponse(
        status_code=200,
        content={
            "connector_id": connector_id,
            "capabilities": row["capabilities"],
            "supports_readback": row["supports_readback"],
            "supports_cancel": row["supports_cancel"],
            "supports_status": row["supports_status"],
            "enabled": row["enabled"],
        },
    )


@router.get("/connectors/{connector_id}/health")
async def get_connector_health(connector_id: str, request: Request) -> JSONResponse:
    principal = await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    tenant_id = _tenant_for_read(request, principal)
    row = _connector_row(platform, connector_id)
    if row is None:
        raise CommandNotFound("connector not found")
    context = AdapterContext(
        tenant_id=tenant_id,
        command_id="connector-health",
        correlation_id=getattr(request.state, "correlation_id", None) or str(UUID(int=0)),
        attempt=0,
        timeout_seconds=2.0,
        environment=request.app.state.settings.app_env,
        deployment_sha=request.app.state.settings.source_sha,
        http=runtime.http,
        trace_context=_trace(request),
        test_syn=False,
    )
    readiness = await platform.registry.readiness(context)
    status = readiness.get(row["adapter_id"])
    content = {
        "connector_id": connector_id,
        "status": "healthy" if status and status.ready else ("unavailable" if status else "unknown"),
        "detail": status.detail if status else "",
        "enabled": row["enabled"],
    }
    if not row["enabled"]:
        content["status"] = "disabled"
    return JSONResponse(status_code=200, content=content)


# ----------------------------------------------------------------------
# GET /platform/v1/kernel/describe
# ----------------------------------------------------------------------
@router.get("/kernel/describe")
async def describe_kernel(request: Request) -> JSONResponse:
    await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    description = platform.kernel.describe(
        runtime_schema_version=RUNTIME_SCHEMA_VERSION,
        contract_digest=_public_contract_digest(),
        command_contract_version=COMMAND_CONTRACT_VERSION,
    )
    return JSONResponse(status_code=200, content=description)


def _public_contract_digest() -> str | None:
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "deploy" / "public-api-route-contract.sha256"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text.split()[0] if text else None


__all__ = ["router", "CommandNotFound"]
