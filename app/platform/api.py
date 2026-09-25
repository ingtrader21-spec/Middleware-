"""The canonical V3 kernel surface: eight routes under ``/platform/v1``.

Served by every application profile through the router registry, so the
deployed integration API (8095) exposes them behind Kong. Every handler
verifies the Keycloak JWT (issuer, audience, azp, scope) as its first
statement, derives the principal from verified claims only, re-authorizes
the tenant, and delegates to the one command kernel. Domain errors are
rendered by the registry's error envelope (``error.code`` / ``message`` /
``correlation_id`` / ``retryable`` / ``details``).

Scopes: ``platform.command`` (submit, cancel), ``platform.command.read``
(operation, timeline, describe, adapter readback), ``platform.command.replay``
+ role ``platform-operator`` (replay).

``GET /platform/v1/adapters`` and ``GET /platform/v1/adapters/{adapter_id}``
are read-only registration evidence: which adapters are registered (in
production, only the manifest adapters of ``config/production-adapters.v1.json``),
the state of every capability, and readiness. They never contact a provider
while no capability is enabled.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Path, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api_inputs import optional_header, required_header
from app.commands import API_OPERATION_STATES, CommandCapabilityDisabled, CommandEnvelope, CommandNotFound, CommandOperation, OperationEvent, redact_metadata
from app.platform.kernel import SCOPE_COMMAND, SCOPE_COMMAND_READ, SCOPE_COMMAND_REPLAY, AdapterNotFound, CapabilityUnknown
from app.platform.principal import KernelPrincipal, authenticate
from app.platform.resilience import ReplayMode
from app.security import AuthorizationError, RequestValidationError
from app.storage import RUNTIME_SCHEMA_VERSION, StorageError

router = APIRouter(prefix="/platform/v1", tags=["platform-command-kernel"])

COMMAND_CONTRACT_VERSION = "command-envelope.v1"
_SAFE_ERROR_CODE = re.compile(r"[^a-z0-9_.:-]+")
TRACE_HEADERS = ("traceparent", "tracestate")
ADAPTER_ID_PATTERN = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


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


class CapabilityState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    known: bool
    enabled: bool
    classification: str
    adapter_ids: list[str]


class AdapterRegistrationRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_id: str
    provider_family: str
    connector_ids: list[str]
    capabilities: list[str]
    registered: bool
    reason: str


class AdapterRow(AdapterRegistrationRow):
    command_prefixes: list[str]
    capability_states: dict[str, bool]
    version: str | None = None
    supports_readback: bool | None = None
    supports_cancel: bool | None = None
    supports_status: bool | None = None
    safe_reexecution: bool | None = None
    external_effect: bool | None = None


class RegistrationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_version: str
    activation_authorized: bool
    refused: bool
    violations: list[str]
    adapters: list[AdapterRegistrationRow]


class AdapterReadinessEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_registry: bool
    platform_adapters: bool | None
    probed_adapter_ids: list[str]


class AdapterReadback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: str
    source_sha: str
    registration_mode: str
    registration: RegistrationEvidence | None
    registry_valid: bool
    registry_error: str | None
    adapters: list[AdapterRow]
    capabilities: dict[str, CapabilityState]
    unknown_capabilities: list[str]
    effectful_capabilities_enabled: list[str]
    provider_effects_enabled: bool
    readiness: AdapterReadinessEvidence


class AdapterDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: str
    registration_mode: str
    registry_valid: bool
    provider_effects_enabled: bool
    adapter: AdapterRow
    capabilities: dict[str, CapabilityState]


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
    if body.capability is not None and body.capability not in runtime.commands.policies.capabilities:
        raise CapabilityUnknown("capability is not listed in the capability registry")
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


# ----------------------------------------------------------------------
# GET /platform/v1/adapters
# ----------------------------------------------------------------------
_NO_STORE = {"Cache-Control": "no-store"}


@router.get("/adapters", response_model=AdapterReadback)
async def list_adapters(request: Request) -> JSONResponse:
    await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    readback = AdapterReadback.model_validate(await platform.adapter_readback())
    return JSONResponse(status_code=200, content=readback.model_dump(mode="json"), headers=_NO_STORE)


# ----------------------------------------------------------------------
# GET /platform/v1/adapters/{adapter_id}
# ----------------------------------------------------------------------
@router.get("/adapters/{adapter_id}", response_model=AdapterDetail)
async def get_adapter(adapter_id: Annotated[str, Path(pattern=ADAPTER_ID_PATTERN, max_length=100)], request: Request) -> JSONResponse:
    await authenticate(request, required_scope=SCOPE_COMMAND_READ)
    runtime, platform = _runtime(request)
    readback = AdapterReadback.model_validate(await platform.adapter_readback())
    row = next((item for item in readback.adapters if item.adapter_id == adapter_id), None)
    if row is None:
        raise AdapterNotFound("adapter is neither registered nor listed for this environment")
    detail = AdapterDetail(
        environment=readback.environment,
        registration_mode=readback.registration_mode,
        registry_valid=readback.registry_valid,
        provider_effects_enabled=readback.provider_effects_enabled,
        adapter=row,
        capabilities={name: readback.capabilities[name] for name in row.capabilities if name in readback.capabilities},
    )
    return JSONResponse(status_code=200, content=detail.model_dump(mode="json"), headers=_NO_STORE)


def _public_contract_digest() -> str | None:
    from pathlib import Path as FilePath

    path = FilePath(__file__).resolve().parents[2] / "deploy" / "public-api-route-contract.sha256"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text.split()[0] if text else None


__all__ = ["router", "CommandNotFound"]
