from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol
from uuid import UUID, uuid5, NAMESPACE_URL

import asyncpg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from .automation_policy import (
    AutomationAuthorizationError,
    AutomationClientPolicy,
    AutomationPolicy,
)
from .commands import CommandCapabilityDisabled, CommandEnvelope, CommandError, CommandOperation
from .models import EventEnvelope, IngressResult
from .storage import (
    NATS_JETSTREAM_DESTINATION,
    ZERO_LEDGER_HASH,
    PostgresInboxStore,
    ReplayConflict,
    StorageError,
    canonical_payload_sha256,
    event_ledger_hash,
)

ROOT = Path(__file__).resolve().parents[1]
ROUTING_PATH = ROOT / "config" / "automation-workflow-routing.v1.json"
AUTOMATION_SCHEMA_VERSION = 1
LEASE_SECONDS = 60
MAX_SAFE_METADATA_BYTES = 16_384
MAX_AUTOMATION_PAYLOAD_BYTES = 262_144
UNVERSIONED_COMMAND = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$")
VERSION_SUFFIX = re.compile(r"\.v[1-9][0-9]*$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}$")
SENSITIVE_PARTS = (
    "authorization",
    "token",
    "password",
    "secret",
    "credential",
    "private_key",
    "api_key",
    "access_token",
    "refresh_token",
)
SAFE_REPLAY_CLASSIFICATIONS = frozenset(
    {"NO_EFFECT", "IDEMPOTENT_CONFIRMED", "READBACK_CONFIRMED_NOT_APPLIED"}
)

JobState = Literal[
    "PENDING",
    "DISPATCHING",
    "CLAIMED",
    "RUNNING",
    "WAITING_APPROVAL",
    "WAITING_TIMER",
    "WAITING_COMMAND",
    "RETRY_SCHEDULED",
    "COMPLETED",
    "FAILED_TERMINAL",
    "DEAD_LETTER",
    "CANCELLED",
]


class AutomationError(CommandError):
    code = "automation_invalid"
    status_code = 400
    retryable = False


class AutomationAuthenticationError(AutomationError):
    code = "authentication_failed"
    status_code = 401


class AutomationAuthorizationDenied(AutomationError):
    code = "authorization_denied"
    status_code = 403


class AutomationNotFound(AutomationError):
    code = "automation_not_found"
    status_code = 404


class AutomationConflict(AutomationError):
    code = "automation_conflict"
    status_code = 409


class AutomationCapabilityDisabled(AutomationAuthorizationDenied):
    code = "capability_disabled"


class MirroredMutation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=180)
    idempotency_key: str = Field(min_length=8, max_length=180)


class JobClaimRequest(MirroredMutation):
    job_id: UUID
    delivery_token: str = Field(min_length=32, max_length=512)
    workflow_key: str = Field(min_length=1, max_length=180)
    workflow_version: int = Field(ge=1, le=2_147_483_647)
    execution_id: UUID


class LeaseMutation(MirroredMutation):
    lease_token: str = Field(min_length=32, max_length=512)
    execution_id: UUID


class HeartbeatRequest(LeaseMutation):
    pass


class StepRecord(LeaseMutation):
    step_key: str = Field(min_length=1, max_length=180)
    step_state: Literal["STARTED", "COMPLETED", "FAILED", "WAITING"]
    recorded_at: AwareDatetime
    safe_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("safe_metadata")
    @classmethod
    def safe_metadata_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_safe_document(value, label="safe_metadata", maximum=MAX_SAFE_METADATA_BYTES)
        return value


class TerminalResult(LeaseMutation):
    result_code: str = Field(min_length=1, max_length=180, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    safe_result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("safe_result")
    @classmethod
    def safe_result_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_safe_document(value, label="safe_result", maximum=MAX_SAFE_METADATA_BYTES)
        return value


class FailureResult(LeaseMutation):
    error_code: str = Field(min_length=1, max_length=180, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    retryable: bool
    unknown_outcome: bool = False
    safe_error: dict[str, Any] = Field(default_factory=dict)

    @field_validator("safe_error")
    @classmethod
    def safe_error_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_safe_document(value, label="safe_error", maximum=MAX_SAFE_METADATA_BYTES)
        return value

    @model_validator(mode="after")
    def unknown_outcome_is_never_blindly_retried(self) -> "FailureResult":
        if self.unknown_outcome and self.retryable:
            raise ValueError("unknown outcomes require reconciliation before retry")
        return self


class AutomationCommandRequest(MirroredMutation):
    job_id: UUID
    lease_token: str = Field(min_length=32, max_length=512)
    execution_id: UUID
    workflow_key: str = Field(min_length=1, max_length=180)
    workflow_version: int = Field(ge=1, le=2_147_483_647)
    step_key: str = Field(min_length=1, max_length=180)
    event_id: str = Field(min_length=1, max_length=180)
    causation_id: str = Field(min_length=1, max_length=180)
    command_type: str = Field(min_length=3, max_length=180)
    command_version: Literal["1.0"]
    occurred_at: AwareDatetime
    payload: dict[str, Any]

    @field_validator("command_type")
    @classmethod
    def unversioned_type(cls, value: str) -> str:
        if not UNVERSIONED_COMMAND.fullmatch(value) or VERSION_SUFFIX.search(value):
            raise ValueError("command_type must be normalized and unversioned")
        return value

    @field_validator("payload")
    @classmethod
    def bound_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_document_size(value, label="payload", maximum=MAX_AUTOMATION_PAYLOAD_BYTES)
        return value


class ApprovalRequest(MirroredMutation):
    job_id: UUID
    approval_type: str = Field(min_length=1, max_length=100, pattern=r"^[A-Z][A-Z0-9_]*$")
    summary: str = Field(min_length=1, max_length=1000)
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def future_expiry(self) -> "ApprovalRequest":
        if self.expires_at <= datetime.now(UTC):
            raise ValueError("approval expiry must be in the future")
        return self


class DeadLetterReplayRequest(MirroredMutation):
    approval_id: UUID
    expected_version: int = Field(ge=1)
    original_effect_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    safe_replay_classification: str
    replay_reason: str = Field(min_length=1, max_length=1000)

    @field_validator("safe_replay_classification")
    @classmethod
    def classification_allowlist(cls, value: str) -> str:
        if value not in SAFE_REPLAY_CLASSIFICATIONS:
            raise ValueError("safe replay classification is not allowlisted")
        return value


class ReconciliationRequest(MirroredMutation):
    mode: Literal["READ", "PLAN"] = "READ"
    job_ids: list[UUID] = Field(default_factory=list, max_length=1000)


class AutomationJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: UUID
    tenant_id: str
    event_id: str
    correlation_id: str
    causation_id: str
    occurred_at: AwareDatetime
    workflow_key: str
    workflow_family: str
    workflow_version: int
    actor_context: dict[str, Any]
    safe_payload: dict[str, Any]
    state: JobState
    execution_id: UUID | None = None
    lease_client_id: str | None = None
    lease_expires_at: AwareDatetime | None = None
    attempt_count: int = 0
    max_attempts: int = 3
    result_code: str | None = None
    error_code: str | None = None
    resource_version: int = 1
    created_at: AwareDatetime
    updated_at: AwareDatetime
    duplicate: bool = False


class JobClaimResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job: AutomationJob
    lease_token: str
    lease_expires_at: AwareDatetime
    duplicate: bool = False


class StepEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: int
    job_id: UUID
    execution_id: UUID
    step_key: str
    step_state: str
    safe_metadata: dict[str, Any]
    recorded_at: AwareDatetime
    duplicate: bool = False


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: UUID
    tenant_id: str
    job_id: UUID
    approval_type: str
    summary: str
    state: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"]
    requested_by: str
    decided_by: str | None = None
    expires_at: AwareDatetime
    created_at: AwareDatetime
    updated_at: AwareDatetime
    resource_version: int = 1
    duplicate: bool = False


class DeadLetterRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dead_letter_id: UUID
    tenant_id: str
    job_id: UUID
    workflow_key: str
    workflow_family: str
    original_effect_fingerprint: str
    safe_payload: dict[str, Any]
    state: Literal["OPEN", "REPLAY_REQUESTED", "REPLAYED", "CLOSED"]
    resource_version: int
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ReconciliationRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reconciliation_id: UUID
    tenant_id: str
    mode: Literal["READ", "PLAN"]
    requested_by: str
    status: Literal["COMPLETED"] = "COMPLETED"
    inspected_jobs: int
    state_counts: dict[str, int]
    expired_leases: int
    missing_dispatches: int
    safe_plan: list[dict[str, Any]]
    created_at: AwareDatetime
    duplicate: bool = False


@dataclass(frozen=True)
class WorkflowRoute:
    event_type: str
    workflow_key: str
    workflow_family: str
    workflow_version: int
    client_id: str
    max_attempts: int
    external_effect: bool


class WorkflowRouter:
    def __init__(self, routes: tuple[WorkflowRoute, ...]) -> None:
        self.routes = routes
        by_event: dict[str, list[WorkflowRoute]] = {}
        for route in routes:
            by_event.setdefault(route.event_type, []).append(route)
        self.by_event = {key: tuple(value) for key, value in by_event.items()}

    @classmethod
    def load(cls, path: Path = ROUTING_PATH) -> "WorkflowRouter":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "1.0" or raw.get("status") != "SOURCE_ONLY_DISABLED":
            raise RuntimeError("automation workflow routing authority is invalid")
        rows = raw.get("routes")
        if not isinstance(rows, list) or not rows:
            raise RuntimeError("automation workflow routing contains no routes")
        routes: list[WorkflowRoute] = []
        seen: set[tuple[str, str, int]] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("automation workflow route must be an object")
            route = WorkflowRoute(
                event_type=str(row.get("event_type", "")),
                workflow_key=str(row.get("workflow_key", "")),
                workflow_family=str(row.get("workflow_family", "")),
                workflow_version=int(row.get("workflow_version", 0)),
                client_id=str(row.get("client_id", "")),
                max_attempts=int(row.get("max_attempts", 0)),
                external_effect=row.get("external_effect") is True,
            )
            identity = (route.event_type, route.workflow_key, route.workflow_version)
            if (
                not all(identity)
                or route.workflow_version < 1
                or route.max_attempts < 1
                or identity in seen
                or route.external_effect
            ):
                raise RuntimeError("automation workflow route violates first-release safety")
            seen.add(identity)
            routes.append(route)
        return cls(tuple(routes))

    def for_event(self, event_type: str) -> tuple[WorkflowRoute, ...]:
        return self.by_event.get(event_type, ())


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _validate_document_size(value: object, *, label: str, maximum: int) -> None:
    if len(_json_bytes(value)) > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")


def _validate_safe_document(value: object, *, label: str, maximum: int) -> None:
    _validate_document_size(value, label=label, maximum=maximum)

    def visit(item: object, path: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                normalized = str(key).lower()
                if any(part in normalized for part in SENSITIVE_PARTS):
                    raise ValueError(f"{label} contains sensitive key at {path}.{key}")
                visit(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")

    visit(value, label)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _lease_token(delivery_token: str, job_id: UUID, execution_id: UUID, client_id: str) -> str:
    material = f"{job_id}:{execution_id}:{client_id}".encode("utf-8")
    raw = hmac.new(delivery_token.encode("utf-8"), material, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _job_id(tenant_id: str, event_id: str, route: WorkflowRoute) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"codestra-automation-job:{tenant_id}:{event_id}:{route.workflow_key}:{route.workflow_version}",
    )


def _command_id(body: AutomationCommandRequest) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"codestra-automation-command:{body.tenant_id}:{body.job_id}:{body.idempotency_key}:{body.command_type}:{body.command_version}",
    )


def _peek_client_id(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise AutomationAuthenticationError("Bearer token is required")
    token = authorization[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise AutomationAuthenticationError("Bearer token is not a JWT")
    try:
        segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutomationAuthenticationError("Bearer token payload is malformed") from exc
    client_id = payload.get("azp") if isinstance(payload, dict) else None
    if not isinstance(client_id, str) or not SAFE_IDENTIFIER.fullmatch(client_id):
        raise AutomationAuthenticationError("Bearer token azp is missing or invalid")
    return client_id


def _require_header(request: Request, name: str) -> str:
    value = request.headers.get(name, "").strip()
    if not value:
        raise AutomationError(f"{name} is required")
    if len(value) > 180:
        raise AutomationError(f"{name} exceeds 180 characters")
    return value


def _assert_header_body_mirror(request: Request, body: MirroredMutation) -> None:
    if _require_header(request, "X-Tenant-ID") != body.tenant_id:
        raise AutomationConflict("X-Tenant-ID does not match body tenant_id")
    if _require_header(request, "X-Correlation-ID") != body.correlation_id:
        raise AutomationConflict("X-Correlation-ID does not match body correlation_id")
    if _require_header(request, "Idempotency-Key") != body.idempotency_key:
        raise AutomationConflict("Idempotency-Key does not match body idempotency_key")
    _require_header(request, "X-Request-ID")


def _read_headers(request: Request) -> tuple[str, str]:
    tenant_id = _require_header(request, "X-Tenant-ID")
    correlation_id = _require_header(request, "X-Correlation-ID")
    _require_header(request, "X-Request-ID")
    return tenant_id, correlation_id


def _row_json(value: object) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, Mapping):
        raise StorageError("persisted automation JSON is invalid")
    return dict(value)


class AutomationStore(Protocol):
    async def ready(self) -> bool: ...
    async def close(self) -> None: ...
    async def enqueue_event(self, envelope: EventEnvelope, route: WorkflowRoute, *, source_client_id: str) -> None: ...
    async def claim(self, body: JobClaimRequest, *, client_id: str) -> JobClaimResponse: ...
    async def get_job(self, tenant_id: str, job_id: UUID) -> AutomationJob: ...
    async def heartbeat(self, job_id: UUID, body: HeartbeatRequest, *, client_id: str) -> AutomationJob: ...
    async def record_step(self, job_id: UUID, body: StepRecord, *, client_id: str) -> StepEvidence: ...
    async def complete(self, job_id: UUID, body: TerminalResult, *, client_id: str) -> AutomationJob: ...
    async def fail(self, job_id: UUID, body: FailureResult, *, client_id: str) -> AutomationJob: ...
    async def request_approval(self, body: ApprovalRequest, *, client_id: str, requested_by: str) -> ApprovalRecord: ...
    async def get_approval(self, tenant_id: str, approval_id: UUID) -> ApprovalRecord: ...
    async def get_dead_letter(self, tenant_id: str, dead_letter_id: UUID) -> DeadLetterRecord: ...
    async def replay_dead_letter(self, dead_letter_id: UUID, body: DeadLetterReplayRequest, *, client_id: str) -> AutomationJob: ...
    async def reconcile(self, body: ReconciliationRequest, *, requested_by: str) -> ReconciliationRun: ...


class MemoryAutomationStore:
    """Concurrency-safe test/development implementation of the v2 state machine."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.jobs: dict[tuple[str, UUID], dict[str, Any]] = {}
        self.steps: dict[tuple[str, UUID, str], tuple[str, StepEvidence]] = {}
        self.approvals: dict[tuple[str, UUID], tuple[str, ApprovalRecord]] = {}
        self.approval_idempotency: dict[tuple[str, UUID, str], UUID] = {}
        self.dead_letters: dict[tuple[str, UUID], DeadLetterRecord] = {}
        self.reconciliations: dict[tuple[str, str], tuple[str, ReconciliationRun]] = {}
        self.dispatches: dict[tuple[str, UUID], dict[str, Any]] = {}

    def _job(self, raw: dict[str, Any], *, duplicate: bool = False) -> AutomationJob:
        return AutomationJob(
            job_id=raw["job_id"],
            tenant_id=raw["tenant_id"],
            event_id=raw["event_id"],
            correlation_id=raw["correlation_id"],
            causation_id=raw["causation_id"],
            occurred_at=raw["occurred_at"],
            workflow_key=raw["workflow_key"],
            workflow_family=raw["workflow_family"],
            workflow_version=raw["workflow_version"],
            actor_context=dict(raw["actor_context"]),
            safe_payload=dict(raw["safe_payload"]),
            state=raw["state"],
            execution_id=raw.get("execution_id"),
            lease_client_id=raw.get("lease_client_id"),
            lease_expires_at=raw.get("lease_expires_at"),
            attempt_count=raw["attempt_count"],
            max_attempts=raw["max_attempts"],
            result_code=raw.get("result_code"),
            error_code=raw.get("error_code"),
            resource_version=raw["resource_version"],
            created_at=raw["created_at"],
            updated_at=raw["updated_at"],
            duplicate=duplicate,
        )

    def _raw(self, tenant_id: str, job_id: UUID) -> dict[str, Any]:
        value = self.jobs.get((tenant_id, job_id))
        if value is None:
            raise AutomationNotFound("automation job was not found")
        return value

    def _active_lease(
        self,
        raw: dict[str, Any],
        *,
        lease_token: str,
        execution_id: UUID,
        client_id: str,
    ) -> None:
        now = _utcnow()
        if (
            raw.get("lease_token_sha256") != _token_digest(lease_token)
            or raw.get("execution_id") != execution_id
            or raw.get("lease_client_id") != client_id
            or raw.get("lease_expires_at") is None
            or raw["lease_expires_at"] <= now
            or raw["state"] not in {
                "CLAIMED",
                "RUNNING",
                "WAITING_APPROVAL",
                "WAITING_TIMER",
                "WAITING_COMMAND",
            }
        ):
            raise AutomationConflict("active automation lease is required")

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None

    async def enqueue_event(
        self,
        envelope: EventEnvelope,
        route: WorkflowRoute,
        *,
        source_client_id: str,
    ) -> None:
        async with self._lock:
            job_id = _job_id(envelope.tenant_id, envelope.event_id, route)
            key = (envelope.tenant_id, job_id)
            if key in self.jobs:
                return
            now = _utcnow()
            delivery_token = secrets.token_urlsafe(32)
            self.jobs[key] = {
                "job_id": job_id,
                "tenant_id": envelope.tenant_id,
                "event_id": envelope.event_id,
                "correlation_id": envelope.correlation_id,
                "causation_id": envelope.causation_id,
                "occurred_at": envelope.occurred_at,
                "workflow_key": route.workflow_key,
                "workflow_family": route.workflow_family,
                "workflow_version": route.workflow_version,
                "expected_client_id": route.client_id,
                "actor_context": {
                    "source_client_id": source_client_id,
                    "source_event_id": envelope.event_id,
                },
                "safe_payload": dict(envelope.payload),
                "state": "PENDING",
                "delivery_token_sha256": _token_digest(delivery_token),
                "delivery_token_used_at": None,
                "lease_token_sha256": None,
                "lease_client_id": None,
                "execution_id": None,
                "lease_expires_at": None,
                "attempt_count": 0,
                "max_attempts": route.max_attempts,
                "result_code": None,
                "error_code": None,
                "terminal_idempotency_key": None,
                "terminal_request_sha256": None,
                "resource_version": 1,
                "created_at": now,
                "updated_at": now,
            }
            self.dispatches[key] = {
                "delivery_token": delivery_token,
                "payload": {
                    "job_id": str(job_id),
                    "workflow_key": route.workflow_key,
                    "workflow_version": route.workflow_version,
                    "correlation_id": envelope.correlation_id,
                    "delivery_token": delivery_token,
                },
                "state": "PENDING",
            }

    async def claim(self, body: JobClaimRequest, *, client_id: str) -> JobClaimResponse:
        async with self._lock:
            raw = self._raw(body.tenant_id, body.job_id)
            now = _utcnow()
            if raw["workflow_key"] != body.workflow_key or raw["workflow_version"] != body.workflow_version:
                raise AutomationConflict("claim workflow identity does not match durable job")
            if raw["expected_client_id"] != client_id:
                raise AutomationAuthorizationDenied("client does not own the job workflow family")
            if raw["delivery_token_sha256"] != _token_digest(body.delivery_token):
                raise AutomationAuthorizationDenied("delivery token is invalid")
            lease_token = _lease_token(body.delivery_token, body.job_id, body.execution_id, client_id)
            duplicate = False
            if raw["delivery_token_used_at"] is not None:
                if (
                    raw.get("execution_id") == body.execution_id
                    and raw.get("lease_client_id") == client_id
                    and raw.get("lease_expires_at") is not None
                    and raw["lease_expires_at"] > now
                    and raw.get("lease_token_sha256") == _token_digest(lease_token)
                ):
                    duplicate = True
                else:
                    raise AutomationConflict("delivery token was already consumed")
            elif raw["state"] not in {"PENDING", "RETRY_SCHEDULED"}:
                raise AutomationConflict("automation job is not claimable")
            else:
                raw["delivery_token_used_at"] = now
                raw["lease_token_sha256"] = _token_digest(lease_token)
                raw["lease_client_id"] = client_id
                raw["execution_id"] = body.execution_id
                raw["lease_expires_at"] = now + timedelta(seconds=LEASE_SECONDS)
                raw["attempt_count"] += 1
                raw["state"] = "CLAIMED"
                raw["resource_version"] += 1
                raw["updated_at"] = now
                self.dispatches[(body.tenant_id, body.job_id)]["state"] = "CLAIMED"
            return JobClaimResponse(
                job=self._job(raw, duplicate=duplicate),
                lease_token=lease_token,
                lease_expires_at=raw["lease_expires_at"],
                duplicate=duplicate,
            )

    async def get_job(self, tenant_id: str, job_id: UUID) -> AutomationJob:
        async with self._lock:
            return self._job(self._raw(tenant_id, job_id))

    async def heartbeat(
        self,
        job_id: UUID,
        body: HeartbeatRequest,
        *,
        client_id: str,
    ) -> AutomationJob:
        async with self._lock:
            raw = self._raw(body.tenant_id, job_id)
            self._active_lease(
                raw,
                lease_token=body.lease_token,
                execution_id=body.execution_id,
                client_id=client_id,
            )
            now = _utcnow()
            raw["lease_expires_at"] = now + timedelta(seconds=LEASE_SECONDS)
            raw["state"] = "RUNNING"
            raw["resource_version"] += 1
            raw["updated_at"] = now
            return self._job(raw)

    async def record_step(
        self,
        job_id: UUID,
        body: StepRecord,
        *,
        client_id: str,
    ) -> StepEvidence:
        async with self._lock:
            raw = self._raw(body.tenant_id, job_id)
            self._active_lease(
                raw,
                lease_token=body.lease_token,
                execution_id=body.execution_id,
                client_id=client_id,
            )
            key = (body.tenant_id, job_id, body.idempotency_key)
            request_digest = _digest(
                {
                    "execution_id": str(body.execution_id),
                    "step_key": body.step_key,
                    "step_state": body.step_state,
                    "recorded_at": body.recorded_at.isoformat(),
                    "safe_metadata": body.safe_metadata,
                }
            )
            existing = self.steps.get(key)
            if existing is not None:
                if existing[0] != request_digest:
                    raise AutomationConflict("step idempotency key was reused with different content")
                return existing[1].model_copy(update={"duplicate": True})
            evidence = StepEvidence(
                evidence_id=len(self.steps) + 1,
                job_id=job_id,
                execution_id=body.execution_id,
                step_key=body.step_key,
                step_state=body.step_state,
                safe_metadata=dict(body.safe_metadata),
                recorded_at=body.recorded_at,
            )
            self.steps[key] = (request_digest, evidence)
            raw["state"] = "RUNNING"
            raw["resource_version"] += 1
            raw["updated_at"] = _utcnow()
            return evidence

    def _terminal_replay(
        self,
        raw: dict[str, Any],
        idempotency_key: str,
        request_digest: str,
    ) -> AutomationJob | None:
        existing_key = raw.get("terminal_idempotency_key")
        if existing_key is None:
            return None
        if existing_key == idempotency_key and raw.get("terminal_request_sha256") == request_digest:
            return self._job(raw, duplicate=True)
        raise AutomationConflict("job already has a different terminal transition")

    async def complete(
        self,
        job_id: UUID,
        body: TerminalResult,
        *,
        client_id: str,
    ) -> AutomationJob:
        async with self._lock:
            raw = self._raw(body.tenant_id, job_id)
            request_digest = _digest(
                {
                    "execution_id": str(body.execution_id),
                    "result_code": body.result_code,
                    "safe_result": body.safe_result,
                }
            )
            replay = self._terminal_replay(raw, body.idempotency_key, request_digest)
            if replay is not None:
                return replay
            self._active_lease(
                raw,
                lease_token=body.lease_token,
                execution_id=body.execution_id,
                client_id=client_id,
            )
            now = _utcnow()
            raw.update(
                state="COMPLETED",
                result_code=body.result_code,
                error_code=None,
                terminal_idempotency_key=body.idempotency_key,
                terminal_request_sha256=request_digest,
                lease_expires_at=None,
                lease_token_sha256=None,
                resource_version=raw["resource_version"] + 1,
                updated_at=now,
            )
            return self._job(raw)

    async def fail(
        self,
        job_id: UUID,
        body: FailureResult,
        *,
        client_id: str,
    ) -> AutomationJob:
        async with self._lock:
            raw = self._raw(body.tenant_id, job_id)
            request_digest = _digest(
                {
                    "execution_id": str(body.execution_id),
                    "error_code": body.error_code,
                    "retryable": body.retryable,
                    "unknown_outcome": body.unknown_outcome,
                    "safe_error": body.safe_error,
                }
            )
            replay = self._terminal_replay(raw, body.idempotency_key, request_digest)
            if replay is not None:
                return replay
            self._active_lease(
                raw,
                lease_token=body.lease_token,
                execution_id=body.execution_id,
                client_id=client_id,
            )
            now = _utcnow()
            state: JobState
            if body.unknown_outcome:
                state = "DEAD_LETTER"
            elif body.retryable and raw["attempt_count"] < raw["max_attempts"]:
                state = "RETRY_SCHEDULED"
            elif raw["attempt_count"] >= raw["max_attempts"]:
                state = "DEAD_LETTER"
            else:
                state = "FAILED_TERMINAL"
            raw.update(
                state=state,
                result_code=None,
                error_code=body.error_code,
                terminal_idempotency_key=body.idempotency_key,
                terminal_request_sha256=request_digest,
                lease_expires_at=None,
                lease_token_sha256=None,
                resource_version=raw["resource_version"] + 1,
                updated_at=now,
            )
            if state == "RETRY_SCHEDULED":
                delivery_token = secrets.token_urlsafe(32)
                raw["delivery_token_sha256"] = _token_digest(delivery_token)
                raw["delivery_token_used_at"] = None
                raw["execution_id"] = None
                raw["lease_client_id"] = None
                raw["terminal_idempotency_key"] = None
                raw["terminal_request_sha256"] = None
                self.dispatches[(body.tenant_id, job_id)] = {
                    "delivery_token": delivery_token,
                    "payload": {
                        "job_id": str(job_id),
                        "workflow_key": raw["workflow_key"],
                        "workflow_version": raw["workflow_version"],
                        "correlation_id": raw["correlation_id"],
                        "delivery_token": delivery_token,
                    },
                    "state": "PENDING",
                }
            elif state == "DEAD_LETTER":
                dead_letter_id = uuid5(NAMESPACE_URL, f"codestra-dead-letter:{body.tenant_id}:{job_id}")
                fingerprint = _digest(
                    {
                        "tenant_id": body.tenant_id,
                        "job_id": str(job_id),
                        "workflow_key": raw["workflow_key"],
                        "error_code": body.error_code,
                    }
                )
                self.dead_letters[(body.tenant_id, dead_letter_id)] = DeadLetterRecord(
                    dead_letter_id=dead_letter_id,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    workflow_key=raw["workflow_key"],
                    workflow_family=raw["workflow_family"],
                    original_effect_fingerprint=fingerprint,
                    safe_payload={"error_code": body.error_code, "unknown_outcome": body.unknown_outcome},
                    state="OPEN",
                    resource_version=1,
                    created_at=now,
                    updated_at=now,
                )
            return self._job(raw)

    async def request_approval(
        self,
        body: ApprovalRequest,
        *,
        client_id: str,
        requested_by: str,
    ) -> ApprovalRecord:
        async with self._lock:
            raw = self._raw(body.tenant_id, body.job_id)
            if raw["expected_client_id"] != client_id:
                raise AutomationAuthorizationDenied("client does not own the approval job family")
            digest = _digest(
                {
                    "job_id": str(body.job_id),
                    "approval_type": body.approval_type,
                    "summary": body.summary,
                    "expires_at": body.expires_at.isoformat(),
                }
            )
            idem_key = (body.tenant_id, body.job_id, body.idempotency_key)
            existing_id = self.approval_idempotency.get(idem_key)
            if existing_id is not None:
                existing_digest, existing = self.approvals[(body.tenant_id, existing_id)]
                if existing_digest != digest:
                    raise AutomationConflict("approval idempotency key was reused with different content")
                return existing.model_copy(update={"duplicate": True})
            now = _utcnow()
            approval_id = uuid5(
                NAMESPACE_URL,
                f"codestra-approval:{body.tenant_id}:{body.job_id}:{body.idempotency_key}",
            )
            record = ApprovalRecord(
                approval_id=approval_id,
                tenant_id=body.tenant_id,
                job_id=body.job_id,
                approval_type=body.approval_type,
                summary=body.summary,
                state="PENDING",
                requested_by=requested_by,
                expires_at=body.expires_at,
                created_at=now,
                updated_at=now,
            )
            self.approvals[(body.tenant_id, approval_id)] = (digest, record)
            self.approval_idempotency[idem_key] = approval_id
            if raw["state"] not in {"COMPLETED", "CANCELLED", "FAILED_TERMINAL", "DEAD_LETTER"}:
                raw["state"] = "WAITING_APPROVAL"
                raw["resource_version"] += 1
                raw["updated_at"] = now
            return record

    async def get_approval(self, tenant_id: str, approval_id: UUID) -> ApprovalRecord:
        async with self._lock:
            entry = self.approvals.get((tenant_id, approval_id))
            if entry is None:
                raise AutomationNotFound("approval was not found")
            record = entry[1]
            if record.state == "PENDING" and record.expires_at <= _utcnow():
                record = record.model_copy(
                    update={
                        "state": "EXPIRED",
                        "updated_at": _utcnow(),
                        "resource_version": record.resource_version + 1,
                    }
                )
                self.approvals[(tenant_id, approval_id)] = (entry[0], record)
            return record

    async def get_dead_letter(self, tenant_id: str, dead_letter_id: UUID) -> DeadLetterRecord:
        async with self._lock:
            record = self.dead_letters.get((tenant_id, dead_letter_id))
            if record is None:
                raise AutomationNotFound("dead letter was not found")
            return record

    async def approve_for_test(
        self,
        tenant_id: str,
        approval_id: UUID,
        *,
        decided_by: str,
    ) -> ApprovalRecord:
        async with self._lock:
            entry = self.approvals.get((tenant_id, approval_id))
            if entry is None:
                raise AutomationNotFound("approval was not found")
            record = entry[1]
            if record.requested_by == decided_by:
                raise AutomationConflict("approval requester cannot self-approve")
            record = record.model_copy(
                update={
                    "state": "APPROVED",
                    "decided_by": decided_by,
                    "updated_at": _utcnow(),
                    "resource_version": record.resource_version + 1,
                }
            )
            self.approvals[(tenant_id, approval_id)] = (entry[0], record)
            return record

    async def replay_dead_letter(
        self,
        dead_letter_id: UUID,
        body: DeadLetterReplayRequest,
        *,
        client_id: str,
    ) -> AutomationJob:
        async with self._lock:
            if client_id != "n8n-operations-automation":
                raise AutomationAuthorizationDenied("only operations automation may request replay")
            dead = self.dead_letters.get((body.tenant_id, dead_letter_id))
            if dead is None:
                raise AutomationNotFound("dead letter was not found")
            approval_entry = self.approvals.get((body.tenant_id, body.approval_id))
            if approval_entry is None:
                raise AutomationNotFound("approval was not found")
            approval = approval_entry[1]
            if (
                approval.job_id != dead.job_id
                or approval.approval_type != "REPLAY"
                or approval.state != "APPROVED"
                or not approval.decided_by
                or approval.decided_by == approval.requested_by
                or approval.expires_at <= _utcnow()
            ):
                raise AutomationAuthorizationDenied("protected non-self approval is required")
            if dead.resource_version != body.expected_version:
                raise AutomationConflict("dead-letter expected_version is stale")
            if dead.original_effect_fingerprint != body.original_effect_fingerprint:
                raise AutomationConflict("dead-letter effect fingerprint does not match")
            if dead.state != "OPEN":
                raise AutomationConflict("dead letter is not open for replay")
            original = self._raw(body.tenant_id, dead.job_id)
            now = _utcnow()
            delivery_token = secrets.token_urlsafe(32)
            original.update(
                state="RETRY_SCHEDULED",
                delivery_token_sha256=_token_digest(delivery_token),
                delivery_token_used_at=None,
                lease_token_sha256=None,
                lease_client_id=None,
                execution_id=None,
                lease_expires_at=None,
                terminal_idempotency_key=None,
                terminal_request_sha256=None,
                resource_version=original["resource_version"] + 1,
                updated_at=now,
            )
            self.dispatches[(body.tenant_id, dead.job_id)] = {
                "delivery_token": delivery_token,
                "payload": {
                    "job_id": str(dead.job_id),
                    "workflow_key": original["workflow_key"],
                    "workflow_version": original["workflow_version"],
                    "correlation_id": original["correlation_id"],
                    "delivery_token": delivery_token,
                },
                "state": "PENDING",
            }
            self.dead_letters[(body.tenant_id, dead_letter_id)] = dead.model_copy(
                update={
                    "state": "REPLAY_REQUESTED",
                    "resource_version": dead.resource_version + 1,
                    "updated_at": now,
                }
            )
            return self._job(original)

    async def reconcile(
        self,
        body: ReconciliationRequest,
        *,
        requested_by: str,
    ) -> ReconciliationRun:
        async with self._lock:
            digest = _digest(
                {"mode": body.mode, "job_ids": [str(item) for item in body.job_ids]}
            )
            key = (body.tenant_id, body.idempotency_key)
            existing = self.reconciliations.get(key)
            if existing is not None:
                if existing[0] != digest:
                    raise AutomationConflict("reconciliation idempotency key was reused")
                return existing[1].model_copy(update={"duplicate": True})
            selected = [
                raw
                for (tenant_id, job_id), raw in self.jobs.items()
                if tenant_id == body.tenant_id and (not body.job_ids or job_id in body.job_ids)
            ]
            now = _utcnow()
            counts: dict[str, int] = {}
            expired = 0
            missing_dispatches = 0
            plan: list[dict[str, Any]] = []
            for raw in selected:
                counts[raw["state"]] = counts.get(raw["state"], 0) + 1
                if raw.get("lease_expires_at") is not None and raw["lease_expires_at"] <= now:
                    expired += 1
                    if body.mode == "PLAN":
                        plan.append({"job_id": str(raw["job_id"]), "action": "REQUEUE_EXPIRED_LEASE"})
                if raw["state"] in {"PENDING", "RETRY_SCHEDULED"} and (
                    raw["tenant_id"], raw["job_id"]
                ) not in self.dispatches:
                    missing_dispatches += 1
                    if body.mode == "PLAN":
                        plan.append({"job_id": str(raw["job_id"]), "action": "RECREATE_DISPATCH"})
            run = ReconciliationRun(
                reconciliation_id=uuid5(
                    NAMESPACE_URL,
                    f"codestra-automation-reconcile:{body.tenant_id}:{body.idempotency_key}",
                ),
                tenant_id=body.tenant_id,
                mode=body.mode,
                requested_by=requested_by,
                inspected_jobs=len(selected),
                state_counts=counts,
                expired_leases=expired,
                missing_dispatches=missing_dispatches,
                safe_plan=plan,
                created_at=now,
            )
            self.reconciliations[key] = (digest, run)
            return run


class PostgresAutomationStore:
    REQUIRED_TABLES = frozenset(
        {
            "middleware_automation_schema_migrations",
            "middleware_automation_jobs",
            "middleware_automation_job_steps",
            "middleware_automation_approvals",
            "middleware_automation_dead_letters",
            "middleware_automation_reconciliation_runs",
            "middleware_automation_replay_requests",
            "middleware_automation_dispatch_outbox",
            "middleware_automation_audit",
        }
    )

    def __init__(self, pool: asyncpg.Pool, *, owns_pool: bool = True) -> None:
        self.pool = pool
        self.owns_pool = owns_pool

    @classmethod
    async def connect(cls, database_url: str) -> "PostgresAutomationStore":
        pool = await asyncpg.create_pool(
            database_url,
            min_size=1,
            max_size=10,
            command_timeout=10,
        )
        store = cls(pool)
        try:
            if not await store.ready():
                raise StorageError("automation v2 schema is unavailable or stale")
        except Exception:
            await pool.close()
            raise
        return store

    async def ready(self) -> bool:
        try:
            async with self.pool.acquire() as conn:
                version = await conn.fetchval(
                    "SELECT max(version) FROM middleware_automation_schema_migrations"
                )
                rows = await conn.fetch(
                    """
                    SELECT table_name FROM information_schema.tables
                    WHERE table_schema='public' AND table_name=ANY($1::text[])
                    """,
                    list(self.REQUIRED_TABLES),
                )
            return version == AUTOMATION_SCHEMA_VERSION and {
                row["table_name"] for row in rows
            } == set(self.REQUIRED_TABLES)
        except Exception:
            return False

    async def close(self) -> None:
        if self.owns_pool:
            await self.pool.close()

    @staticmethod
    def _job_from_row(row: Mapping[str, Any], *, duplicate: bool = False) -> AutomationJob:
        return AutomationJob(
            job_id=row["job_id"],
            tenant_id=row["tenant_id"],
            event_id=row["event_id"],
            correlation_id=row["correlation_id"],
            causation_id=row["causation_id"],
            occurred_at=row["occurred_at"],
            workflow_key=row["workflow_key"],
            workflow_family=row["workflow_family"],
            workflow_version=row["workflow_version"],
            actor_context=_row_json(row["actor_context"]),
            safe_payload=_row_json(row["safe_payload"]),
            state=row["state"],
            execution_id=row["execution_id"],
            lease_client_id=row["lease_client_id"],
            lease_expires_at=row["lease_expires_at"],
            attempt_count=row["attempt_count"],
            max_attempts=row["max_attempts"],
            result_code=row["result_code"],
            error_code=row["error_code"],
            resource_version=row["resource_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            duplicate=duplicate,
        )

    @staticmethod
    def _approval_from_row(row: Mapping[str, Any], *, duplicate: bool = False) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=row["approval_id"],
            tenant_id=row["tenant_id"],
            job_id=row["job_id"],
            approval_type=row["approval_type"],
            summary=row["summary"],
            state=row["state"],
            requested_by=row["requested_by"],
            decided_by=row["decided_by"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            resource_version=row["resource_version"],
            duplicate=duplicate,
        )

    @staticmethod
    def _dead_from_row(row: Mapping[str, Any]) -> DeadLetterRecord:
        return DeadLetterRecord(
            dead_letter_id=row["dead_letter_id"],
            tenant_id=row["tenant_id"],
            job_id=row["job_id"],
            workflow_key=row["workflow_key"],
            workflow_family=row["workflow_family"],
            original_effect_fingerprint=row["original_effect_fingerprint"],
            safe_payload=_row_json(row["safe_payload"]),
            state=row["state"],
            resource_version=row["resource_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def enqueue_event(
        self,
        envelope: EventEnvelope,
        route: WorkflowRoute,
        *,
        source_client_id: str,
    ) -> None:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self.enqueue_event_on_connection(
                    conn,
                    envelope,
                    route,
                    source_client_id=source_client_id,
                )

    async def enqueue_event_on_connection(
        self,
        conn: asyncpg.Connection,
        envelope: EventEnvelope,
        route: WorkflowRoute,
        *,
        source_client_id: str,
    ) -> None:
        job_id = _job_id(envelope.tenant_id, envelope.event_id, route)
        delivery_token = secrets.token_urlsafe(32)
        now = _utcnow()
        row = await conn.fetchrow(
            """
            INSERT INTO middleware_automation_jobs (
                tenant_id, job_id, event_id, correlation_id, causation_id, occurred_at,
                workflow_key, workflow_family, workflow_version, expected_client_id,
                actor_context, safe_payload, state, delivery_token_sha256,
                max_attempts, created_at, updated_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,
                'PENDING',$13,$14,$15,$15
            )
            ON CONFLICT (tenant_id,event_id,workflow_key,workflow_version) DO NOTHING
            RETURNING job_id
            """,
            envelope.tenant_id,
            job_id,
            envelope.event_id,
            envelope.correlation_id,
            envelope.causation_id,
            envelope.occurred_at,
            route.workflow_key,
            route.workflow_family,
            route.workflow_version,
            route.client_id,
            json.dumps(
                {
                    "source_client_id": source_client_id,
                    "source_event_id": envelope.event_id,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            json.dumps(dict(envelope.payload), separators=(",", ":"), sort_keys=True),
            _token_digest(delivery_token),
            route.max_attempts,
            now,
        )
        if row is None:
            return
        wake = {
            "job_id": str(job_id),
            "workflow_key": route.workflow_key,
            "workflow_version": route.workflow_version,
            "correlation_id": envelope.correlation_id,
            "delivery_token": delivery_token,
        }
        await conn.execute(
            """
            INSERT INTO middleware_automation_dispatch_outbox (
                tenant_id, job_id, workflow_key, workflow_version,
                correlation_id, payload, state, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,'PENDING',$7,$7)
            ON CONFLICT (tenant_id,job_id,dispatch_generation) DO NOTHING
            """,
            envelope.tenant_id,
            job_id,
            route.workflow_key,
            route.workflow_version,
            envelope.correlation_id,
            json.dumps(wake, separators=(",", ":"), sort_keys=True),
            now,
        )
        await conn.execute(
            """
            INSERT INTO middleware_automation_audit (
                tenant_id, job_id, event_type, previous_state, new_state,
                actor_id, correlation_id, safe_metadata
            ) VALUES ($1,$2,'job.created',NULL,'PENDING',$3,$4,$5::jsonb)
            """,
            envelope.tenant_id,
            job_id,
            source_client_id,
            envelope.correlation_id,
            json.dumps({"workflow_key": route.workflow_key}, separators=(",", ":"), sort_keys=True),
        )

    async def claim(self, body: JobClaimRequest, *, client_id: str) -> JobClaimResponse:
        token_hash = _token_digest(body.delivery_token)
        lease_token = _lease_token(body.delivery_token, body.job_id, body.execution_id, client_id)
        lease_hash = _token_digest(lease_token)
        now = _utcnow()
        expires = now + timedelta(seconds=LEASE_SECONDS)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    """
                    SELECT * FROM middleware_automation_jobs
                    WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE
                    """,
                    body.tenant_id,
                    body.job_id,
                )
                if current is None:
                    raise AutomationNotFound("automation job was not found")
                if current["workflow_key"] != body.workflow_key or current["workflow_version"] != body.workflow_version:
                    raise AutomationConflict("claim workflow identity does not match durable job")
                if current["expected_client_id"] != client_id:
                    raise AutomationAuthorizationDenied("client does not own the job workflow family")
                if current["delivery_token_sha256"] != token_hash:
                    raise AutomationAuthorizationDenied("delivery token is invalid")
                duplicate = False
                if current["delivery_token_used_at"] is not None:
                    if (
                        current["execution_id"] == body.execution_id
                        and current["lease_client_id"] == client_id
                        and current["lease_expires_at"] is not None
                        and current["lease_expires_at"] > now
                        and current["lease_token_sha256"] == lease_hash
                    ):
                        duplicate = True
                        row = current
                        expires = current["lease_expires_at"]
                    else:
                        raise AutomationConflict("delivery token was already consumed")
                else:
                    if current["state"] not in {"PENDING", "RETRY_SCHEDULED"}:
                        raise AutomationConflict("automation job is not claimable")
                    row = await conn.fetchrow(
                        """
                        UPDATE middleware_automation_jobs
                        SET delivery_token_used_at=$3,
                            lease_token_sha256=$4,
                            lease_client_id=$5,
                            execution_id=$6,
                            lease_expires_at=$7,
                            attempt_count=attempt_count+1,
                            state='CLAIMED',
                            resource_version=resource_version+1,
                            updated_at=$3
                        WHERE tenant_id=$1 AND job_id=$2
                        RETURNING *
                        """,
                        body.tenant_id,
                        body.job_id,
                        now,
                        lease_hash,
                        client_id,
                        body.execution_id,
                        expires,
                    )
                    await conn.execute(
                        """
                        UPDATE middleware_automation_dispatch_outbox
                        SET state='CLAIMED', claimed_at=$3, updated_at=$3
                        WHERE tenant_id=$1 AND job_id=$2 AND state='PENDING'
                        """,
                        body.tenant_id,
                        body.job_id,
                        now,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_automation_audit (
                            tenant_id,job_id,event_type,previous_state,new_state,
                            actor_id,correlation_id,safe_metadata
                        ) VALUES ($1,$2,'job.claimed',$3,'CLAIMED',$4,$5,$6::jsonb)
                        """,
                        body.tenant_id,
                        body.job_id,
                        current["state"],
                        client_id,
                        current["correlation_id"],
                        json.dumps({"execution_id": str(body.execution_id)}, separators=(",", ":"), sort_keys=True),
                    )
                assert row is not None
                return JobClaimResponse(
                    job=self._job_from_row(row, duplicate=duplicate),
                    lease_token=lease_token,
                    lease_expires_at=expires,
                    duplicate=duplicate,
                )

    async def get_job(self, tenant_id: str, job_id: UUID) -> AutomationJob:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM middleware_automation_jobs WHERE tenant_id=$1 AND job_id=$2",
                tenant_id,
                job_id,
            )
        if row is None:
            raise AutomationNotFound("automation job was not found")
        return self._job_from_row(row)

    async def _lease_row(
        self,
        conn: asyncpg.Connection,
        *,
        tenant_id: str,
        job_id: UUID,
        lease_token: str,
        execution_id: UUID,
        client_id: str,
    ) -> Mapping[str, Any]:
        row = await conn.fetchrow(
            """
            SELECT * FROM middleware_automation_jobs
            WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE
            """,
            tenant_id,
            job_id,
        )
        if row is None:
            raise AutomationNotFound("automation job was not found")
        if (
            row["lease_token_sha256"] != _token_digest(lease_token)
            or row["execution_id"] != execution_id
            or row["lease_client_id"] != client_id
            or row["lease_expires_at"] is None
            or row["lease_expires_at"] <= _utcnow()
            or row["state"] not in {
                "CLAIMED",
                "RUNNING",
                "WAITING_APPROVAL",
                "WAITING_TIMER",
                "WAITING_COMMAND",
            }
        ):
            raise AutomationConflict("active automation lease is required")
        return row

    async def heartbeat(
        self,
        job_id: UUID,
        body: HeartbeatRequest,
        *,
        client_id: str,
    ) -> AutomationJob:
        now = _utcnow()
        expires = now + timedelta(seconds=LEASE_SECONDS)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await self._lease_row(
                    conn,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    lease_token=body.lease_token,
                    execution_id=body.execution_id,
                    client_id=client_id,
                )
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_automation_jobs
                    SET state='RUNNING', lease_expires_at=$3,
                        resource_version=resource_version+1, updated_at=$4
                    WHERE tenant_id=$1 AND job_id=$2 RETURNING *
                    """,
                    body.tenant_id,
                    job_id,
                    expires,
                    now,
                )
                await conn.execute(
                    """
                    INSERT INTO middleware_automation_audit (
                        tenant_id,job_id,event_type,previous_state,new_state,
                        actor_id,correlation_id,safe_metadata
                    ) VALUES ($1,$2,'job.heartbeat',$3,'RUNNING',$4,$5,'{}'::jsonb)
                    """,
                    body.tenant_id,
                    job_id,
                    current["state"],
                    client_id,
                    body.correlation_id,
                )
        assert row is not None
        return self._job_from_row(row)

    async def record_step(
        self,
        job_id: UUID,
        body: StepRecord,
        *,
        client_id: str,
    ) -> StepEvidence:
        request_digest = _digest(
            {
                "execution_id": str(body.execution_id),
                "step_key": body.step_key,
                "step_state": body.step_state,
                "recorded_at": body.recorded_at.isoformat(),
                "safe_metadata": body.safe_metadata,
            }
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self._lease_row(
                    conn,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    lease_token=body.lease_token,
                    execution_id=body.execution_id,
                    client_id=client_id,
                )
                row = await conn.fetchrow(
                    """
                    INSERT INTO middleware_automation_job_steps (
                        tenant_id,job_id,execution_id,step_key,step_state,
                        idempotency_key,request_sha256,safe_metadata,recorded_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)
                    ON CONFLICT (tenant_id,job_id,idempotency_key) DO NOTHING
                    RETURNING id,job_id,execution_id,step_key,step_state,safe_metadata,recorded_at
                    """,
                    body.tenant_id,
                    job_id,
                    body.execution_id,
                    body.step_key,
                    body.step_state,
                    body.idempotency_key,
                    request_digest,
                    json.dumps(body.safe_metadata, separators=(",", ":"), sort_keys=True),
                    body.recorded_at,
                )
                duplicate = False
                if row is None:
                    row = await conn.fetchrow(
                        """
                        SELECT id,job_id,execution_id,step_key,step_state,
                               safe_metadata,recorded_at,request_sha256
                        FROM middleware_automation_job_steps
                        WHERE tenant_id=$1 AND job_id=$2 AND idempotency_key=$3
                        """,
                        body.tenant_id,
                        job_id,
                        body.idempotency_key,
                    )
                    if row is None or row["request_sha256"] != request_digest:
                        raise AutomationConflict("step idempotency key was reused with different content")
                    duplicate = True
                await conn.execute(
                    """
                    UPDATE middleware_automation_jobs
                    SET state='RUNNING',resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND job_id=$2
                    """,
                    body.tenant_id,
                    job_id,
                )
        assert row is not None
        return StepEvidence(
            evidence_id=row["id"],
            job_id=row["job_id"],
            execution_id=row["execution_id"],
            step_key=row["step_key"],
            step_state=row["step_state"],
            safe_metadata=_row_json(row["safe_metadata"]),
            recorded_at=row["recorded_at"],
            duplicate=duplicate,
        )

    async def _terminal_existing(
        self,
        current: Mapping[str, Any],
        *,
        idempotency_key: str,
        request_digest: str,
    ) -> AutomationJob | None:
        if current["terminal_idempotency_key"] is None:
            return None
        if (
            current["terminal_idempotency_key"] == idempotency_key
            and current["terminal_request_sha256"] == request_digest
        ):
            return self._job_from_row(current, duplicate=True)
        raise AutomationConflict("job already has a different terminal transition")

    async def complete(
        self,
        job_id: UUID,
        body: TerminalResult,
        *,
        client_id: str,
    ) -> AutomationJob:
        request_digest = _digest(
            {
                "execution_id": str(body.execution_id),
                "result_code": body.result_code,
                "safe_result": body.safe_result,
            }
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    "SELECT * FROM middleware_automation_jobs WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE",
                    body.tenant_id,
                    job_id,
                )
                if current is None:
                    raise AutomationNotFound("automation job was not found")
                replay = await self._terminal_existing(
                    current,
                    idempotency_key=body.idempotency_key,
                    request_digest=request_digest,
                )
                if replay is not None:
                    return replay
                await self._lease_row(
                    conn,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    lease_token=body.lease_token,
                    execution_id=body.execution_id,
                    client_id=client_id,
                )
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_automation_jobs
                    SET state='COMPLETED',result_code=$3,error_code=NULL,
                        safe_terminal_result=$4::jsonb,
                        terminal_idempotency_key=$5,terminal_request_sha256=$6,
                        lease_token_sha256=NULL,lease_expires_at=NULL,
                        resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND job_id=$2 RETURNING *
                    """,
                    body.tenant_id,
                    job_id,
                    body.result_code,
                    json.dumps(body.safe_result, separators=(",", ":"), sort_keys=True),
                    body.idempotency_key,
                    request_digest,
                )
                await conn.execute(
                    """
                    INSERT INTO middleware_automation_audit (
                        tenant_id,job_id,event_type,previous_state,new_state,
                        actor_id,correlation_id,safe_metadata
                    ) VALUES ($1,$2,'job.completed',$3,'COMPLETED',$4,$5,$6::jsonb)
                    """,
                    body.tenant_id,
                    job_id,
                    current["state"],
                    client_id,
                    body.correlation_id,
                    json.dumps({"result_code": body.result_code}, separators=(",", ":"), sort_keys=True),
                )
        assert row is not None
        return self._job_from_row(row)

    async def fail(
        self,
        job_id: UUID,
        body: FailureResult,
        *,
        client_id: str,
    ) -> AutomationJob:
        request_digest = _digest(
            {
                "execution_id": str(body.execution_id),
                "error_code": body.error_code,
                "retryable": body.retryable,
                "unknown_outcome": body.unknown_outcome,
                "safe_error": body.safe_error,
            }
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchrow(
                    "SELECT * FROM middleware_automation_jobs WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE",
                    body.tenant_id,
                    job_id,
                )
                if current is None:
                    raise AutomationNotFound("automation job was not found")
                replay = await self._terminal_existing(
                    current,
                    idempotency_key=body.idempotency_key,
                    request_digest=request_digest,
                )
                if replay is not None:
                    return replay
                await self._lease_row(
                    conn,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    lease_token=body.lease_token,
                    execution_id=body.execution_id,
                    client_id=client_id,
                )
                if body.unknown_outcome:
                    state: JobState = "DEAD_LETTER"
                elif body.retryable and current["attempt_count"] < current["max_attempts"]:
                    state = "RETRY_SCHEDULED"
                elif current["attempt_count"] >= current["max_attempts"]:
                    state = "DEAD_LETTER"
                else:
                    state = "FAILED_TERMINAL"
                delivery_token = secrets.token_urlsafe(32) if state == "RETRY_SCHEDULED" else None
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_automation_jobs
                    SET state=$3,result_code=NULL,error_code=$4,
                        safe_terminal_result=$5::jsonb,
                        terminal_idempotency_key=CASE WHEN $3='RETRY_SCHEDULED' THEN NULL ELSE $6 END,
                        terminal_request_sha256=CASE WHEN $3='RETRY_SCHEDULED' THEN NULL ELSE $7 END,
                        delivery_token_sha256=CASE WHEN $3='RETRY_SCHEDULED' THEN $8 ELSE delivery_token_sha256 END,
                        delivery_token_used_at=CASE WHEN $3='RETRY_SCHEDULED' THEN NULL ELSE delivery_token_used_at END,
                        lease_token_sha256=NULL,lease_client_id=CASE WHEN $3='RETRY_SCHEDULED' THEN NULL ELSE lease_client_id END,
                        execution_id=CASE WHEN $3='RETRY_SCHEDULED' THEN NULL ELSE execution_id END,
                        lease_expires_at=NULL,resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND job_id=$2 RETURNING *
                    """,
                    body.tenant_id,
                    job_id,
                    state,
                    body.error_code,
                    json.dumps(body.safe_error, separators=(",", ":"), sort_keys=True),
                    body.idempotency_key,
                    request_digest,
                    _token_digest(delivery_token) if delivery_token is not None else None,
                )
                if state == "RETRY_SCHEDULED":
                    generation = await conn.fetchval(
                        """
                        SELECT COALESCE(max(dispatch_generation),0)+1
                        FROM middleware_automation_dispatch_outbox
                        WHERE tenant_id=$1 AND job_id=$2
                        """,
                        body.tenant_id,
                        job_id,
                    )
                    wake = {
                        "job_id": str(job_id),
                        "workflow_key": current["workflow_key"],
                        "workflow_version": current["workflow_version"],
                        "correlation_id": current["correlation_id"],
                        "delivery_token": delivery_token,
                    }
                    await conn.execute(
                        """
                        INSERT INTO middleware_automation_dispatch_outbox (
                            tenant_id,job_id,dispatch_generation,workflow_key,workflow_version,
                            correlation_id,payload,state
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,'PENDING')
                        """,
                        body.tenant_id,
                        job_id,
                        generation,
                        current["workflow_key"],
                        current["workflow_version"],
                        current["correlation_id"],
                        json.dumps(wake, separators=(",", ":"), sort_keys=True),
                    )
                elif state == "DEAD_LETTER":
                    dead_letter_id = uuid5(NAMESPACE_URL, f"codestra-dead-letter:{body.tenant_id}:{job_id}")
                    fingerprint = _digest(
                        {
                            "tenant_id": body.tenant_id,
                            "job_id": str(job_id),
                            "workflow_key": current["workflow_key"],
                            "error_code": body.error_code,
                        }
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_automation_dead_letters (
                            tenant_id,dead_letter_id,job_id,workflow_key,workflow_family,
                            original_effect_fingerprint,safe_payload,state
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,'OPEN')
                        ON CONFLICT (tenant_id,dead_letter_id) DO NOTHING
                        """,
                        body.tenant_id,
                        dead_letter_id,
                        job_id,
                        current["workflow_key"],
                        current["workflow_family"],
                        fingerprint,
                        json.dumps(
                            {"error_code": body.error_code, "unknown_outcome": body.unknown_outcome},
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    )
                await conn.execute(
                    """
                    INSERT INTO middleware_automation_audit (
                        tenant_id,job_id,event_type,previous_state,new_state,
                        actor_id,correlation_id,safe_metadata
                    ) VALUES ($1,$2,'job.failed',$3,$4,$5,$6,$7::jsonb)
                    """,
                    body.tenant_id,
                    job_id,
                    current["state"],
                    state,
                    client_id,
                    body.correlation_id,
                    json.dumps(
                        {"error_code": body.error_code, "unknown_outcome": body.unknown_outcome},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
        assert row is not None
        return self._job_from_row(row)

    async def request_approval(
        self,
        body: ApprovalRequest,
        *,
        client_id: str,
        requested_by: str,
    ) -> ApprovalRecord:
        request_digest = _digest(
            {
                "job_id": str(body.job_id),
                "approval_type": body.approval_type,
                "summary": body.summary,
                "expires_at": body.expires_at.isoformat(),
            }
        )
        approval_id = uuid5(
            NAMESPACE_URL,
            f"codestra-approval:{body.tenant_id}:{body.job_id}:{body.idempotency_key}",
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                job = await conn.fetchrow(
                    "SELECT * FROM middleware_automation_jobs WHERE tenant_id=$1 AND job_id=$2 FOR UPDATE",
                    body.tenant_id,
                    body.job_id,
                )
                if job is None:
                    raise AutomationNotFound("automation job was not found")
                if job["expected_client_id"] != client_id:
                    raise AutomationAuthorizationDenied("client does not own the approval job family")
                row = await conn.fetchrow(
                    """
                    INSERT INTO middleware_automation_approvals (
                        tenant_id,approval_id,job_id,approval_type,summary,state,
                        requested_by,expires_at,idempotency_key,request_sha256
                    ) VALUES ($1,$2,$3,$4,$5,'PENDING',$6,$7,$8,$9)
                    ON CONFLICT (tenant_id,job_id,idempotency_key) DO NOTHING
                    RETURNING *
                    """,
                    body.tenant_id,
                    approval_id,
                    body.job_id,
                    body.approval_type,
                    body.summary,
                    requested_by,
                    body.expires_at,
                    body.idempotency_key,
                    request_digest,
                )
                duplicate = False
                if row is None:
                    row = await conn.fetchrow(
                        """
                        SELECT * FROM middleware_automation_approvals
                        WHERE tenant_id=$1 AND job_id=$2 AND idempotency_key=$3
                        """,
                        body.tenant_id,
                        body.job_id,
                        body.idempotency_key,
                    )
                    if row is None or row["request_sha256"] != request_digest:
                        raise AutomationConflict("approval idempotency key was reused with different content")
                    duplicate = True
                else:
                    await conn.execute(
                        """
                        UPDATE middleware_automation_jobs
                        SET state='WAITING_APPROVAL',resource_version=resource_version+1,updated_at=now()
                        WHERE tenant_id=$1 AND job_id=$2
                          AND state NOT IN ('COMPLETED','CANCELLED','FAILED_TERMINAL','DEAD_LETTER')
                        """,
                        body.tenant_id,
                        body.job_id,
                    )
        assert row is not None
        return self._approval_from_row(row, duplicate=duplicate)

    async def get_approval(self, tenant_id: str, approval_id: UUID) -> ApprovalRecord:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    UPDATE middleware_automation_approvals
                    SET state='EXPIRED',resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND approval_id=$2 AND state='PENDING' AND expires_at<=now()
                    """,
                    tenant_id,
                    approval_id,
                )
                row = await conn.fetchrow(
                    "SELECT * FROM middleware_automation_approvals WHERE tenant_id=$1 AND approval_id=$2",
                    tenant_id,
                    approval_id,
                )
        if row is None:
            raise AutomationNotFound("approval was not found")
        return self._approval_from_row(row)

    async def get_dead_letter(self, tenant_id: str, dead_letter_id: UUID) -> DeadLetterRecord:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM middleware_automation_dead_letters WHERE tenant_id=$1 AND dead_letter_id=$2",
                tenant_id,
                dead_letter_id,
            )
        if row is None:
            raise AutomationNotFound("dead letter was not found")
        return self._dead_from_row(row)

    async def replay_dead_letter(
        self,
        dead_letter_id: UUID,
        body: DeadLetterReplayRequest,
        *,
        client_id: str,
    ) -> AutomationJob:
        if client_id != "n8n-operations-automation":
            raise AutomationAuthorizationDenied("only operations automation may request replay")
        request_digest = _digest(body.model_dump(mode="json"))
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                prior = await conn.fetchrow(
                    """
                    SELECT request_sha256,response_payload FROM middleware_automation_replay_requests
                    WHERE tenant_id=$1 AND dead_letter_id=$2 AND idempotency_key=$3
                    """,
                    body.tenant_id,
                    dead_letter_id,
                    body.idempotency_key,
                )
                if prior is not None:
                    if prior["request_sha256"] != request_digest:
                        raise AutomationConflict("replay idempotency key was reused with different content")
                    return AutomationJob.model_validate(_row_json(prior["response_payload"])).model_copy(
                        update={"duplicate": True}
                    )
                dead = await conn.fetchrow(
                    """
                    SELECT * FROM middleware_automation_dead_letters
                    WHERE tenant_id=$1 AND dead_letter_id=$2 FOR UPDATE
                    """,
                    body.tenant_id,
                    dead_letter_id,
                )
                if dead is None:
                    raise AutomationNotFound("dead letter was not found")
                approval = await conn.fetchrow(
                    """
                    SELECT * FROM middleware_automation_approvals
                    WHERE tenant_id=$1 AND approval_id=$2 FOR UPDATE
                    """,
                    body.tenant_id,
                    body.approval_id,
                )
                if approval is None:
                    raise AutomationNotFound("approval was not found")
                if (
                    approval["job_id"] != dead["job_id"]
                    or approval["approval_type"] != "REPLAY"
                    or approval["state"] != "APPROVED"
                    or not approval["decided_by"]
                    or approval["decided_by"] == approval["requested_by"]
                    or approval["expires_at"] <= _utcnow()
                ):
                    raise AutomationAuthorizationDenied("protected non-self approval is required")
                if dead["resource_version"] != body.expected_version:
                    raise AutomationConflict("dead-letter expected_version is stale")
                if dead["original_effect_fingerprint"] != body.original_effect_fingerprint:
                    raise AutomationConflict("dead-letter effect fingerprint does not match")
                if dead["state"] != "OPEN":
                    raise AutomationConflict("dead letter is not open for replay")
                delivery_token = secrets.token_urlsafe(32)
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_automation_jobs
                    SET state='RETRY_SCHEDULED',delivery_token_sha256=$3,
                        delivery_token_used_at=NULL,lease_token_sha256=NULL,
                        lease_client_id=NULL,execution_id=NULL,lease_expires_at=NULL,
                        terminal_idempotency_key=NULL,terminal_request_sha256=NULL,
                        resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND job_id=$2 RETURNING *
                    """,
                    body.tenant_id,
                    dead["job_id"],
                    _token_digest(delivery_token),
                )
                if row is None:
                    raise AutomationNotFound("dead-letter job was not found")
                generation = await conn.fetchval(
                    """
                    SELECT COALESCE(max(dispatch_generation),0)+1
                    FROM middleware_automation_dispatch_outbox
                    WHERE tenant_id=$1 AND job_id=$2
                    """,
                    body.tenant_id,
                    dead["job_id"],
                )
                wake = {
                    "job_id": str(dead["job_id"]),
                    "workflow_key": dead["workflow_key"],
                    "workflow_version": row["workflow_version"],
                    "correlation_id": row["correlation_id"],
                    "delivery_token": delivery_token,
                }
                await conn.execute(
                    """
                    INSERT INTO middleware_automation_dispatch_outbox (
                        tenant_id,job_id,dispatch_generation,workflow_key,workflow_version,
                        correlation_id,payload,state
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,'PENDING')
                    """,
                    body.tenant_id,
                    dead["job_id"],
                    generation,
                    dead["workflow_key"],
                    row["workflow_version"],
                    row["correlation_id"],
                    json.dumps(wake, separators=(",", ":"), sort_keys=True),
                )
                await conn.execute(
                    """
                    UPDATE middleware_automation_dead_letters
                    SET state='REPLAY_REQUESTED',resource_version=resource_version+1,updated_at=now()
                    WHERE tenant_id=$1 AND dead_letter_id=$2
                    """,
                    body.tenant_id,
                    dead_letter_id,
                )
                response = self._job_from_row(row).model_dump(mode="json")
                await conn.execute(
                    """
                    INSERT INTO middleware_automation_replay_requests (
                        tenant_id,dead_letter_id,idempotency_key,request_sha256,response_payload
                    ) VALUES ($1,$2,$3,$4,$5::jsonb)
                    """,
                    body.tenant_id,
                    dead_letter_id,
                    body.idempotency_key,
                    request_digest,
                    json.dumps(response, separators=(",", ":"), sort_keys=True),
                )
        return self._job_from_row(row)

    async def reconcile(
        self,
        body: ReconciliationRequest,
        *,
        requested_by: str,
    ) -> ReconciliationRun:
        request_digest = _digest(
            {"mode": body.mode, "job_ids": [str(item) for item in body.job_ids]}
        )
        reconciliation_id = uuid5(
            NAMESPACE_URL,
            f"codestra-automation-reconcile:{body.tenant_id}:{body.idempotency_key}",
        )
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    """
                    SELECT * FROM middleware_automation_reconciliation_runs
                    WHERE tenant_id=$1 AND idempotency_key=$2
                    """,
                    body.tenant_id,
                    body.idempotency_key,
                )
                if existing is not None:
                    if existing["request_sha256"] != request_digest:
                        raise AutomationConflict("reconciliation idempotency key was reused")
                    result = _row_json(existing["result_payload"])
                    return ReconciliationRun.model_validate(result).model_copy(update={"duplicate": True})
                rows = await conn.fetch(
                    """
                    SELECT j.*,
                           EXISTS(
                             SELECT 1 FROM middleware_automation_dispatch_outbox d
                             WHERE d.tenant_id=j.tenant_id AND d.job_id=j.job_id
                               AND d.state IN ('PENDING','CLAIMED')
                           ) AS has_dispatch
                    FROM middleware_automation_jobs j
                    WHERE j.tenant_id=$1
                      AND ($2::uuid[] IS NULL OR j.job_id=ANY($2::uuid[]))
                    ORDER BY j.created_at,j.job_id
                    """,
                    body.tenant_id,
                    list(body.job_ids) if body.job_ids else None,
                )
                now = _utcnow()
                counts: dict[str, int] = {}
                expired = 0
                missing = 0
                plan: list[dict[str, Any]] = []
                for row in rows:
                    counts[row["state"]] = counts.get(row["state"], 0) + 1
                    if row["lease_expires_at"] is not None and row["lease_expires_at"] <= now:
                        expired += 1
                        if body.mode == "PLAN":
                            plan.append({"job_id": str(row["job_id"]), "action": "REQUEUE_EXPIRED_LEASE"})
                    if row["state"] in {"PENDING", "RETRY_SCHEDULED"} and not row["has_dispatch"]:
                        missing += 1
                        if body.mode == "PLAN":
                            plan.append({"job_id": str(row["job_id"]), "action": "RECREATE_DISPATCH"})
                run = ReconciliationRun(
                    reconciliation_id=reconciliation_id,
                    tenant_id=body.tenant_id,
                    mode=body.mode,
                    requested_by=requested_by,
                    inspected_jobs=len(rows),
                    state_counts=counts,
                    expired_leases=expired,
                    missing_dispatches=missing,
                    safe_plan=plan,
                    created_at=now,
                )
                inserted = await conn.fetchrow(
                    """
                    INSERT INTO middleware_automation_reconciliation_runs (
                        tenant_id,reconciliation_id,mode,requested_by,idempotency_key,
                        request_sha256,result_payload,created_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
                    ON CONFLICT (tenant_id,idempotency_key) DO NOTHING
                    RETURNING reconciliation_id
                    """,
                    body.tenant_id,
                    reconciliation_id,
                    body.mode,
                    requested_by,
                    body.idempotency_key,
                    request_digest,
                    json.dumps(run.model_dump(mode="json"), separators=(",", ":"), sort_keys=True),
                    now,
                )
                if inserted is None:
                    existing = await conn.fetchrow(
                        """
                        SELECT request_sha256,result_payload
                        FROM middleware_automation_reconciliation_runs
                        WHERE tenant_id=$1 AND idempotency_key=$2
                        """,
                        body.tenant_id,
                        body.idempotency_key,
                    )
                    if existing is None or existing["request_sha256"] != request_digest:
                        raise AutomationConflict("reconciliation idempotency key was reused")
                    return ReconciliationRun.model_validate(
                        _row_json(existing["result_payload"])
                    ).model_copy(update={"duplicate": True})
        return run


@dataclass
class AutomationService:
    store: AutomationStore
    policy: AutomationPolicy
    workflow_router: WorkflowRouter
    commands: Any
    umbrella_controls: Mapping[str, bool]

    async def ready(self) -> bool:
        return await self.store.ready()

    async def close(self) -> None:
        await self.store.close()

    async def accept_event(
        self,
        inbox: Any,
        envelope: EventEnvelope,
        *,
        producer_client_id: str,
        body_sha256: str,
        semantic_sha256: str,
    ) -> IngressResult:
        routes = self.workflow_router.for_event(envelope.event_type)
        if isinstance(inbox, PostgresInboxStore) and isinstance(self.store, PostgresAutomationStore):
            return await self._accept_postgres_event_atomic(
                inbox,
                envelope,
                routes,
                producer_client_id=producer_client_id,
                body_sha256=body_sha256,
                semantic_sha256=semantic_sha256,
            )
        result = await inbox.accept(
            envelope,
            producer_client_id=producer_client_id,
            body_sha256=body_sha256,
            semantic_sha256=semantic_sha256,
        )
        for route in routes:
            await self.store.enqueue_event(
                envelope,
                route,
                source_client_id=producer_client_id,
            )
        return result

    async def _accept_postgres_event_atomic(
        self,
        inbox: PostgresInboxStore,
        envelope: EventEnvelope,
        routes: tuple[WorkflowRoute, ...],
        *,
        producer_client_id: str,
        body_sha256: str,
        semantic_sha256: str,
    ) -> IngressResult:
        if not isinstance(self.store, PostgresAutomationStore):
            raise StorageError("atomic event acceptance requires the PostgreSQL automation store")
        payload = envelope.model_dump(mode="json")
        if canonical_payload_sha256(payload) != semantic_sha256:
            raise StorageError("semantic hash does not match canonical event payload")
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        now = _utcnow()
        async with inbox.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO middleware_inbox (
                        event_id,tenant_id,source_client_id,event_type,
                        body_sha256,semantic_sha256,idempotency_key,correlation_id,
                        payload,received_at,status
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'accepted')
                    ON CONFLICT DO NOTHING RETURNING event_id
                    """,
                    envelope.event_id,
                    envelope.tenant_id,
                    producer_client_id,
                    envelope.event_type,
                    body_sha256,
                    semantic_sha256,
                    envelope.idempotency_key,
                    envelope.correlation_id,
                    payload_json,
                    now,
                )
                duplicate = row is None
                if not duplicate:
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                        envelope.tenant_id,
                    )
                    previous = await conn.fetchrow(
                        """
                        SELECT tenant_sequence,entry_hash FROM middleware_event_ledger
                        WHERE tenant_id=$1 ORDER BY tenant_sequence DESC LIMIT 1
                        """,
                        envelope.tenant_id,
                    )
                    sequence = int(previous["tenant_sequence"]) + 1 if previous else 1
                    previous_hash = str(previous["entry_hash"]) if previous else ZERO_LEDGER_HASH
                    entry_hash = event_ledger_hash(
                        tenant_id=envelope.tenant_id,
                        tenant_sequence=sequence,
                        event_id=envelope.event_id,
                        semantic_sha256=semantic_sha256,
                        previous_entry_hash=previous_hash,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_event_ledger (
                            tenant_id,tenant_sequence,event_id,event_type,event_version,
                            source_client_id,correlation_id,causation_id,idempotency_key,
                            semantic_sha256,previous_entry_hash,entry_hash,payload
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
                        """,
                        envelope.tenant_id,
                        sequence,
                        envelope.event_id,
                        envelope.event_type,
                        envelope.event_version,
                        producer_client_id,
                        envelope.correlation_id,
                        envelope.causation_id,
                        envelope.idempotency_key,
                        semantic_sha256,
                        previous_hash,
                        entry_hash,
                        payload_json,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_outbox (
                            tenant_id,destination,event_type,payload,idempotency_key
                        ) VALUES ($1,$2,$3,$4::jsonb,$5)
                        """,
                        envelope.tenant_id,
                        NATS_JETSTREAM_DESTINATION,
                        envelope.event_type,
                        payload_json,
                        envelope.idempotency_key,
                    )
                else:
                    existing_rows = await conn.fetch(
                        """
                        SELECT event_id,tenant_id,idempotency_key,semantic_sha256,correlation_id
                        FROM middleware_inbox
                        WHERE (tenant_id=$1 AND event_id=$2)
                           OR (tenant_id=$1 AND idempotency_key=$3)
                        ORDER BY received_at ASC
                        """,
                        envelope.tenant_id,
                        envelope.event_id,
                        envelope.idempotency_key,
                    )
                    if not existing_rows:
                        raise StorageError("inbox conflict could not be reconciled")
                    identities = {(item["event_id"], item["idempotency_key"]) for item in existing_rows}
                    if len(identities) != 1 or existing_rows[0]["semantic_sha256"] != semantic_sha256:
                        raise ReplayConflict("event identity was reused with different semantic content")
                for route in routes:
                    await self.store.enqueue_event_on_connection(
                        conn,
                        envelope,
                        route,
                        source_client_id=producer_client_id,
                    )
                return IngressResult(
                    event_id=envelope.event_id,
                    tenant_id=envelope.tenant_id,
                    status="duplicate" if duplicate else "accepted",
                    duplicate=duplicate,
                    correlation_id=envelope.correlation_id,
                )

    def command_policy(self, command_type: str) -> Any:
        matches = [
            item for item in self.commands.policies.policies
            if command_type.startswith(item.prefix)
        ]
        if len(matches) != 1:
            raise AutomationCapabilityDisabled("command type has no unique durable adapter policy")
        return matches[0]

    def capability_state(self, capability: str) -> bool:
        if capability in self.umbrella_controls:
            return self.umbrella_controls.get(capability) is True
        return self.commands.policies.capabilities.get(capability) is True


async def _assert_store_lease(
    store: AutomationStore,
    job_id: UUID,
    body: LeaseMutation | AutomationCommandRequest,
    *,
    client_id: str,
) -> AutomationJob:
    if isinstance(store, MemoryAutomationStore):
        async with store._lock:
            raw = store._raw(body.tenant_id, job_id)
            store._active_lease(
                raw,
                lease_token=body.lease_token,
                execution_id=body.execution_id,
                client_id=client_id,
            )
            return store._job(raw)
    if isinstance(store, PostgresAutomationStore):
        async with store.pool.acquire() as conn:
            async with conn.transaction():
                row = await store._lease_row(
                    conn,
                    tenant_id=body.tenant_id,
                    job_id=job_id,
                    lease_token=body.lease_token,
                    execution_id=body.execution_id,
                    client_id=client_id,
                )
                return store._job_from_row(row)
    job = await store.get_job(body.tenant_id, job_id)
    if job.execution_id != body.execution_id or job.lease_client_id != client_id:
        raise AutomationConflict("active automation lease is required")
    return job


def _automation(request: Request) -> AutomationService:
    service = getattr(request.app.state.runtime, "automation", None)
    if service is None:
        raise StorageError("automation v2 service is unavailable")
    return service


async def _authorized(
    request: Request,
    service: AutomationService,
    required_scope: str,
) -> tuple[dict[str, Any], str, AutomationClientPolicy]:
    authorization = request.headers.get("Authorization", "")
    client_id = _peek_client_id(authorization)
    claims = await request.app.state.runtime.tokens.verify(
        authorization,
        expected_client_id=client_id,
        required_scope=required_scope,
    )
    try:
        policy = service.policy.authorize_token(claims, required_scope=required_scope)
    except AutomationAuthorizationError as exc:
        raise AutomationAuthorizationDenied(str(exc)) from exc
    return claims, client_id, policy


def _subject(claims: Mapping[str, Any]) -> str:
    value = claims.get("sub")
    if not isinstance(value, str) or not value:
        raise AutomationAuthorizationDenied("token subject is required")
    return value


def _authorize_family(
    service: AutomationService,
    claims: Mapping[str, Any],
    required_scope: str,
    workflow_family: str,
) -> AutomationClientPolicy:
    try:
        return service.policy.authorize_job_family(
            claims,
            required_scope=required_scope,
            workflow_family=workflow_family,
        )
    except AutomationAuthorizationError as exc:
        raise AutomationAuthorizationDenied(str(exc)) from exc


def _json_response(
    model: BaseModel,
    *,
    status_code: int = 200,
    correlation_id: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    merged = {"X-Correlation-ID": correlation_id, **dict(headers or {})}
    return JSONResponse(
        status_code=status_code,
        content=model.model_dump(mode="json"),
        headers=merged,
    )


v2_router = APIRouter(prefix="/v2/automation", tags=["automation-v2"])


@v2_router.post("/jobs/claim")
async def claim_automation_job(body: JobClaimRequest, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.job.claim")
    job = await service.store.get_job(body.tenant_id, body.job_id)
    _authorize_family(service, claims, "automation.job.claim", job.workflow_family)
    result = await service.store.claim(body, client_id=client_id)
    return _json_response(result, correlation_id=body.correlation_id)


@v2_router.get("/jobs/{job_id}")
async def read_automation_job(job_id: UUID, request: Request) -> JSONResponse:
    tenant_id, correlation_id = _read_headers(request)
    service = _automation(request)
    claims, _, _ = await _authorized(request, service, "automation.job.read")
    job = await service.store.get_job(tenant_id, job_id)
    _authorize_family(service, claims, "automation.job.read", job.workflow_family)
    return _json_response(job, correlation_id=correlation_id)


@v2_router.post("/jobs/{job_id}/heartbeat")
async def heartbeat_automation_job(job_id: UUID, body: HeartbeatRequest, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.job.heartbeat")
    job = await service.store.get_job(body.tenant_id, job_id)
    _authorize_family(service, claims, "automation.job.heartbeat", job.workflow_family)
    result = await service.store.heartbeat(job_id, body, client_id=client_id)
    return _json_response(result, correlation_id=body.correlation_id)


@v2_router.post("/jobs/{job_id}/steps", status_code=202)
async def record_automation_step(job_id: UUID, body: StepRecord, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.job.step.write")
    job = await service.store.get_job(body.tenant_id, job_id)
    _authorize_family(service, claims, "automation.job.step.write", job.workflow_family)
    evidence = await service.store.record_step(job_id, body, client_id=client_id)
    return _json_response(evidence, status_code=200 if evidence.duplicate else 202, correlation_id=body.correlation_id)


@v2_router.post("/jobs/{job_id}/complete")
async def complete_automation_job(job_id: UUID, body: TerminalResult, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.job.complete")
    job = await service.store.get_job(body.tenant_id, job_id)
    _authorize_family(service, claims, "automation.job.complete", job.workflow_family)
    result = await service.store.complete(job_id, body, client_id=client_id)
    return _json_response(result, correlation_id=body.correlation_id)


@v2_router.post("/jobs/{job_id}/fail")
async def fail_automation_job(job_id: UUID, body: FailureResult, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.job.fail")
    job = await service.store.get_job(body.tenant_id, job_id)
    _authorize_family(service, claims, "automation.job.fail", job.workflow_family)
    result = await service.store.fail(job_id, body, client_id=client_id)
    return _json_response(result, correlation_id=body.correlation_id)


@v2_router.post("/commands")
async def submit_automation_command(body: AutomationCommandRequest, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    authorization = request.headers.get("Authorization", "")
    client_id = _peek_client_id(authorization)
    try:
        command_family = service.policy.resolve_command_family(body.command_type)
    except AutomationAuthorizationError as exc:
        raise AutomationAuthorizationDenied(str(exc)) from exc
    if command_family.client_id != client_id:
        raise AutomationAuthorizationDenied("client does not own the command prefix")
    claims = await request.app.state.runtime.tokens.verify(
        authorization,
        expected_client_id=client_id,
        required_scope=command_family.scope,
    )
    try:
        service.policy.authorize_token(claims, required_scope=command_family.scope)
    except AutomationAuthorizationError as exc:
        raise AutomationAuthorizationDenied(str(exc)) from exc
    job = await _assert_store_lease(service.store, body.job_id, body, client_id=client_id)
    if job.workflow_key != body.workflow_key or job.workflow_version != body.workflow_version:
        raise AutomationConflict("command workflow identity does not match durable job")
    if job.event_id != body.event_id:
        raise AutomationConflict("command event_id does not match durable job")
    try:
        service.policy.authorize_command(
            claims,
            workflow_family=job.workflow_family,
            command_type=body.command_type,
        )
    except AutomationAuthorizationError as exc:
        raise AutomationAuthorizationDenied(str(exc)) from exc
    adapter_policy = service.command_policy(body.command_type)
    actor = str(job.actor_context.get("actor_id") or _subject(claims))
    command = CommandEnvelope(
        command_id=_command_id(body),
        command_type=body.command_type,
        command_version=body.command_version,
        target=adapter_policy.target,
        tenant_id=body.tenant_id,
        requested_by=actor,
        correlation_id=body.correlation_id,
        idempotency_key=body.idempotency_key,
        capability=adapter_policy.capability,
        payload=body.payload,
    )
    try:
        operation = await service.commands.submit(
            command,
            authenticated_subject=actor,
            authenticated_client_id=client_id,
        )
    except CommandCapabilityDisabled as exc:
        raise AutomationCapabilityDisabled(str(exc)) from exc
    status_code = 200 if operation.duplicate else 202
    return _json_response(
        operation,
        status_code=status_code,
        correlation_id=body.correlation_id,
        headers={"Location": f"/v2/automation/commands/{operation.command_id}"},
    )


@v2_router.get("/commands/{command_id}")
async def read_automation_command(command_id: UUID, request: Request) -> JSONResponse:
    tenant_id, correlation_id = _read_headers(request)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.command.read")
    operation: CommandOperation = await service.commands.get(tenant_id, command_id)
    family = service.policy.resolve_command_family(operation.command_type)
    if family.client_id != client_id:
        raise AutomationAuthorizationDenied("client does not own the command family")
    return _json_response(operation, correlation_id=correlation_id)


@v2_router.post("/approvals")
async def request_automation_approval(body: ApprovalRequest, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(request, service, "automation.approval.request")
    job = await service.store.get_job(body.tenant_id, body.job_id)
    _authorize_family(service, claims, "automation.approval.request", job.workflow_family)
    record = await service.store.request_approval(
        body,
        client_id=client_id,
        requested_by=_subject(claims),
    )
    return _json_response(
        record,
        status_code=200 if record.duplicate else 201,
        correlation_id=body.correlation_id,
        headers={"Location": f"/v2/automation/approvals/{record.approval_id}"},
    )


@v2_router.get("/approvals/{approval_id}")
async def read_automation_approval(approval_id: UUID, request: Request) -> JSONResponse:
    tenant_id, correlation_id = _read_headers(request)
    service = _automation(request)
    claims, _, _ = await _authorized(request, service, "automation.approval.read")
    record = await service.store.get_approval(tenant_id, approval_id)
    job = await service.store.get_job(tenant_id, record.job_id)
    _authorize_family(service, claims, "automation.approval.read", job.workflow_family)
    return _json_response(record, correlation_id=correlation_id)


@v2_router.post("/dead-letters/{dead_letter_id}/replay", status_code=202)
async def replay_automation_dead_letter(
    dead_letter_id: UUID,
    body: DeadLetterReplayRequest,
    request: Request,
) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    _, client_id, _ = await _authorized(
        request,
        service,
        "automation.operations.replay.request",
    )
    if not service.capability_state("DEAD_LETTER_REPLAY_ENABLED"):
        raise AutomationCapabilityDisabled("DEAD_LETTER_REPLAY_ENABLED is disabled")
    result = await service.store.replay_dead_letter(
        dead_letter_id,
        body,
        client_id=client_id,
    )
    return _json_response(result, status_code=202, correlation_id=body.correlation_id)


@v2_router.post("/jobs/reconcile")
async def reconcile_automation_jobs(body: ReconciliationRequest, request: Request) -> JSONResponse:
    _assert_header_body_mirror(request, body)
    service = _automation(request)
    claims, client_id, _ = await _authorized(
        request,
        service,
        "automation.operations.reconcile",
    )
    if client_id != "n8n-operations-automation":
        raise AutomationAuthorizationDenied("only operations automation may reconcile jobs")
    run = await service.store.reconcile(body, requested_by=_subject(claims))
    return _json_response(
        run,
        status_code=200 if run.duplicate else 202,
        correlation_id=body.correlation_id,
    )


@v2_router.get("/capabilities/{capability}")
async def read_automation_capability(capability: str, request: Request) -> JSONResponse:
    tenant_id, correlation_id = _read_headers(request)
    service = _automation(request)
    _, client_id, _ = await _authorized(request, service, "automation.capability.read")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,100}", capability):
        raise AutomationNotFound("capability was not found")
    known = capability in service.umbrella_controls or capability in service.commands.policies.capabilities
    if not known:
        raise AutomationNotFound("capability was not found")
    payload = {
        "tenant_id": tenant_id,
        "capability": capability,
        "effective": service.capability_state(capability),
        "client_id": client_id,
        "source": "middleware-runtime-policy",
        "external_effects_authorized": False,
    }
    return JSONResponse(
        status_code=200,
        content=payload,
        headers={"X-Correlation-ID": correlation_id},
    )
