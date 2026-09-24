"""Private restricted Controller API candidate."""

from functools import lru_cache
from pathlib import Path
from typing import Any, Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.core.controller import ApprovalTokens, ControllerError, RestrictedController

router = APIRouter(prefix="/api/v1", tags=["private-controller"])


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TaskCreate(StrictModel):
    title: str = Field(min_length=1, max_length=160)
    objective: str = Field(min_length=1, max_length=4000)
    workspace: str = Field(min_length=1, max_length=1024)


class PlanStep(StrictModel):
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)


class PlanCreate(StrictModel):
    steps: list[PlanStep] = Field(min_length=1, max_length=64)


class Approval(StrictModel):
    plan_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    server_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")


class ExecutionCreate(StrictModel):
    task_id: str
    server_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    workspace: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_token: str


class AgentRegistration(StrictModel):
    server_id: str = Field(pattern=r"^(middleware|qwen|web|vici)$")
    spiffe_id: str
    private_endpoint: str
    profile: str = Field(pattern=r"^(DEVELOPMENT|PRODUCTION_OBSERVER)$")
    certificate_sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    certificate_serial: str = Field(min_length=1, max_length=128)
    not_after: str = Field(min_length=20, max_length=40)
    rotation_owner: str = Field(min_length=1, max_length=128)
    public_listener: bool = False


def _required(value: str, name: str) -> str:
    if not value.strip():
        raise HTTPException(422, f"{name} is required")
    return value


Tenant = Annotated[str, Header(alias="X-Tenant-ID")]
RequestID = Annotated[str, Header(alias="X-Request-ID")]
CorrelationID = Annotated[str, Header(alias="X-Correlation-ID")]


@lru_cache
def controller() -> RestrictedController:
    secret_path = Path(settings.controller_approval_signing_key_file)
    secret = secret_path.read_bytes() if secret_path.is_file() else b""
    roots = tuple(
        Path(item.strip()) for item in settings.controller_workspace_allowlist.split(",")
        if item.strip()
    )
    return RestrictedController(ApprovalTokens(secret), roots)


def _controller() -> RestrictedController:
    try:
        return controller()
    except (OSError, ControllerError) as exc:
        raise HTTPException(503, "controller signing authority unavailable") from exc


def _error(exc: ControllerError) -> HTTPException:
    message = str(exc)
    if "not found" in message:
        return HTTPException(404, message)
    if "expired" in message or "invalid" in message or "replay" in message or "scope" in message:
        return HTTPException(401, message)
    if "conflict" in message or "state transition" in message or "approval does not" in message:
        return HTTPException(409, message)
    return HTTPException(403, message)


@router.post("/tasks", status_code=201)
async def create_task(body: TaskCreate, tenant_id: Tenant, request_id: RequestID,
                      correlation_id: CorrelationID,
                      idempotency_key: Annotated[str, Header(alias="Idempotency-Key")]):
    try:
        task, replay = _controller().create_task(
            body.model_dump(), tenant_id=_required(tenant_id, "tenant_id"),
            request_id=_required(request_id, "request_id"),
            correlation_id=_required(correlation_id, "correlation_id"),
            idempotency_key=_required(idempotency_key, "idempotency_key"),
        )
        return {**task.public(), "idempotent_replay": replay}
    except ControllerError as exc:
        raise _error(exc) from exc


@router.get("/tasks/{task_id}")
async def get_task(task_id: str, tenant_id: Tenant):
    try:
        return _controller().get_task(task_id, tenant_id).public()
    except ControllerError as exc:
        raise _error(exc) from exc


@router.post("/tasks/{task_id}/plan")
async def plan_task(task_id: str, body: PlanCreate, tenant_id: Tenant):
    try:
        return _controller().plan(
            task_id, tenant_id, [step.model_dump() for step in body.steps]
        ).public()
    except ControllerError as exc:
        raise _error(exc) from exc


@router.post("/tasks/{task_id}/approve")
async def approve_task(task_id: str, body: Approval, tenant_id: Tenant,
                       actor_id: Annotated[str, Header(alias="X-Actor-ID")]):
    try:
        task, token = _controller().approve(
            task_id, tenant_id, body.plan_hash, _required(actor_id, "actor_id"), body.server_id
        )
        return {**task.public(), "approval_token": token, "expires_in": _controller().tokens.ttl_seconds}
    except ControllerError as exc:
        raise _error(exc) from exc


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, tenant_id: Tenant):
    try:
        return _controller().cancel(task_id, tenant_id).public()
    except ControllerError as exc:
        raise _error(exc) from exc


@router.post("/executions", status_code=202)
@router.post("/tools/execute", status_code=202)
async def create_execution(body: ExecutionCreate, tenant_id: Tenant,
                           request_id: RequestID, correlation_id: CorrelationID):
    try:
        execution = _controller().execute(
            **body.model_dump(exclude={"approval_token"}), tenant_id=tenant_id,
            token=body.approval_token, request_id=request_id,
            correlation_id=correlation_id,
        )
        verification = _controller().verification(execution["execution_id"], tenant_id)
        return {**execution, "verification_code": verification["verification_code"]}
    except ControllerError as exc:
        raise _error(exc) from exc


@router.get("/executions/{execution_id}")
async def get_execution(execution_id: str, tenant_id: Tenant):
    record = _controller().executions.get(execution_id)
    if record is None or record["tenant_id"] != tenant_id:
        raise HTTPException(404, "execution not found")
    return record


@router.get("/verifications/{verification_code}")
async def get_verification(verification_code: str, tenant_id: Tenant):
    record = _controller().verifications.get(verification_code)
    if record is None or record["tenant_id"] != tenant_id:
        raise HTTPException(404, "verification not found")
    return record


@router.get("/audit/{task_id}")
async def get_audit(task_id: str, tenant_id: Tenant):
    _controller().get_task(task_id, tenant_id)
    return {"task_id": task_id, "records": _controller().audits.get(task_id, [])}


@router.post("/agents/register", status_code=201)
async def register_agent(body: AgentRegistration):
    try:
        return _controller().register_agent(body.model_dump())
    except ControllerError as exc:
        raise _error(exc) from exc


@router.get("/agents")
async def list_agents():
    return {"agents": list(_controller().agents.values())}
