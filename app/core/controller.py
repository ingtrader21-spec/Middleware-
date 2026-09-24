"""Restricted multi-server controller domain.

The controller authorizes typed tools.  It never accepts or constructs a shell
command and it does not execute tools locally.  A deployment-specific agent is
responsible for interpreting the signed, narrowly scoped execution envelope.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.automation import canonical_hash, redact


class ControllerError(ValueError):
    pass


class TaskState(str, Enum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    PLAN_READY = "PLAN_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DEAD_LETTER = "DEAD_LETTER"


ALLOWED_TOOLS = frozenset(
    {
        "inspect_workspace",
        "list_files",
        "read_file",
        "search_code",
        "git_status",
        "git_diff",
        "apply_patch",
        "run_formatter",
        "run_linter",
        "run_typecheck",
        "run_unit_tests",
        "run_integration_tests",
        "run_security_scan",
        "run_secret_scan",
        "build_project",
        "check_service",
        "read_sanitized_logs",
        "restart_development_service",
    }
)

AGENT_PROFILES = frozenset({"DEVELOPMENT", "PRODUCTION_OBSERVER"})
AGENT_IDENTITIES = {
    "middleware": "spiffe://codestra.internal/agent/middleware",
    "qwen": "spiffe://codestra.internal/agent/qwen",
    "web": "spiffe://codestra.internal/agent/web",
    "vici": "spiffe://codestra.internal/agent/vici",
}
AGENT_ENDPOINTS = {
    "middleware": "10.40.0.1:9443",
    "qwen": "10.40.0.4:9443",
    "web": "10.40.0.3:9443",
    "vici": "10.40.0.2:9444",
}

FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "command",
        "command_string",
        "shell",
        "shell_command",
        "private_key",
        "ca_private_key",
        "docker_socket",
        "database_url",
        "password",
        "secret",
        "token",
    }
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _reject_forbidden(value: Any, path: str = "arguments") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.lower() in FORBIDDEN_ARGUMENT_KEYS:
                raise ControllerError(f"forbidden field: {path}.{key}")
            _reject_forbidden(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_forbidden(nested, f"{path}[{index}]")


def validate_workspace(workspace: str, allowlist: tuple[Path, ...]) -> str:
    if not workspace.startswith("/") or ".." in Path(workspace).parts:
        raise ControllerError("workspace path denied")
    for root in allowlist:
        if workspace == str(root):
            return str(root)
    raise ControllerError("workspace is outside the allowlist")


class ApprovalTokens:
    """HMAC tokens bound to one task, tenant, server, workspace and tool set."""

    def __init__(self, secret: bytes, ttl_seconds: int = 300):
        if len(secret) < 32:
            raise ControllerError("approval signing key is unavailable")
        self._secret = secret
        self.ttl_seconds = min(max(ttl_seconds, 30), 600)
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def issue(self, claims: dict[str, Any], now: int | None = None) -> str:
        issued = int(time.time()) if now is None else now
        payload = {
            **claims,
            "iat": issued,
            "exp": issued + self.ttl_seconds,
            "jti": uuid4().hex,
            "version": 1,
        }
        encoded = _b64(_canonical(payload))
        signature = _b64(hmac.new(self._secret, encoded.encode(), hashlib.sha256).digest())
        return f"{encoded}.{signature}"

    def verify(
        self,
        token: str,
        *,
        task_id: str,
        tenant_id: str,
        server_id: str,
        workspace: str,
        tool: str,
        consume: bool,
        now: int | None = None,
    ) -> dict[str, Any]:
        try:
            encoded, supplied = token.split(".", 1)
            expected = _b64(hmac.new(self._secret, encoded.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(supplied, expected):
                raise ControllerError("approval token invalid")
            claims = json.loads(_unb64(encoded))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ControllerError("approval token invalid") from exc
        current = int(time.time()) if now is None else now
        if current < int(claims.get("iat", 0)) - 5 or current >= int(claims.get("exp", 0)):
            raise ControllerError("approval token expired")
        expected_claims = {
            "task_id": task_id,
            "tenant_id": tenant_id,
            "server_id": server_id,
            "workspace": workspace,
        }
        if any(claims.get(key) != value for key, value in expected_claims.items()):
            raise ControllerError("approval token scope denied")
        if tool not in claims.get("tools", []):
            raise ControllerError("approval token tool scope denied")
        if consume:
            jti = str(claims.get("jti", ""))
            with self._lock:
                if not jti or jti in self._consumed:
                    raise ControllerError("approval token replay rejected")
                self._consumed.add(jti)
        return claims


@dataclass
class TaskRecord:
    task_id: str
    tenant_id: str
    workspace: str
    title: str
    objective: str
    request_id: str
    correlation_id: str
    idempotency_key_hash: str
    request_hash: str
    state: TaskState = TaskState.CREATED
    plan: list[dict[str, Any]] = field(default_factory=list)
    plan_hash: str = ""
    approval_token: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "workspace": self.workspace,
            "title": self.title,
            "objective": self.objective,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "state": self.state,
            "plan": redact(self.plan),
            "plan_hash": self.plan_hash,
        }


class RestrictedController:
    """Thread-safe candidate store and policy engine.

    Persistence is deliberately behind this domain boundary so API and agent
    policy tests cannot bypass scope checks.  No production service is enabled
    by this candidate.
    """

    def __init__(self, tokens: ApprovalTokens, workspaces: tuple[Path, ...]):
        self.tokens = tokens
        self.workspaces = tuple(path.resolve() for path in workspaces)
        self.tasks: dict[str, TaskRecord] = {}
        self.executions: dict[str, dict[str, Any]] = {}
        self.verifications: dict[str, dict[str, Any]] = {}
        self.agents: dict[str, dict[str, Any]] = {}
        self.audits: dict[str, list[dict[str, Any]]] = {}
        self.idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._lock = threading.RLock()

    def register_agent(self, registration: dict[str, Any]) -> dict[str, Any]:
        server_id = str(registration["server_id"])
        expected_identity = AGENT_IDENTITIES.get(server_id)
        expected_endpoint = AGENT_ENDPOINTS.get(server_id)
        if expected_identity is None or expected_endpoint is None:
            raise ControllerError("unknown server identity")
        if registration["spiffe_id"] != expected_identity:
            raise ControllerError("agent SPIFFE identity denied")
        if registration["private_endpoint"] != expected_endpoint:
            raise ControllerError("agent private endpoint denied")
        if registration["profile"] not in AGENT_PROFILES:
            raise ControllerError("agent profile denied")
        fingerprint = str(registration["certificate_sha256"]).lower()
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise ControllerError("agent certificate fingerprint invalid")
        if registration["public_listener"]:
            raise ControllerError("public agent listener denied")
        record = {
            **registration,
            "certificate_sha256": fingerprint,
            "enabled": False,
            "registration_hash": canonical_hash(registration),
        }
        with self._lock:
            prior = self.agents.get(server_id)
            if prior and prior["registration_hash"] != record["registration_hash"]:
                raise ControllerError("agent registration conflict")
            self.agents[server_id] = record
        return record

    def _audit(self, task: TaskRecord, action: str, details: dict[str, Any]) -> None:
        safe = redact(details)
        previous = self.audits.get(task.task_id, [])
        previous_hash = previous[-1]["record_hash"] if previous else "0" * 64
        record = {
            "sequence": len(previous) + 1,
            "task_id": task.task_id,
            "tenant_id": task.tenant_id,
            "action": action,
            "details": safe,
            "previous_hash": previous_hash,
            "recorded_at": int(time.time()),
        }
        record["record_hash"] = canonical_hash(record)
        self.audits.setdefault(task.task_id, []).append(record)

    def _task(self, task_id: str, tenant_id: str) -> TaskRecord:
        task = self.tasks.get(task_id)
        if task is None or task.tenant_id != tenant_id:
            raise ControllerError("task not found")
        return task

    def create_task(self, body: dict[str, Any], *, tenant_id: str, request_id: str,
                    correlation_id: str, idempotency_key: str) -> tuple[TaskRecord, bool]:
        workspace = validate_workspace(body["workspace"], self.workspaces)
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        request_hash = canonical_hash(body)
        with self._lock:
            prior = self.idempotency.get((tenant_id, key_hash))
            if prior:
                prior_hash, task_id = prior
                if prior_hash != request_hash:
                    raise ControllerError("idempotency key conflict")
                return self._task(task_id, tenant_id), True
            task = TaskRecord(
                task_id=str(uuid4()), tenant_id=tenant_id, workspace=workspace,
                title=body["title"], objective=body["objective"], request_id=request_id,
                correlation_id=correlation_id, idempotency_key_hash=key_hash,
                request_hash=request_hash,
            )
            self.tasks[task.task_id] = task
            self.idempotency[(tenant_id, key_hash)] = (request_hash, task.task_id)
            self._audit(task, "task.created", {"request_id": request_id})
            return task, False

    def get_task(self, task_id: str, tenant_id: str) -> TaskRecord:
        with self._lock:
            return self._task(task_id, tenant_id)

    def plan(self, task_id: str, tenant_id: str, steps: list[dict[str, Any]]) -> TaskRecord:
        with self._lock:
            task = self._task(task_id, tenant_id)
            if task.state != TaskState.CREATED:
                raise ControllerError("invalid task state transition")
            for step in steps:
                tool = step.get("tool")
                if tool not in ALLOWED_TOOLS:
                    raise ControllerError("unknown tool")
                _reject_forbidden(step.get("arguments", {}))
            task.state = TaskState.PLANNING
            task.plan = steps
            task.plan_hash = canonical_hash(steps)
            task.state = TaskState.AWAITING_APPROVAL
            self._audit(task, "task.plan_ready", {"plan_hash": task.plan_hash})
            return task

    def approve(self, task_id: str, tenant_id: str, plan_hash: str,
                approver: str, server_id: str) -> tuple[TaskRecord, str]:
        with self._lock:
            task = self._task(task_id, tenant_id)
            if task.state != TaskState.AWAITING_APPROVAL or not hmac.compare_digest(
                task.plan_hash, plan_hash
            ):
                raise ControllerError("approval does not match current plan")
            tools = sorted({str(step["tool"]) for step in task.plan})
            token = self.tokens.issue({
                "task_id": task.task_id, "tenant_id": tenant_id,
                "server_id": server_id, "workspace": task.workspace,
                "tools": tools, "plan_hash": task.plan_hash,
                "approver_hash": hashlib.sha256(approver.encode()).hexdigest(),
            })
            task.state = TaskState.APPROVED
            task.approval_token = token
            self._audit(task, "task.approved", {"approver": "[REDACTED]", "server_id": server_id})
            return task, token

    def cancel(self, task_id: str, tenant_id: str) -> TaskRecord:
        with self._lock:
            task = self._task(task_id, tenant_id)
            if task.state in {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED, TaskState.DEAD_LETTER}:
                raise ControllerError("invalid task state transition")
            task.state = TaskState.CANCELLED
            self._audit(task, "task.cancelled", {})
            return task

    def execute(self, *, task_id: str, tenant_id: str, server_id: str, tool: str,
                workspace: str, arguments: dict[str, Any], token: str,
                request_id: str, correlation_id: str) -> dict[str, Any]:
        if tool not in ALLOWED_TOOLS:
            raise ControllerError("unknown tool")
        normalized = validate_workspace(workspace, self.workspaces)
        _reject_forbidden(arguments)
        with self._lock:
            task = self._task(task_id, tenant_id)
            if task.state not in {TaskState.APPROVED, TaskState.EXECUTING}:
                raise ControllerError("invalid task state transition")
            self.tokens.verify(token, task_id=task_id, tenant_id=tenant_id,
                               server_id=server_id, workspace=normalized, tool=tool,
                               consume=True)
            execution_id = str(uuid4())
            envelope = {
                "execution_id": execution_id, "task_id": task_id,
                "tenant_id": tenant_id, "server_id": server_id,
                "workspace": normalized, "tool": tool,
                "arguments": redact(arguments), "state": "AUTHORIZED",
                "request_id": request_id, "correlation_id": correlation_id,
                "plan_hash": task.plan_hash,
            }
            envelope["evidence_hash"] = canonical_hash(envelope)
            self.executions[execution_id] = envelope
            task.state = TaskState.EXECUTING
            self._audit(task, "execution.authorized", {
                "execution_id": execution_id, "tool": tool,
                "evidence_hash": envelope["evidence_hash"],
            })
            return envelope

    def verification(self, execution_id: str, tenant_id: str) -> dict[str, Any]:
        execution = self.executions.get(execution_id)
        if execution is None or execution["tenant_id"] != tenant_id:
            raise ControllerError("execution not found")
        code = "VRF-" + secrets.token_hex(12)
        record = {
            "verification_code": code, "execution_id": execution_id,
            "task_id": execution["task_id"], "tenant_id": tenant_id,
            "checks": {name: "PENDING" for name in (
                "PATCH_APPLIES", "FORMAT", "LINT", "TYPECHECK", "BUILD",
                "UNIT_TESTS", "INTEGRATION_TESTS", "MIGRATION_TEST",
                "SECURITY_SCAN", "SECRET_SCAN", "API_CONTRACT_TEST",
                "REVIEW_BLOCKERS", "UNEXPECTED_FILES_CHANGED",
            )},
            "evidence_hash": execution["evidence_hash"],
        }
        record["signature"] = hmac.new(
            self.tokens._secret, _canonical(record), hashlib.sha256  # noqa: SLF001
        ).hexdigest()
        self.verifications[code] = record
        return record
