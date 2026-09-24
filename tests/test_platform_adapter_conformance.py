"""One conformance suite for every adapter the kernel can register.

An adapter is V3-ready only when it passes this suite: configuration,
capabilities, readiness, execute success / validation failure / provider
auth failure / timeout before effect / ambiguous timeout, readback matched /
mismatch / unavailable, cancel supported or explicitly UNSUPPORTED,
reconcile, normalized errors, secret redaction, correlation and idempotency
propagation, tenant isolation, and the "never reads the environment, never
opens a client" rules.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.commands import CommandEnvelope, CommandOperation, CommandState
from app.platform.adapter import (
    ADAPTER_METHODS,
    AdapterConfigurationError,
    AdapterContext,
    AdapterResult,
    ErrorClass,
    Outcome,
    ReadbackStatus,
    assert_adapter,
)
from app.platform.adapters.fixtures import development_fixtures
from app.platform.adapters.providers import CRM_BRIDGE_COMMANDS, LegacyBridge, OdooAdapter
from app.platform.registry import AdapterRegistry
from app.platform.runtime import command_policies

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-19T00:00:00+00:00"


# ----------------------------------------------------------------------------
# fakes for the provider bridges
# ----------------------------------------------------------------------------
@dataclass
class ActivityResult:
    status: str
    detail: str = ""
    provider_operation_id: str | None = None
    readback_evidence: dict[str, Any] | None = None


class ProviderAuthError(RuntimeError):
    pass


class FakeLegacy:
    """A legacy execute/readback transport with scripted behaviour."""

    def __init__(self) -> None:
        self.env = {"KLYROW_EMAIL_API_BASE_URL": "https://klyrow.invalid", "KLYROW_EMAIL_MTLS_CA_FILE": "ca", "KLYROW_EMAIL_MTLS_CERT_FILE": "cert", "KLYROW_EMAIL_MTLS_KEY_FILE": "key"}
        self.requests: list[Any] = []
        self.readbacks: list[Any] = []
        self.behaviour = "accepted"
        self.readback_status = "matched"

    async def execute(self, request: Any) -> ActivityResult:
        self.requests.append(request)
        if self.behaviour == "auth":
            raise ProviderAuthError("401 from provider")
        if self.behaviour == "connect_timeout":
            raise httpx.ConnectTimeout("connect timed out")
        if self.behaviour == "read_timeout":
            raise httpx.ReadTimeout("read timed out")
        if self.behaviour == "rejected":
            return ActivityResult("rejected", "provider refused", None)
        return ActivityResult("accepted", "queued", provider_operation_id=f"msg-{request.command_id}")

    async def readback(self, request: Any) -> ActivityResult:
        self.readbacks.append(request)
        if self.readback_status == "unavailable":
            raise httpx.ConnectError("provider down")
        return ActivityResult(self.readback_status, "read back", provider_operation_id=f"msg-{request.command_id}", readback_evidence={"status": self.readback_status, "api_key": "should-be-redacted"})


class FakeCrmBridge:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.configured_tenant_id = "TEST_SYN"
        self.status_code = 201
        self.raise_error: Exception | None = None
        self.records: dict[int, dict[str, Any]] = {}
        self.children: dict[str, list[dict[str, Any]]] = {}

    def __getattr__(self, name: str):
        async def method(*args: Any, **kwargs: Any):
            self.calls.append((name, args, kwargs))
            if self.raise_error:
                raise self.raise_error
            from app.adapters.odoo.crm_bridge_client import BridgeResponse

            if name.startswith("get_"):
                identifier = args[0]
                if identifier in self.records:
                    return BridgeResponse(200, self.records[identifier])
                from app.adapters.odoo.crm_bridge_client import CrmBridgeNotFound

                raise CrmBridgeNotFound(str(identifier))
            if name in {"list_notes", "list_tasks"}:
                items = [row for row in self.children.get(name.split("_", 1)[1], []) if row["profile_id"] == args[0]]
                return BridgeResponse(200, {"items": [{k: v for k, v in row.items() if k != "profile_id"} for row in items]})
            body: dict[str, Any]
            if "contact" in name:
                body = {"profile_id": 5}
            elif "ticket" in name:
                body = {"ticket_id": 7}
            elif "opportunity" in name:
                body = {"external_id": "opp-1"}
            elif name == "create_note":  # {note_id, profile_id}, like the bridge
                body = {"note_id": 3, "profile_id": args[0]}
                self.children.setdefault("notes", []).append({"note_id": 3, "profile_id": args[0], **args[1]})
            elif name == "update_note":  # {note_id, body}: no parent in the answer
                for row in self.children.get("notes", []):
                    if row["note_id"] == args[0]:
                        row.update(args[1])
                body = {"note_id": args[0], "body": args[1].get("body")}
            elif name == "create_task":  # {task_id, profile_id, status}
                body = {"task_id": 9, "profile_id": args[0], "status": "scheduled"}
                self.children.setdefault("tasks", []).append({"task_id": 9, "profile_id": args[0], **args[1]})
            elif name == "update_task":  # {task_id, summary}: no parent in the answer
                body = {"task_id": args[0], "summary": args[1].get("summary")}
            elif name == "complete_task":  # the activity is unlinked once completed
                self.children["tasks"] = [row for row in self.children.get("tasks", []) if row["task_id"] != args[0]]
                body = {"task_id": args[0], "profile_id": 5, "status": "completed"}
            else:
                body = {"note_id": 3}
            if name.startswith("create_contact"):
                self.records[5] = {"profile_id": 5, **(args[0] if args else {})}
            if name.startswith("create_ticket"):
                self.records[7] = {"ticket_id": 7}
            return BridgeResponse(self.status_code, body)

        return method


def klyrow_bridge() -> tuple[LegacyBridge, FakeLegacy]:
    legacy = FakeLegacy()
    bridge = LegacyBridge(
        adapter_id="klyrow-email",
        provider_family="email",
        connector_ids=("klyrow-email",),
        served_capabilities=("EMAIL_DELIVERY",),
        legacy=legacy,
        supported_command_types=frozenset({"email.message.send.v1"}),
        rejected_errors=(ProviderAuthError,),
        required_settings=("KLYROW_EMAIL_API_BASE_URL",),
    )
    return bridge, legacy


def odoo_bridge() -> tuple[OdooAdapter, FakeCrmBridge]:
    crm = FakeCrmBridge()
    adapter = OdooAdapter(crm_bridge=crm, supported_command_types=frozenset(CRM_BRIDGE_COMMANDS))
    return adapter, crm


@dataclass
class Subject:
    adapter: Any
    command_type: str
    target: str
    capability: str
    payload: dict[str, Any]
    legacy: FakeLegacy | None = None
    crm: FakeCrmBridge | None = None


def subjects() -> list[Subject]:
    rows: list[Subject] = []
    prefixes = {
        "test-syn": ("test.syn.execute.v1", "test-syn", "TEST_SYN_EXECUTE"),
        "odoo-fixture": ("crm.contact.create.v1", "odoo-19", "ODOO_WRITE"),
        "email-fixture": ("email.message.send.v1", "klyrow-email", "EMAIL_DELIVERY"),
        "sms-fixture": ("sms.message.submit.v1", "telnexa-sms", "SMS_DELIVERY"),
        "telephony-fixture": ("telephony-internal.calls.originate", "vicidial-restricted", "INTERNAL_TELEPHONY_CALLS"),
        "crawler-fixture": ("crawler.job.start.v1", "kyqra-crawler", "CRAWLER_EXECUTION"),
        "social-fixture": ("social.publication.publish.v1", "postly-social", "SOCIAL_PUBLISH"),
        "provisioning-fixture": ("provisioning.identity.create.v1", "provisioning-service", "PROVISIONING_WRITE"),
        "n8n-fixture": ("automation.workflow.submit.v1", "n8n-automation", "N8N_WORKFLOW_DISPATCH"),
    }
    for adapter in development_fixtures():
        command_type, target, capability = prefixes[adapter.adapter_id]
        rows.append(Subject(adapter, command_type, target, capability, {"probe": True}))
    bridge, legacy = klyrow_bridge()
    rows.append(Subject(bridge, "email.message.send.v1", "klyrow-email", "EMAIL_DELIVERY", {"to": "x@example.invalid"}, legacy=legacy))
    odoo, crm = odoo_bridge()
    rows.append(Subject(odoo, "crm.contact.create.v1", "odoo-19", "ODOO_WRITE", {"record": {"name": "Jane"}}, crm=crm))
    return rows


SUBJECTS = subjects()
IDS = [row.adapter.adapter_id for row in SUBJECTS]


def fresh(index: int) -> Subject:
    return subjects()[index]


def envelope(subject: Subject, **updates: Any) -> CommandEnvelope:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": subject.command_type,
        "command_version": "1.0",
        "target": subject.target,
        "tenant_id": "TEST_SYN",
        "requested_by": "user-1",
        "correlation_id": "corr-" + uuid4().hex[:8],
        "idempotency_key": "idem-" + uuid4().hex,
        "capability": subject.capability,
        "payload": dict(subject.payload),
    }
    value.update(updates)
    return CommandEnvelope.model_validate(value)


def operation(command: CommandEnvelope, *, state: CommandState = "accepted", provider_operation_id: str | None = None) -> CommandOperation:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return CommandOperation(**command.model_dump(exclude={"payload"}), state=state, created_at=now, updated_at=now, provider_operation_id=provider_operation_id)


def context(command: CommandEnvelope, *, timeout: float = 5.0, attempt: int = 1) -> AdapterContext:
    return AdapterContext(
        tenant_id=command.tenant_id,
        command_id=str(command.command_id),
        correlation_id=command.correlation_id,
        attempt=attempt,
        timeout_seconds=timeout,
        environment="test",
        deployment_sha="0" * 40,
        trace_context={"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01"},
        payload=command.payload,
    )


# ----------------------------------------------------------------------------
# contract shape
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("index", range(len(SUBJECTS)), ids=IDS)
def test_adapter_implements_the_contract_and_validates_configuration(index: int) -> None:
    subject = fresh(index)
    adapter = assert_adapter(subject.adapter)
    adapter.validate_config()
    advertised = adapter.capabilities()
    assert advertised.adapter_id == adapter.adapter_id
    assert subject.target in advertised.connector_ids
    assert subject.capability in advertised.capabilities
    assert all(callable(getattr(adapter, name)) for name in ADAPTER_METHODS)


def test_bridge_configuration_fails_closed() -> None:
    bridge, legacy = klyrow_bridge()
    legacy.env.pop("KLYROW_EMAIL_API_BASE_URL")
    with pytest.raises(AdapterConfigurationError, match="required configuration missing"):
        bridge.validate_config()
    with pytest.raises(AdapterConfigurationError):
        OdooAdapter().validate_config()


@pytest.mark.parametrize("index", range(len(SUBJECTS)), ids=IDS)
def test_adapter_registers_and_owns_exactly_its_prefixes(index: int, test_settings) -> None:
    subject = fresh(index)
    registry = AdapterRegistry(command_policies(test_settings))
    registry.register(subject.adapter)
    ownership = registry.ownership(subject.command_type)
    assert ownership is not None and ownership.adapter_id == subject.adapter.adapter_id


# ----------------------------------------------------------------------------
# readiness / execute / readback / reconcile / cancel
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(len(SUBJECTS)), ids=IDS)
async def test_readiness_execute_success_and_matched_readback(index: int) -> None:
    subject = fresh(index)
    command = envelope(subject)
    ctx = context(command)
    assert (await subject.adapter.readiness(ctx)).ready is True
    result = await subject.adapter.execute(command, ctx)
    assert result.outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}, result
    assert result.provider_operation_id
    op = operation(command, provider_operation_id=result.provider_operation_id)
    readback = await subject.adapter.readback(op, ctx)
    assert readback.status is ReadbackStatus.MATCHED, readback
    reconciled = await subject.adapter.reconcile(op, ctx)
    assert reconciled.status is ReadbackStatus.MATCHED
    # correlation / idempotency propagation
    assert ctx.outbound_headers()["X-Correlation-ID"] == command.correlation_id
    assert ctx.outbound_headers()["traceparent"].startswith("00-")
    if subject.legacy is not None:
        request = subject.legacy.requests[0]
        assert request.correlation_id == command.correlation_id
        assert request.idempotency_key == command.idempotency_key
        assert request.tenant_id == command.tenant_id
    if subject.crm is not None:
        name, args, kwargs = subject.crm.calls[0]
        assert kwargs["correlation_id"] == command.correlation_id
        assert kwargs["idempotency_key"] == command.idempotency_key


BRIDGE_INDEXES = [index for index, subject in enumerate(SUBJECTS) if subject.legacy is not None or subject.crm is not None]


@pytest.mark.asyncio
@pytest.mark.parametrize("index", BRIDGE_INDEXES, ids=[IDS[index] for index in BRIDGE_INDEXES])
async def test_execute_validation_failure_is_explicit(index: int) -> None:
    """Provider bridges refuse a command type they do not implement (the
    no-effect fixtures accept every command of their family by design)."""
    subject = fresh(index)
    command = envelope(subject, command_type=subject.command_type.rsplit(".", 1)[0] + ".unsupported-operation.v9")
    result = await subject.adapter.execute(command, context(command))
    assert result.outcome in {Outcome.UNSUPPORTED, Outcome.REJECTED}
    assert result.error_class in {ErrorClass.UNSUPPORTED, ErrorClass.NON_RETRYABLE}


@pytest.mark.asyncio
async def test_bridge_classifies_provider_auth_and_timeouts() -> None:
    bridge, legacy = klyrow_bridge()
    command = envelope(SUBJECTS[-2])
    legacy.behaviour = "auth"
    assert (await bridge.execute(command, context(command))).outcome is Outcome.REJECTED
    legacy.behaviour = "connect_timeout"
    before = await bridge.execute(command, context(command))
    assert before.outcome is Outcome.TRANSIENT and before.error_class is ErrorClass.RETRYABLE_BEFORE_EFFECT
    legacy.behaviour = "read_timeout"
    ambiguous = await bridge.execute(command, context(command))
    assert ambiguous.outcome is Outcome.UNKNOWN and ambiguous.error_class is ErrorClass.AMBIGUOUS
    legacy.behaviour = "rejected"
    assert (await bridge.execute(command, context(command))).outcome is Outcome.REJECTED
    assert bridge.classify_error(httpx.ConnectError("x")) is ErrorClass.RETRYABLE_BEFORE_EFFECT
    assert bridge.classify_error(httpx.ReadTimeout("x")) is ErrorClass.AMBIGUOUS
    assert bridge.classify_error(RuntimeError("x")) is ErrorClass.AMBIGUOUS
    assert bridge.classify_error(ValueError("x")) is ErrorClass.NON_RETRYABLE


@pytest.mark.asyncio
async def test_bridge_readback_mismatch_and_unavailable() -> None:
    bridge, legacy = klyrow_bridge()
    command = envelope(SUBJECTS[-2])
    op = operation(command, provider_operation_id="msg-1")
    legacy.readback_status = "mismatch"
    assert (await bridge.readback(op, context(command))).status is ReadbackStatus.MISMATCH
    legacy.readback_status = "pending"
    assert (await bridge.readback(op, context(command))).status is ReadbackStatus.UNAVAILABLE
    legacy.readback_status = "unavailable"
    assert (await bridge.readback(op, context(command))).status is ReadbackStatus.UNAVAILABLE
    legacy.readback_status = "matched"
    matched = await bridge.readback(op, context(command))
    assert matched.evidence["api_key"] == "[REDACTED]"  # secret redaction of provider evidence


@pytest.mark.asyncio
async def test_odoo_bridge_readback_tenant_binding_and_ambiguity() -> None:
    adapter, crm = odoo_bridge()
    command = envelope(SUBJECTS[-1])
    result = await adapter.execute(command, context(command))
    assert result.outcome is Outcome.ACCEPTED and result.provider_operation_id == "profile_id:5"
    op = operation(command, provider_operation_id=result.provider_operation_id)
    assert (await adapter.readback(op, context(command))).status is ReadbackStatus.MATCHED
    crm.records.clear()
    assert (await adapter.readback(op, context(command))).status is ReadbackStatus.NOT_FOUND
    foreign = envelope(SUBJECTS[-1], tenant_id="tenant-b")
    denied = await adapter.execute(foreign, context(foreign))
    assert denied.outcome is Outcome.REJECTED and denied.safe_error_code == "crm_bridge_tenant_mismatch"
    from app.adapters.odoo.crm_bridge_client import CrmBridgeUnavailable

    crm.raise_error = CrmBridgeUnavailable("502")
    assert (await adapter.execute(command, context(command))).outcome is Outcome.UNKNOWN
    crm.raise_error = httpx.ConnectError("refused")
    assert (await adapter.execute(command, context(command))).outcome is Outcome.TRANSIENT
    note = envelope(SUBJECTS[-1], command_type="crm.note.create.v1", payload={"record": {"body": "x"}})
    crm.raise_error = None
    missing = await adapter.execute(note, context(note))
    assert missing.outcome is Outcome.REJECTED and missing.safe_error_code == "missing_contact_id"


@pytest.mark.asyncio
async def test_odoo_notes_and_tasks_read_back_through_the_parent_profile_list() -> None:
    """Notes/tasks have no GET-by-id on the bridge: create/update read back as
    'listed under the parent profile with the requested fields'; a completed
    task reads back as 'gone' (Odoo unlinks completed activities)."""
    adapter, crm = odoo_bridge()
    note = envelope(SUBJECTS[-1], command_type="crm.note.create.v1", payload={"contact_id": 5, "record": {"body": "hello"}})
    created = await adapter.execute(note, context(note))
    assert created.outcome is Outcome.ACCEPTED and created.provider_operation_id == "note_id:3@profile_id:5"
    listed = await adapter.readback(operation(note, provider_operation_id=created.provider_operation_id), context(note))
    assert listed.status is ReadbackStatus.MATCHED and listed.evidence == {"note_id": "3", "profile_id": "5", "listed": True}

    # update: the answer carries no parent, the payload's contact_id does; the
    # list's body must agree with the requested record
    update = envelope(SUBJECTS[-1], command_type="crm.note.update.v1", payload={"contact_id": 5, "note_id": 3, "record": {"body": "edited"}})
    updated = await adapter.execute(update, context(update))
    assert updated.provider_operation_id == "note_id:3"
    assert (await adapter.readback(operation(update, provider_operation_id="note_id:3"), context(update))).status is ReadbackStatus.MATCHED
    crm.children["notes"][0]["body"] = "another edit"
    drifted = await adapter.readback(operation(update, provider_operation_id="note_id:3"), context(update))
    assert drifted.status is ReadbackStatus.MISMATCH and drifted.evidence["drift"] == ["body"]

    task = envelope(SUBJECTS[-1], command_type="crm.task.create.v1", payload={"contact_id": 5, "record": {"summary": "call back"}})
    created_task = await adapter.execute(task, context(task))
    assert created_task.provider_operation_id == "task_id:9@profile_id:5"
    assert (await adapter.readback(operation(task, provider_operation_id=created_task.provider_operation_id), context(task))).status is ReadbackStatus.MATCHED

    # task.update carries no parent at all today: explicit UNSUPPORTED, never a silent completion
    task_update = envelope(SUBJECTS[-1], command_type="crm.task.update.v1", payload={"task_id": 9, "record": {"summary": "call back today"}})
    assert (await adapter.execute(task_update, context(task_update))).provider_operation_id == "task_id:9"
    unsupported = await adapter.readback(operation(task_update, provider_operation_id="task_id:9"), context(task_update))
    assert unsupported.status is ReadbackStatus.UNSUPPORTED and unsupported.safe_error_code == "crm_parent_profile_unknown"

    # complete: the bridge takes the (empty) feedback record; readback = the activity is gone
    complete = envelope(SUBJECTS[-1], command_type="crm.task.complete.v1", payload={"task_id": 9, "record": {}})
    completed = await adapter.execute(complete, context(complete))
    assert completed.outcome is Outcome.ACCEPTED and completed.provider_operation_id == "task_id:9@profile_id:5"
    assert crm.calls[-1][0] == "complete_task" and crm.calls[-1][1] == (9, {})
    gone = await adapter.readback(operation(complete, provider_operation_id=completed.provider_operation_id), context(complete))
    assert gone.status is ReadbackStatus.MATCHED and gone.evidence["listed"] is False
    crm.children.setdefault("tasks", []).append({"task_id": 9, "profile_id": 5, "summary": "still open"})
    assert (await adapter.readback(operation(complete, provider_operation_id=completed.provider_operation_id), context(complete))).status is ReadbackStatus.MISMATCH

    # a note that vanished from the parent list is NOT_FOUND (safe to re-execute), a bridge outage is UNAVAILABLE
    crm.children["notes"].clear()
    assert (await adapter.readback(operation(note, provider_operation_id=created.provider_operation_id), context(note))).status is ReadbackStatus.NOT_FOUND
    from app.adapters.odoo.crm_bridge_client import CrmBridgeUnavailable

    crm.raise_error = CrmBridgeUnavailable("503")
    assert (await adapter.readback(operation(note, provider_operation_id=created.provider_operation_id), context(note))).status is ReadbackStatus.UNAVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(len(SUBJECTS)), ids=IDS)
async def test_cancel_and_status_are_supported_or_explicitly_unsupported(index: int) -> None:
    subject = fresh(index)
    command = envelope(subject)
    op = operation(command, provider_operation_id="ref-1")
    advertised = subject.adapter.capabilities()
    cancel = await subject.adapter.cancel(op, context(command))
    if advertised.supports_cancel:
        assert cancel.outcome is Outcome.CANCELLED
    else:
        assert cancel.outcome is Outcome.UNSUPPORTED and cancel.error_class is ErrorClass.UNSUPPORTED
    status = await subject.adapter.status(op, context(command))
    if advertised.supports_status:
        assert status.outcome is not Outcome.UNSUPPORTED
    else:
        assert status.outcome is Outcome.UNSUPPORTED


@pytest.mark.parametrize("index", range(len(SUBJECTS)), ids=IDS)
def test_normalize_and_redact(index: int) -> None:
    subject = fresh(index)
    normalized = subject.adapter.normalize_result(AdapterResult(Outcome.ACCEPTED, provider_operation_id="x"))
    assert normalized.outcome is Outcome.ACCEPTED
    garbage = subject.adapter.normalize_result(object())
    assert garbage.outcome in {Outcome.UNKNOWN, Outcome.REJECTED}
    redacted = subject.adapter.redact({"authorization": "Bearer x", "nested": {"client_secret": "s"}, "ok": 1})
    assert redacted["authorization"] == "[REDACTED]" and redacted["nested"]["client_secret"] == "[REDACTED]" and redacted["ok"] == 1


# ----------------------------------------------------------------------------
# static rules: no environment reads, no pools, no per-call clients
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("module", sorted((ROOT / "app" / "platform").rglob("*.py")), ids=lambda path: path.name)
def test_platform_modules_never_read_the_environment_or_open_infrastructure(module: Path) -> None:
    source = module.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_calls = {"getenv", "create_pool", "from_url", "PyJWKClient", "create_engine", "create_async_engine"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            raise AssertionError(f"{module.name} reads os.environ")
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            assert name not in forbidden_calls, f"{module.name} calls {name}"
            if name == "AsyncClient" and module.name != "runtime.py":
                raise AssertionError(f"{module.name} constructs an httpx.AsyncClient")


def test_adapter_context_carries_the_shared_client_not_a_new_one() -> None:
    signature = inspect.signature(AdapterContext)
    assert "http" in signature.parameters
