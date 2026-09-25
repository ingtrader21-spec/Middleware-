"""The production no-effect rehearsal of the V3 command kernel.

One rehearsal proves, against the *running* process and without a single
provider effect, that the deployment is the one it claims to be and that
every kernel stage is healthy and fail-closed:

* ``source_identity`` / ``schema_identity`` — the exact source SHA, release,
  Alembic head (settings and the live database), runtime schema version and
  public route-contract digest, optionally pinned by the operator;
* ``api_health`` — the RuntimeContainer readiness components;
* ``adapter_readiness`` — the live adapter registry is valid and every
  enabled adapter reports ready (readiness probes are reads);
* ``effect_capabilities_disabled`` / ``safety_denials`` — no external-effect
  capability is enabled, and the *live* Safety Gate denies every one of them
  even with a registered, ready adapter (no budget is consumed);
* ``worker_backlog`` / ``reconciler_health`` — the live outbox backlog is
  within the Safety Gate bounds and the live reconciler can read its backlog;
* ``synthetic_lifecycle`` / ``restart_reconciliation`` / ``kill_switch_denial``
  — the real :class:`CommandKernel`, :class:`AdapterDispatch`,
  :class:`MemoryExecutionBus` and :class:`Reconciler` run a TEST_SYN command in
  an isolated sandbox (in-memory ledger, a fresh no-effect fixture adapter, no
  HTTP client, a Safety Gate cloned from the live switch table): submit →
  worker → matched read-back → exact-replay dedupe; a worker crash after the
  send → process restart (new dispatch, bus and reconciler over the same
  ledger once the crashed lease expires) → reconciled from read-back without
  a resend; a tripped kill switch → denied before persistence. In production
  the Policy Engine refuses synthetic commands, so the sandbox proves that
  denial instead (``synthetic_production_denial``);
* ``zero_provider_effects`` — the live ``provider_effect_attempts`` counter did
  not move, the sandbox owns no external-effect adapter and no HTTP client.

Nothing here writes to the live command ledger, the outbox or a provider.
Reports are kept in a bounded, process-local ledger for read-back and carry
a SHA-256 digest over their canonical JSON so evidence can be pinned.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

from app.commands import CommandConflict, CommandEnvelope, CommandNotFound, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.control_plane_auth import ControlPlaneCaller
from app.core.config import CANONICAL_SCHEMA_HEAD
from app.platform.adapter import AdapterContext
from app.platform.adapters.fixtures import FixtureAdapter, test_syn_adapter
from app.platform.bus import AdapterDispatch
from app.platform.kernel import SCOPE_COMMAND, CommandKernel, MemoryDenialAuditSink, PolicyDenied, SafetyDenied
from app.platform.memory import MemoryExecutionBus, MemoryReconciliationSource
from app.platform.metrics import KernelMetrics
from app.platform.principal import KernelPrincipal
from app.platform.reconciler import Reconciler
from app.platform.registry import AdapterRegistry
from app.platform.safety import SafetyContext, SafetyGate, SafetySubject

if TYPE_CHECKING:  # pragma: no cover - import cycle guard (core.runtime imports platform.runtime)
    from app.core.runtime import RuntimeContainer

REHEARSAL_VERSION = "no-effect-rehearsal.v1"
REHEARSAL_TENANT = "TEST_SYN"
REHEARSAL_CLIENT_ID = "middleware-rehearsal"
REHEARSAL_CAMPAIGN = "rehearsal-no-effect"
HISTORY_LIMIT = 50
SANDBOX_LEASE_SECONDS = 60.0

CheckStatus = Literal["pass", "fail", "skipped"]


@dataclass(frozen=True)
class RehearsalRequest:
    requested_by: str
    correlation_id: str
    reason: str
    expected_source_sha: str | None = None
    expected_schema_head: str | None = None

    def digest(self) -> str:
        canonical = json.dumps(
            {
                "reason": self.reason,
                "expected_source_sha": self.expected_source_sha,
                "expected_schema_head": self.expected_schema_head,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class RehearsalCheck:
    name: str
    status: CheckStatus
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _counter_total(counter: Any) -> float:
    total = 0.0
    for metric in counter.collect():
        for sample in metric.samples:
            if sample.name.endswith("_total"):
                total += float(sample.value)
    return total


class _SandboxClock:
    """A monotonic clock the sandbox can advance to expire a crashed lease."""

    def __init__(self) -> None:
        self._offset = 0.0

    def __call__(self) -> float:
        return time.monotonic() + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds


class _Sandbox:
    """The real kernel stages over an isolated in-memory ledger and one
    rehearsal-only TEST_SYN fixture. It shares nothing writable with the
    live process: no store, no HTTP client, no adapter, no metrics registry."""

    def __init__(self, live_settings: Any, live_safety: SafetyGate, *, subject: str, service_id: str) -> None:
        from app.platform.runtime import TEST_SYN_CAPABILITY, synthetic_policy

        self.settings = live_settings
        self.clock = _SandboxClock()
        self.policies = CommandPolicyRegistry((synthetic_policy(),), {TEST_SYN_CAPABILITY: True})
        self.store = MemoryCommandStore()
        self.commands = CommandService(store=self.store, policies=self.policies)
        self.metrics = KernelMetrics(service=f"{service_id}-rehearsal")
        # Same switch table and the same tightened kill switches as the live gate.
        self.safety = SafetyGate(live_settings, self.policies, switches=live_safety.switches, clock=self.clock)
        if live_safety.global_kill:
            self.safety.trip()
        for provider, tripped in live_safety.describe()["provider_kill_switches"].items():
            if tripped:
                self.safety.trip(provider)
        self.adapter: FixtureAdapter = test_syn_adapter()
        self.registry = AdapterRegistry(self.policies)
        self.registry.register(self.adapter)
        self.registry.validate()
        self.kernel = CommandKernel(
            settings=live_settings,
            commands=self.commands,
            registry=self.registry,
            safety=self.safety,
            metrics=self.metrics,
            denials=MemoryDenialAuditSink(),
            service_id=f"{service_id}-rehearsal",
        )
        self.principal = KernelPrincipal(
            subject=subject,
            client_id=REHEARSAL_CLIENT_ID,
            tenants=(REHEARSAL_TENANT,),
            roles=(),
            scopes=(SCOPE_COMMAND,),
            caller=ControlPlaneCaller(
                client_id=REHEARSAL_CLIENT_ID,
                command_scope=SCOPE_COMMAND,
                status_scope="platform.command.read",
                allowed_command_prefixes=("test.syn.",),
                allowed_targets=frozenset({"test-syn"}),
                connector_commands_allowed=True,
                compatibility_only=False,
            ),
        )
        self.generation = 0
        self.start_process()

    def start_process(self) -> None:
        """(Re)start the worker and reconciler processes over the same ledger."""
        self.generation += 1
        self.dispatch = AdapterDispatch(
            settings=self.settings,
            commands=self.commands,
            registry=self.registry,
            safety=self.safety,
            metrics=self.metrics,
            http=None,
            worker_id=f"rehearsal-worker-{self.generation}",
            clock=self.clock,
        )
        self.bus = MemoryExecutionBus(self.store, self.dispatch, lease_seconds=SANDBOX_LEASE_SECONDS, clock=self.clock, worker_id=f"rehearsal-bus-{self.generation}")
        self.source = MemoryReconciliationSource(self.store, clock=self.clock)
        self.reconciler = Reconciler(
            settings=self.settings,
            commands=self.commands,
            registry=self.registry,
            source=self.source,
            metrics=self.metrics,
            http=None,
            lease_seconds=SANDBOX_LEASE_SECONDS,
            timeout_seconds=5.0,
            reconciler_id=f"rehearsal-reconciler-{self.generation}",
        )

    def envelope(self, correlation_id: str, *, fixture: str = "success") -> CommandEnvelope:
        return CommandEnvelope(
            command_id=uuid4(),
            command_type="test.syn.execute.v1",
            command_version="1.0",
            target="test-syn",
            tenant_id=REHEARSAL_TENANT,
            requested_by=self.principal.subject,
            correlation_id=correlation_id,
            idempotency_key="rehearsal-" + uuid4().hex,
            capability="TEST_SYN_EXECUTE",
            payload={"rehearsal": True, "fixture": fixture},
        )

    def intents(self, command_id: UUID) -> int:
        return sum(1 for item in self.store._outbox if item.command_id == str(command_id))


class RehearsalLedger:
    """Bounded, process-local report history plus operator idempotency."""

    def __init__(self, limit: int = HISTORY_LIMIT) -> None:
        self.limit = limit
        self._reports: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self.lock = asyncio.Lock()

    def get(self, rehearsal_id: UUID | str) -> dict[str, Any]:
        report = self._reports.get(str(rehearsal_id))
        if report is None:
            raise CommandNotFound("rehearsal was not found")
        return report

    def replayed(self, subject: str, idempotency_key: str, request_digest: str) -> dict[str, Any] | None:
        known = self._idempotency.get((subject, idempotency_key))
        if known is None:
            return None
        digest, rehearsal_id = known
        if digest != request_digest:
            raise CommandConflict("Idempotency-Key was already used for a different rehearsal request")
        report = self._reports.get(rehearsal_id)
        if report is None:
            # The original report aged out of the bounded history; a key must never run twice.
            raise CommandConflict("Idempotency-Key belongs to a rehearsal that is no longer retained")
        return report

    def record(self, subject: str, idempotency_key: str, request_digest: str, report: dict[str, Any]) -> None:
        rehearsal_id = report["rehearsal_id"]
        self._reports[rehearsal_id] = report
        self._idempotency[(subject, idempotency_key)] = (request_digest, rehearsal_id)
        while len(self._reports) > self.limit:
            self._reports.popitem(last=False)

    def latest(self) -> dict[str, Any] | None:
        return next(reversed(self._reports.values()), None) if self._reports else None


class NoEffectRehearsal:
    def __init__(self, runtime: "RuntimeContainer", *, runtime_schema_version: int, contract_digest: str | None) -> None:
        if runtime.platform is None or runtime.commands is None:
            raise RuntimeError("the command kernel is not configured in this process")
        self.runtime = runtime
        self.platform = runtime.platform
        self.settings = runtime.settings
        self.runtime_schema_version = runtime_schema_version
        self.contract_digest = contract_digest

    # ------------------------------------------------------------------
    # live, read-only checks
    # ------------------------------------------------------------------
    def _source_identity(self, request: RehearsalRequest) -> RehearsalCheck:
        source_sha = (self.settings.source_sha or "").strip()
        detail: dict[str, Any] = {
            "source_sha": source_sha or None,
            "release_id": self.settings.release_id,
            "app_version": self.settings.app_version,
            "environment": self.settings.app_env,
            "expected_source_sha": request.expected_source_sha,
        }
        problems: list[str] = []
        if self.settings.app_env in {"staging", "production"} and (not source_sha or source_sha == "unknown"):
            problems.append("source_sha_unknown")
        if request.expected_source_sha is not None and source_sha.lower() != request.expected_source_sha.lower():
            problems.append("source_sha_mismatch")
        detail["problems"] = problems
        return RehearsalCheck("source_identity", "fail" if problems else "pass", detail)

    def _schema_identity(self, request: RehearsalRequest, components: dict[str, str]) -> RehearsalCheck:
        live_head = components.get("alembic_head", "not_configured")
        detail: dict[str, Any] = {
            "alembic_schema_head": self.settings.schema_head,
            "canonical_schema_head": CANONICAL_SCHEMA_HEAD,
            "expected_schema_head": request.expected_schema_head,
            "database_alembic_head": live_head,
            "runtime_schema_version": self.runtime_schema_version,
            "public_contract_digest": self.contract_digest,
        }
        problems: list[str] = []
        if self.settings.schema_head != CANONICAL_SCHEMA_HEAD:
            problems.append("settings_schema_head_not_canonical")
        if request.expected_schema_head is not None and request.expected_schema_head != self.settings.schema_head:
            problems.append("schema_head_mismatch")
        if live_head == "not_ready":
            problems.append("database_alembic_head_drift")
        if self.settings.app_env in {"staging", "production"} and self.contract_digest is None:
            problems.append("public_contract_digest_missing")
        detail["problems"] = problems
        return RehearsalCheck("schema_identity", "fail" if problems else "pass", detail)

    @staticmethod
    def _api_health(components: dict[str, str]) -> RehearsalCheck:
        failing = sorted(name for name, status in components.items() if status not in {"ready", "not_configured"})
        return RehearsalCheck("api_health", "fail" if failing else "pass", {"components": dict(sorted(components.items())), "failing": failing})

    async def _adapter_readiness(self) -> RehearsalCheck:
        registry = self.platform.registry
        context = AdapterContext(
            tenant_id="rehearsal",
            command_id="rehearsal",
            correlation_id="rehearsal",
            attempt=0,
            timeout_seconds=self.settings.readiness_timeout_seconds,
            environment=self.settings.app_env,
            deployment_sha=self.settings.source_sha,
            http=self.platform.dispatch.http,
        )
        report = await registry.readiness(context)
        enabled = set(registry.enabled_adapter_ids())
        adapters = [
            {
                "adapter_id": row["adapter_id"],
                "ready": report[row["adapter_id"]].ready if row["adapter_id"] in report else False,
                "enabled": row["adapter_id"] in enabled,
                "external_effect": row["external_effect"],
                "provider_family": row["provider_family"],
            }
            for row in registry.describe()
        ]
        problems: list[str] = []
        if self.platform.registry_error is not None or not registry.validated:
            problems.append("adapter_registry_invalid")
        problems.extend(f"enabled_adapter_not_ready:{row['adapter_id']}" for row in adapters if row["enabled"] and not row["ready"])
        return RehearsalCheck(
            "adapter_readiness",
            "fail" if problems else "pass",
            {
                "registry_valid": registry.validated and self.platform.registry_error is None,
                "adapters": adapters,
                "unowned_command_prefixes": list(registry.unowned_prefixes()),
                "problems": problems,
            },
        )

    def _effect_capabilities(self) -> RehearsalCheck:
        safety = self.platform.safety
        capabilities = self.runtime.commands.policies.capabilities  # type: ignore[union-attr]
        enabled = sorted(
            name for name, value in capabilities.items() if value is True and safety.classification(name) == "external_effect"
        )
        return RehearsalCheck(
            "effect_capabilities_disabled",
            "fail" if enabled else "pass",
            {"external_effect_capabilities_enabled": enabled, "capabilities_evaluated": len(capabilities)},
        )

    def _safety_denials(self) -> RehearsalCheck:
        safety = self.platform.safety
        policies = self.runtime.commands.policies  # type: ignore[union-attr]
        rows: list[dict[str, Any]] = []
        admitted: list[str] = []
        seen: set[str] = set()
        for policy in sorted(policies.policies, key=lambda item: item.prefix):
            if policy.capability in seen or safety.classification(policy.capability) != "external_effect":
                continue
            seen.add(policy.capability)
            decision = safety.evaluate(
                SafetySubject(
                    tenant_id=REHEARSAL_TENANT,
                    command_type=f"{policy.prefix}rehearsal.v1",
                    target=policy.target,
                    capability=policy.capability,
                    campaign_id=REHEARSAL_CAMPAIGN,
                    correlation_id="rehearsal",
                ),
                # Worst case: an adapter is registered and ready. Only the gates may deny.
                SafetyContext(adapter_registered=True, adapter_ready=True, tenant_backlog=None, global_backlog=None),
                consume_budget=False,
            )
            if decision.allow:
                admitted.append(policy.capability)
            rows.append({"capability": policy.capability, "target": policy.target, "denied": not decision.allow, "reason_codes": list(decision.reason_codes)})
        return RehearsalCheck(
            "safety_denials",
            "fail" if admitted else "pass",
            {"safety_version": safety.switches.safety_version, "evaluated": rows, "admitted": admitted},
        )

    async def _worker_backlog(self) -> RehearsalCheck:
        limits = self.platform.safety.switches.limits
        try:
            tenant_backlog, global_backlog = await self.runtime.commands.backlog(REHEARSAL_TENANT)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - a probe failure is a failed check, not a 500
            return RehearsalCheck("worker_backlog", "fail", {"error": type(exc).__name__})
        saturated = global_backlog >= limits.global_backlog_bound
        return RehearsalCheck(
            "worker_backlog",
            "fail" if saturated else "pass",
            {"active_commands": global_backlog, "synthetic_tenant_active": tenant_backlog, "global_backlog_bound": limits.global_backlog_bound},
        )

    async def _reconciler_health(self) -> RehearsalCheck:
        reconciler = self.platform.reconciler
        if reconciler is None:
            return RehearsalCheck("reconciler_health", "fail", {"configured": False})
        try:
            backlog = await reconciler.source.backlog()
        except Exception as exc:  # noqa: BLE001
            return RehearsalCheck("reconciler_health", "fail", {"configured": True, "error": type(exc).__name__})
        return RehearsalCheck(
            "reconciler_health",
            "pass",
            {"configured": True, "reconciliation_backlog": backlog, "budget": reconciler.budget, "reconciler_id": reconciler.reconciler_id},
        )

    # ------------------------------------------------------------------
    # sandbox drills
    # ------------------------------------------------------------------
    async def _synthetic_lifecycle(self, sandbox: _Sandbox, correlation_id: str) -> RehearsalCheck:
        command = sandbox.envelope(correlation_id)
        accepted = await sandbox.kernel.submit(command, sandbox.principal)
        await sandbox.bus.run_once()
        operation = await sandbox.commands.get(REHEARSAL_TENANT, command.command_id)
        replay = await sandbox.kernel.submit(command, sandbox.principal)
        evidence = operation.readback_evidence if isinstance(operation.readback_evidence, dict) else {}
        detail = {
            "operation_id": str(command.command_id),
            "accepted_state": accepted.operation.state,
            "destination": accepted.destination,
            "final_state": operation.state,
            "readback_status": str(evidence.get("status", "")).lower() or None,
            "readback_evidence_sha256": operation.readback_evidence_sha256,
            "exact_replay_duplicate": replay.operation.duplicate,
            "outbox_intents": sandbox.intents(command.command_id),
            "executions": sandbox.adapter.effects.get(str(command.command_id), 0),
        }
        ok = (
            operation.state == "completed"
            and detail["readback_status"] == "matched"
            and replay.operation.duplicate
            and detail["outbox_intents"] == 1
            and detail["executions"] == 1
        )
        return RehearsalCheck("synthetic_lifecycle", "pass" if ok else "fail", detail)

    async def _restart_reconciliation(self, sandbox: _Sandbox, correlation_id: str) -> RehearsalCheck:
        command = sandbox.envelope(correlation_id, fixture="crash")
        await sandbox.kernel.submit(command, sandbox.principal)
        await sandbox.bus.run_once()  # the worker dies after the provider saw the send
        parked = await sandbox.commands.get(REHEARSAL_TENANT, command.command_id)
        crashed_generation = sandbox.generation
        # Process restart: the crashed lease expires, a fresh worker and reconciler start.
        sandbox.clock.advance(SANDBOX_LEASE_SECONDS + 1.0)
        sandbox.start_process()
        reclaimed_by_worker = await sandbox.bus.run_once()
        decision = await sandbox.reconciler.run_once()
        operation = await sandbox.commands.get(REHEARSAL_TENANT, command.command_id)
        detail = {
            "operation_id": str(command.command_id),
            "state_after_crash": parked.state,
            "crashed_process_generation": crashed_generation,
            "restarted_process_generation": sandbox.generation,
            "worker_reclaimed_quarantined_row": reclaimed_by_worker,
            "reconciler_action": decision.action if decision else None,
            "final_state": operation.state,
            "executions": sandbox.adapter.effects.get(str(command.command_id), 0),
            "reconciliation_backlog": await sandbox.source.backlog(),
        }
        ok = (
            parked.state == "reconciliation_required"
            and not reclaimed_by_worker
            and detail["reconciler_action"] == "complete"
            and operation.state == "completed"
            and detail["executions"] == 1
            and detail["reconciliation_backlog"] == 0
        )
        return RehearsalCheck("restart_reconciliation", "pass" if ok else "fail", detail)

    async def _kill_switch_denial(self, sandbox: _Sandbox, correlation_id: str, *, through_kernel: bool) -> RehearsalCheck:
        sandbox.safety.trip()  # the disposable sandbox gate only; the live gate is untouched
        command = sandbox.envelope(correlation_id)
        gate = sandbox.safety.evaluate(
            SafetySubject(
                tenant_id=command.tenant_id,
                command_type=command.command_type,
                target=command.target,
                capability=command.capability,
                correlation_id=correlation_id,
            ),
            SafetyContext(adapter_registered=True, adapter_ready=True, tenant_backlog=None, global_backlog=None),
            consume_budget=False,
        )
        detail: dict[str, Any] = {"gate_denied": not gate.allow, "gate_reason_codes": list(gate.reason_codes)}
        ok = not gate.allow and "global_kill_switch" in gate.reason_codes
        if through_kernel:
            denied_reason: str | None = None
            try:
                await sandbox.kernel.submit(command, sandbox.principal)
            except SafetyDenied as exc:
                denied_reason = str(exc)
            detail.update({"kernel_denied": denied_reason is not None, "kernel_reason": denied_reason, "outbox_intents": sandbox.intents(command.command_id)})
            ok = ok and denied_reason is not None and "global_kill_switch" in denied_reason and detail["outbox_intents"] == 0
        return RehearsalCheck("kill_switch_denial", "pass" if ok else "fail", detail)

    async def _production_denial(self, sandbox: _Sandbox, correlation_id: str) -> RehearsalCheck:
        command = sandbox.envelope(correlation_id)
        denied_reason: str | None = None
        try:
            await sandbox.kernel.submit(command, sandbox.principal)
        except (PolicyDenied, SafetyDenied) as exc:
            denied_reason = str(exc)
        detail = {"denied": denied_reason is not None, "reason": denied_reason, "outbox_intents": sandbox.intents(command.command_id)}
        ok = denied_reason is not None and "synthetic_command_in_production" in denied_reason and detail["outbox_intents"] == 0
        return RehearsalCheck("synthetic_production_denial", "pass" if ok else "fail", detail)

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    async def run(self, request: RehearsalRequest) -> dict[str, Any]:
        started_at = _now()
        effect_attempts_before = _counter_total(self.platform.metrics.provider_effect_attempts)
        readiness = await self.runtime.readiness()
        components = dict(readiness.components)

        checks: list[RehearsalCheck] = [
            self._source_identity(request),
            self._schema_identity(request, components),
            self._api_health(components),
            await self._adapter_readiness(),
            self._effect_capabilities(),
            self._safety_denials(),
            await self._worker_backlog(),
            await self._reconciler_health(),
        ]

        sandbox = _Sandbox(self.settings, self.platform.safety, subject=request.requested_by, service_id=self.platform.kernel.service_id)
        production = self.settings.app_env == "production"
        for name in ("synthetic_lifecycle", "restart_reconciliation", "kill_switch_denial"):
            try:
                if name == "kill_switch_denial":
                    # Last: it trips the sandbox gate for good.
                    checks.append(await self._kill_switch_denial(sandbox, request.correlation_id, through_kernel=not production))
                elif production:
                    # The Policy Engine refuses synthetic commands in production:
                    # prove that denial once instead of running the lane.
                    if name == "synthetic_lifecycle":
                        checks.append(await self._production_denial(sandbox, request.correlation_id))
                    else:
                        checks.append(RehearsalCheck(name, "skipped", {"reason": "synthetic_lane_denied_in_production"}))
                elif name == "synthetic_lifecycle":
                    checks.append(await self._synthetic_lifecycle(sandbox, request.correlation_id))
                else:
                    checks.append(await self._restart_reconciliation(sandbox, request.correlation_id))
            except Exception as exc:  # noqa: BLE001 - a drill failure is evidence, not a 500
                checks.append(RehearsalCheck(name, "fail", {"error": type(exc).__name__}))

        effect_attempts_after = _counter_total(self.platform.metrics.provider_effect_attempts)
        sandbox_external = sorted(row["adapter_id"] for row in sandbox.registry.describe() if row["external_effect"])
        zero = {
            "live_provider_effect_attempts_delta": effect_attempts_after - effect_attempts_before,
            "sandbox_external_effect_adapters": sandbox_external,
            "sandbox_http_client": sandbox.dispatch.http is not None,
            "sandbox_fixture_executions": sandbox.adapter.provider_effects,
            "live_ledger_writes": 0,
        }
        zero_ok = zero["live_provider_effect_attempts_delta"] == 0 and not sandbox_external and not zero["sandbox_http_client"]
        checks.append(RehearsalCheck("zero_provider_effects", "pass" if zero_ok else "fail", zero))

        failed = [check.name for check in checks if check.status == "fail"]
        report: dict[str, Any] = {
            "rehearsal_id": str(uuid4()),
            "rehearsal_version": REHEARSAL_VERSION,
            "requested_by": request.requested_by,
            "correlation_id": request.correlation_id,
            "reason": request.reason,
            "started_at": started_at,
            "finished_at": _now(),
            "environment": self.settings.app_env,
            "service_id": self.platform.kernel.service_id,
            "identity": {
                "source_sha": self.settings.source_sha,
                "release_id": self.settings.release_id,
                "alembic_schema_head": self.settings.schema_head,
                "runtime_schema_version": self.runtime_schema_version,
                "public_contract_digest": self.contract_digest,
            },
            "verdict": "FAIL" if failed else "PASS",
            "failed_checks": failed,
            "provider_effects": 0 if zero_ok else None,
            "checks": [check.as_dict() for check in checks],
        }
        report["report_sha256"] = _canonical_digest(report)
        return report


__all__ = [
    "NoEffectRehearsal",
    "REHEARSAL_VERSION",
    "RehearsalCheck",
    "RehearsalLedger",
    "RehearsalRequest",
]
