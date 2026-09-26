"""The ExecutionBus: adapter execution over the durable outbox.

PostgreSQL is the truth. The bus does not own a second queue: a command's
outbox intent (``destination = adapter-command``, written in the same
transaction as the command) is claimed with a lease by the existing
:class:`app.worker.OutboxWorker` (``FOR UPDATE SKIP LOCKED``), quarantined as
reconciliation-required *before* provider code runs, heart-beaten while it
runs, and resolved from the handler's outcome. :class:`AdapterDispatch` is
that handler. NATS may wake workers up; losing a NATS message loses nothing
because the backlog is the outbox.

Outcome → ledger:

* ``ACCEPTED``/``COMPLETED`` → ``accepted`` → readback → ``completed`` only
  when the readback ``MATCHED``; ``MISMATCH`` → ``failed``; anything else →
  ``reconciliation_required``.
* ``REJECTED`` (deterministic, before any effect) → ``failed``; no retry.
* ``TRANSIENT`` / retryable-before-effect errors → ``failed`` → ``queued``
  and a known-safe retry of the same outbox row (bounded exponential backoff,
  dead-letter after ``max_attempts``).
* ``UNKNOWN`` / ambiguous errors / timeouts → ``reconciliation_required``;
  the outbox row stays quarantined for the reconciler. Never resent blindly.
* breaker open / bulkhead full → no attempt is opened; known-safe retry.

Finalizations are fenced to the attempt they belong to: a worker holding an
old attempt number cannot finalize a newer attempt.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from uuid import UUID

from app.commands import (
    ADAPTER_COMMAND_DESTINATION,
    AUTHENTICATED_CLIENT_ID_KEY,
    CommandConflict,
    CommandEnvelope,
    CommandNotFound,
    CommandOperation,
    CommandService,
    redact_metadata,
)
from app.core.config import Settings
from app.platform.adapter import (
    Adapter,
    AdapterContext,
    AdapterResult,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)
from app.platform.connector_bridge import (
    KernelAdapterConnector,
    connector_result_to_adapter,
    connector_result_to_readback,
    execution_context,
)
from app.platform.metrics import KernelMetrics
from middleware.connector_runtime.execution import ConnectorRegistry as Section2ConnectorRegistry
from app.platform.registry import AdapterRegistry, Ownership
from app.platform.resilience import Bulkhead, BulkheadFull, CircuitBreaker, CircuitOpen
from app.platform.safety import SafetyContext, SafetyGate, SafetySubject
from app.storage import DEFAULT_MAX_OUTBOX_ATTEMPTS, OutboxRecord
from app.worker import KnownSafeRetryError

logger = logging.getLogger("codestra.platform.bus")

DEFAULT_ADAPTER_TIMEOUT_SECONDS = 30.0
DEFAULT_BULKHEAD_CAPACITY = 8
DEFAULT_BREAKER_THRESHOLD = 5
DEFAULT_BREAKER_OPEN_SECONDS = 30.0


class UnknownOutcomeError(RuntimeError):
    """The provider outcome is unknown; the outbox row must stay quarantined."""


@dataclass
class DispatchOutcome:
    """What one dispatch did, for tests and metrics."""

    command_id: UUID
    attempt: int | None
    final_state: str
    effect_attempted: bool
    result: AdapterResult | None = None
    readback: ReadbackResult | None = None


@dataclass
class BusSettings:
    max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS
    default_timeout_seconds: float = DEFAULT_ADAPTER_TIMEOUT_SECONDS
    bulkhead_capacity: int = DEFAULT_BULKHEAD_CAPACITY
    breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD
    breaker_open_seconds: float = DEFAULT_BREAKER_OPEN_SECONDS
    timeouts_by_prefix: Mapping[str, float] = field(default_factory=dict)


def worker_identity(prefix: str = "worker") -> str:
    return f"{prefix}:{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


class AdapterDispatch:
    """The ``adapter-command`` outbox handler."""

    def __init__(
        self,
        *,
        settings: Settings,
        commands: CommandService,
        registry: AdapterRegistry,
        safety: SafetyGate,
        metrics: KernelMetrics,
        http: Any = None,
        bus_settings: BusSettings | None = None,
        worker_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.commands = commands
        self.registry = registry
        self.safety = safety
        self.metrics = metrics
        self.http = http
        self.bus = bus_settings or BusSettings()
        self.worker_id = worker_id or worker_identity()
        self.clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}
        self._bulkheads: dict[str, Bulkhead] = {}
        self.last_outcome: DispatchOutcome | None = None

    # ------------------------------------------------------------------
    # Resilience primitives, one per adapter
    # ------------------------------------------------------------------
    def breaker(self, adapter_id: str) -> CircuitBreaker:
        breaker = self._breakers.get(adapter_id)
        if breaker is None:
            breaker = CircuitBreaker(
                adapter_id,
                failure_threshold=self.bus.breaker_threshold,
                open_seconds=self.bus.breaker_open_seconds,
                clock=self.clock,
                on_transition=self.metrics.breaker,
            )
            self._breakers[adapter_id] = breaker
        return breaker

    def bulkhead(self, adapter_id: str) -> Bulkhead:
        bulkhead = self._bulkheads.get(adapter_id)
        if bulkhead is None:
            bulkhead = Bulkhead(adapter_id, self.bus.bulkhead_capacity)
            self._bulkheads[adapter_id] = bulkhead
        return bulkhead

    def timeout_for(self, ownership: Ownership) -> float:
        for prefix, seconds in self.bus.timeouts_by_prefix.items():
            if ownership.prefix == prefix:
                return float(seconds)
        return self.bus.default_timeout_seconds

    def context(self, operation: CommandOperation, *, attempt: int, timeout: float, trace: Mapping[str, str] | None = None, payload: Mapping[str, Any] | None = None) -> AdapterContext:
        return AdapterContext(
            tenant_id=operation.tenant_id,
            command_id=str(operation.command_id),
            correlation_id=operation.correlation_id,
            attempt=attempt,
            timeout_seconds=timeout,
            environment=self.settings.app_env,
            deployment_sha=self.settings.source_sha,
            http=self.http,
            trace_context=dict(trace or {}),
            test_syn=operation.tenant_id in self.safety.switches.synthetic_tenants,
            payload=dict(payload or {}),
        )

    # ------------------------------------------------------------------
    # Handler
    # ------------------------------------------------------------------
    async def __call__(self, record: OutboxRecord) -> None:
        if record.destination != ADAPTER_COMMAND_DESTINATION:
            raise KnownSafeRetryError(f"unexpected destination {record.destination}")
        command_id = _command_id_of(record)
        if command_id is None:
            # Not a command intent (or a malformed one): nothing to execute, nothing to retry.
            logger.error("adapter_dispatch_without_command_id", extra={"outbox_id": record.id})
            return
        trace = record.payload.get("_trace") if isinstance(record.payload, Mapping) else None
        await self.dispatch(
            record.tenant_id,
            command_id,
            outbox_attempt=record.attempt_count,
            trace=trace if isinstance(trace, Mapping) else None,
        )

    async def dispatch(self, tenant_id: str, command_id: UUID, *, outbox_attempt: int = 1, trace: Mapping[str, str] | None = None) -> DispatchOutcome:
        try:
            operation = await self.commands.get(tenant_id, command_id)
        except CommandNotFound:
            logger.error("adapter_dispatch_unknown_command", extra={"command_id": str(command_id)})
            return self._record(DispatchOutcome(command_id, None, "missing", False))

        if operation.state in {"completed", "failed", "dead_lettered", "cancelled"}:
            # Terminal already (an operator cancelled it, or a previous worker
            # finished it after its lease expired): nothing to execute.
            return self._record(DispatchOutcome(command_id, None, operation.state, False))

        envelope = await self.commands.load_envelope(tenant_id, command_id)
        ownership = self.registry.ownership(envelope.command_type)
        if ownership is None:
            await self._fail(operation, reason="no adapter owns this command", attempt=None)
            return self._record(DispatchOutcome(command_id, None, "failed", False))
        adapter = self.registry.adapter(ownership.adapter_id)
        capabilities = adapter.capabilities()
        if envelope.target not in capabilities.connector_ids:
            await self._fail(operation, reason="connector unavailable for adapter", attempt=None)
            return self._record(DispatchOutcome(command_id, None, "failed", False))
        family = envelope.command_type.split(".", 1)[0]
        timeout = self.timeout_for(ownership)

        if operation.state in {"dispatching", "accepted", "readback_pending"}:
            # Crash recovery (Phase 19): a previous attempt may have reached the
            # provider. Status/readback first; never a blind resend.
            return await self._recover(operation, envelope, adapter, ownership, family, timeout, trace)

        # Safety is re-evaluated at execution time: a kill switch tripped after
        # acceptance must stop the effect here.
        try:
            readiness = await asyncio.wait_for(
                adapter.readiness(self.context(operation, attempt=outbox_attempt, timeout=timeout, trace=trace, payload=envelope.payload)),
                timeout=timeout,
            )
        except Exception as exc:
            # Readiness runs before execute, so provider effects are impossible here.
            logger.warning("adapter_readiness_failed", extra={"adapter": adapter.adapter_id, "error": type(exc).__name__})
            raise KnownSafeRetryError(f"adapter readiness unavailable: {type(exc).__name__}") from exc
        decision = self.safety.evaluate(
            SafetySubject(
                tenant_id=operation.tenant_id,
                command_type=operation.command_type,
                target=operation.target,
                capability=operation.capability,
                campaign_id=_campaign_id(envelope.payload),
                correlation_id=operation.correlation_id,
            ),
            SafetyContext(adapter_registered=True, adapter_ready=readiness.ready),
            consume_budget=False,
        )
        if not decision.allow:
            self.metrics.safety_denials.labels(reason=decision.reason_code).inc()
            self.metrics.effect_denied.labels(
                connector=adapter.adapter_id,
                provider=adapter.capabilities().provider_family,
                reason=decision.reason_code,
            ).inc()
            if decision.reason_code == "adapter_not_ready":
                # Readiness is transient; back off without opening an attempt.
                raise KnownSafeRetryError("adapter not ready")
            await self._fail(operation, reason=f"safety denied at execution: {decision.reason_code}", attempt=None)
            return self._record(DispatchOutcome(command_id, None, "failed", False))

        breaker = self.breaker(adapter.adapter_id)
        try:
            breaker.admit()
        except CircuitOpen as exc:
            self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="execute", result="circuit_open").inc()
            raise KnownSafeRetryError(str(exc)) from exc

        # queued → dispatching opens the attempt this worker owns.
        if operation.state == "persisted":
            operation = await self.commands.transition(tenant_id, command_id, new_state="queued", actor_id=self.worker_id, reason="claimed by execution bus")
        operation = await self.commands.transition(tenant_id, command_id, new_state="dispatching", actor_id=self.worker_id, reason=f"attempt via adapter {adapter.adapter_id}")
        attempt = await self.commands.latest_attempt(tenant_id, command_id)
        context = self.context(operation, attempt=attempt, timeout=timeout, trace=trace, payload=envelope.payload)

        self.metrics.adapter_requests.labels(adapter=adapter.adapter_id, operation="execute").inc()
        self.metrics.provider_effect_attempts.labels(adapter=adapter.adapter_id).inc()
        provider_family = adapter.capabilities().provider_family
        started = time.perf_counter()
        result: AdapterResult
        try:
            section2 = Section2ConnectorRegistry()
            connector = KernelAdapterConnector(adapter, (ownership.prefix,))
            section2.register(connector)
            effect_class = connector.descriptor.capabilities[0].effect
            runtime_context = execution_context(
                command=envelope,
                adapter_context=context,
                effect_class=effect_class,
                effects_allowed=True,
            )
            connector_result = await self.bulkhead(adapter.adapter_id).run(
                lambda: asyncio.wait_for(
                    section2.execute(
                        envelope.target,
                        envelope.command_type,
                        {"_command": envelope},
                        runtime_context,
                    ),
                    timeout=timeout,
                )
            )
            result = adapter.normalize_result(connector_result_to_adapter(connector_result))
        except BulkheadFull as exc:
            self.metrics.bulkhead_rejections.labels(adapter=adapter.adapter_id).inc()
            # Nothing was sent: close the attempt as failed and retry safely.
            await self._fail(operation, reason=f"bulkhead saturated: {exc}", attempt=attempt, retryable=True)
            raise KnownSafeRetryError(str(exc)) from exc
        except asyncio.TimeoutError:
            result = AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="adapter_timeout")
        except Exception as exc:  # noqa: BLE001 - classified below
            klass = adapter.classify_error(exc)
            if klass is ErrorClass.RETRYABLE_BEFORE_EFFECT:
                result = AdapterResult(Outcome.TRANSIENT, error_class=klass, safe_error_code=type(exc).__name__)
            elif klass is ErrorClass.NON_RETRYABLE or klass is ErrorClass.UNSUPPORTED:
                result = AdapterResult(Outcome.REJECTED, error_class=klass, safe_error_code=type(exc).__name__)
            elif klass is ErrorClass.PROVIDER_AUTH:
                result = AdapterResult(Outcome.REJECTED, error_class=klass, safe_error_code="provider_auth_failed")
            elif klass is ErrorClass.PROVIDER_RATE_LIMITED:
                result = AdapterResult(Outcome.TRANSIENT, error_class=klass, safe_error_code="provider_rate_limited")
            else:
                result = AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        finally:
            self.metrics.adapter_latency.labels(adapter=adapter.adapter_id, operation="execute").observe(time.perf_counter() - started)

        result_label = result.outcome.value.lower()
        self.metrics.provider_requests.labels(
            connector=adapter.adapter_id,
            provider=provider_family,
            operation="execute",
            result=result_label,
        ).inc()
        if result.safe_error_code:
            normalized_error = str(result.safe_error_code).upper()[:64]
            self.metrics.provider_failures.labels(
                connector=adapter.adapter_id,
                provider=provider_family,
                operation="execute",
                error=normalized_error,
            ).inc()
            if "TIMEOUT" in normalized_error:
                self.metrics.provider_timeouts.labels(
                    connector=adapter.adapter_id, provider=provider_family, operation="execute"
                ).inc()
            if "RATE_LIMIT" in normalized_error:
                self.metrics.provider_rate_limits.labels(
                    connector=adapter.adapter_id, provider=provider_family, operation="execute"
                ).inc()
        if result.outcome is Outcome.UNKNOWN:
            self.metrics.provider_unknown_states.labels(
                connector=adapter.adapter_id, provider=provider_family, operation="execute"
            ).inc()
        return await self._finalize(operation, envelope, adapter, ownership, family, attempt, context, result)

    # ------------------------------------------------------------------
    async def _finalize(
        self,
        operation: CommandOperation,
        envelope: CommandEnvelope,
        adapter: Adapter,
        ownership: Ownership,
        family: str,
        attempt: int,
        context: AdapterContext,
        result: AdapterResult,
    ) -> DispatchOutcome:
        tenant_id, command_id = operation.tenant_id, operation.command_id
        breaker = self.breaker(adapter.adapter_id)
        safe = self._safe_reason(result)

        if result.outcome in {Outcome.ACCEPTED, Outcome.COMPLETED}:
            breaker.record_success()
            operation = await self.commands.transition(
                tenant_id, command_id, new_state="accepted", actor_id=self.worker_id,
                reason=f"provider acknowledged ({result.outcome.value})", provider_operation_id=result.provider_operation_id,
                expected_attempt=attempt,
            )
            readback = await self._readback(operation, adapter, context, ownership, attempt)
            return self._record(DispatchOutcome(command_id, attempt, readback[0], True, result, readback[1]))

        if result.outcome is Outcome.REJECTED:
            breaker.record_failure()
            self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="execute", result="rejected").inc()
            await self._fail(operation, reason=safe, attempt=attempt)
            self.metrics.commands_failed.labels(command_family=family, adapter=adapter.adapter_id, result="rejected").inc()
            return self._record(DispatchOutcome(command_id, attempt, "failed", False, result))

        if result.outcome is Outcome.TRANSIENT:
            breaker.record_failure()
            self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="execute", result="transient").inc()
            exhausted = context.attempt >= self.bus.max_attempts
            await self._fail(operation, reason=safe, attempt=attempt, retryable=not exhausted)
            if exhausted:
                await self.commands.transition(tenant_id, command_id, new_state="dead_lettered", actor_id=self.worker_id, reason="retry budget exhausted")
                self.metrics.commands_failed.labels(command_family=family, adapter=adapter.adapter_id, result="dead_lettered").inc()
                self._record(DispatchOutcome(command_id, attempt, "dead_lettered", False, result))
                raise KnownSafeRetryError(f"retry budget exhausted: {safe}")
            self._record(DispatchOutcome(command_id, attempt, "queued", False, result))
            raise KnownSafeRetryError(safe)

        if result.outcome is Outcome.UNSUPPORTED:
            breaker.record_failure()
            await self._fail(operation, reason="adapter does not support execute for this command", attempt=attempt)
            self.metrics.commands_failed.labels(command_family=family, adapter=adapter.adapter_id, result="unsupported").inc()
            return self._record(DispatchOutcome(command_id, attempt, "failed", False, result))

        # UNKNOWN (and CANCELLED, which an execute must not return): the effect
        # may exist. Park for reconciliation; keep the outbox row quarantined.
        breaker.record_failure()
        self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="execute", result="unknown").inc()
        await self.commands.transition(
            tenant_id, command_id, new_state="reconciliation_required", actor_id=self.worker_id,
            reason=safe or "provider outcome unknown", provider_operation_id=result.provider_operation_id, expected_attempt=attempt,
        )
        self.metrics.commands_reconciliation_required.labels(command_family=family, adapter=adapter.adapter_id).inc()
        self._record(DispatchOutcome(command_id, attempt, "reconciliation_required", True, result))
        raise UnknownOutcomeError(safe or "provider outcome unknown")

    async def _readback(self, operation: CommandOperation, adapter: Adapter, context: AdapterContext, ownership: Ownership, attempt: int) -> tuple[str, ReadbackResult]:
        tenant_id, command_id = operation.tenant_id, operation.command_id
        family = operation.command_type.split(".", 1)[0]
        operation = await self.commands.transition(
            tenant_id, command_id, new_state="readback_pending", actor_id=self.worker_id, reason="reading provider state back", expected_attempt=attempt,
        )
        self.metrics.adapter_requests.labels(adapter=adapter.adapter_id, operation="readback").inc()
        started = time.perf_counter()
        try:
            if adapter.capabilities().supports_status and operation.provider_operation_id:
                status = await asyncio.wait_for(adapter.status(operation, context), timeout=context.timeout_seconds)
                status = adapter.normalize_result(status)
                if status.provider_operation_id and status.provider_operation_id != operation.provider_operation_id:
                    readback = ReadbackResult(ReadbackStatus.MISMATCH, provider_operation_id=status.provider_operation_id, safe_error_code="provider_reference_mismatch")
                elif status.outcome is Outcome.ACCEPTED:
                    readback = ReadbackResult(
                        ReadbackStatus.UNAVAILABLE,
                        provider_operation_id=status.provider_operation_id or operation.provider_operation_id,
                        evidence={"provider_state": "pending", "retry_hint": "reconcile"},
                        safe_error_code="provider_operation_pending",
                    )
                elif status.outcome in {Outcome.REJECTED, Outcome.CANCELLED}:
                    readback = ReadbackResult(
                        ReadbackStatus.MISMATCH,
                        provider_operation_id=status.provider_operation_id or operation.provider_operation_id,
                        evidence={"provider_state": status.outcome.value.lower()},
                        safe_error_code=status.safe_error_code or "provider_operation_failed",
                    )
                else:
                    section2 = Section2ConnectorRegistry()
                    connector = KernelAdapterConnector(adapter, (ownership.prefix,))
                    section2.register(connector)
                    runtime_context = execution_context(
                        command=await self.commands.load_envelope(tenant_id, command_id),
                        adapter_context=context,
                        effect_class=connector.descriptor.capabilities[0].effect,
                        effects_allowed=False,
                        operation=operation,
                    )
                    runtime_result = await asyncio.wait_for(
                        connector.readback(operation.provider_operation_id or "", runtime_context),
                        timeout=context.timeout_seconds,
                    )
                    readback = connector_result_to_readback(runtime_result)
            else:
                section2 = Section2ConnectorRegistry()
                connector = KernelAdapterConnector(adapter, (ownership.prefix,))
                section2.register(connector)
                runtime_context = execution_context(
                    command=await self.commands.load_envelope(tenant_id, command_id),
                    adapter_context=context,
                    effect_class=connector.descriptor.capabilities[0].effect,
                    effects_allowed=False,
                    operation=operation,
                )
                runtime_result = await asyncio.wait_for(
                    connector.readback(operation.provider_operation_id or "", runtime_context),
                    timeout=context.timeout_seconds,
                )
                readback = connector_result_to_readback(runtime_result)
        except Exception as exc:  # noqa: BLE001
            readback = ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        finally:
            self.metrics.adapter_latency.labels(adapter=adapter.adapter_id, operation="readback").observe(time.perf_counter() - started)

        evidence = {"schema_version": "1.0", "status": readback.status.value.lower(), "provider_operation_id": readback.provider_operation_id or operation.provider_operation_id, **redact_metadata(dict(readback.evidence))}
        provider_family = adapter.capabilities().provider_family
        self.metrics.provider_readbacks.labels(
            connector=adapter.adapter_id,
            provider=provider_family,
            result=readback.status.value.lower(),
        ).inc()
        if readback.status in {ReadbackStatus.UNKNOWN, ReadbackStatus.UNAVAILABLE, ReadbackStatus.PENDING, ReadbackStatus.ACCEPTED, ReadbackStatus.RUNNING, ReadbackStatus.PARTIAL}:
            self.metrics.provider_unknown_states.labels(
                connector=adapter.adapter_id, provider=provider_family, operation="readback"
            ).inc()
        if readback.status is ReadbackStatus.MATCHED:
            await self.commands.transition(
                tenant_id, command_id, new_state="completed", actor_id=self.worker_id, reason="provider read-back matched",
                provider_operation_id=readback.provider_operation_id, readback_evidence=evidence, expected_attempt=attempt,
            )
            self.metrics.commands_completed.labels(command_family=family, adapter=adapter.adapter_id).inc()
            return "completed", readback
        if readback.status is ReadbackStatus.MISMATCH:
            await self.commands.transition(
                tenant_id, command_id, new_state="failed", actor_id=self.worker_id, reason="provider read-back mismatch", expected_attempt=attempt,
            )
            self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="readback", result="mismatch").inc()
            self.metrics.commands_failed.labels(command_family=family, adapter=adapter.adapter_id, result="readback_mismatch").inc()
            return "failed", readback
        await self.commands.transition(
            tenant_id, command_id, new_state="reconciliation_required", actor_id=self.worker_id,
            reason=f"provider read-back {readback.status.value.lower()}", readback_evidence=evidence, expected_attempt=attempt,
        )
        self.metrics.adapter_failures.labels(adapter=adapter.adapter_id, operation="readback", result=readback.status.value.lower()).inc()
        self.metrics.commands_reconciliation_required.labels(command_family=family, adapter=adapter.adapter_id).inc()
        self._record(DispatchOutcome(command_id, attempt, "reconciliation_required", True, None, readback))
        raise UnknownOutcomeError(f"readback {readback.status.value}")

    async def _recover(self, operation: CommandOperation, envelope: CommandEnvelope, adapter: Adapter, ownership: Ownership, family: str, timeout: float, trace: Mapping[str, str] | None) -> DispatchOutcome:
        attempt = await self.commands.latest_attempt(operation.tenant_id, operation.command_id)
        context = self.context(operation, attempt=attempt, timeout=timeout, trace=trace, payload=envelope.payload)
        self.metrics.lease_expirations.inc()
        if operation.state == "dispatching":
            # The provider may or may not have received attempt N. Only a readback
            # can tell; treat the answer exactly like a post-acknowledgement readback.
            operation = await self.commands.transition(
                operation.tenant_id, operation.command_id, new_state="accepted", actor_id=self.worker_id,
                reason="recovering an expired dispatch lease: reading provider state back", expected_attempt=attempt,
            )
        elif operation.state == "readback_pending":
            # Already past acceptance; go straight to the readback below.
            pass
        readback = await self._readback(operation, adapter, context, ownership, attempt)
        return self._record(DispatchOutcome(operation.command_id, attempt, readback[0], False, None, readback[1]))

    async def _fail(self, operation: CommandOperation, *, reason: str, attempt: int | None, retryable: bool = False) -> None:
        tenant_id, command_id = operation.tenant_id, operation.command_id
        current = await self.commands.get(tenant_id, command_id)
        if current.state in {"persisted", "queued"}:
            # No attempt was opened: the ledger has no persisted → failed edge, so
            # move through queued → dead_lettered for a permanent refusal, or leave
            # it queued when the failure is retryable (the outbox backs off).
            if retryable:
                return
            if current.state == "persisted":
                await self.commands.transition(tenant_id, command_id, new_state="queued", actor_id=self.worker_id, reason="claimed by execution bus")
            await self.commands.transition(tenant_id, command_id, new_state="dead_lettered", actor_id=self.worker_id, reason=reason)
            return
        await self.commands.transition(tenant_id, command_id, new_state="failed", actor_id=self.worker_id, reason=reason, expected_attempt=attempt)
        if retryable:
            await self.commands.transition(tenant_id, command_id, new_state="queued", actor_id=self.worker_id, reason="scheduled for a known-safe retry")

    @staticmethod
    def _safe_reason(result: AdapterResult) -> str:
        parts = [part for part in (result.safe_error_code, result.error_class.value if result.error_class else None) if part]
        return ":".join(parts) if parts else result.outcome.value.lower()

    def _record(self, outcome: DispatchOutcome) -> DispatchOutcome:
        self.last_outcome = outcome
        return outcome


def _command_id_of(record: OutboxRecord) -> UUID | None:
    raw = record.payload.get("command_id") if isinstance(record.payload, Mapping) else None
    if not isinstance(raw, str):
        return None
    try:
        return UUID(raw)
    except ValueError:
        return None


def _campaign_id(payload: Mapping[str, Any]) -> str | None:
    value = payload.get("campaign_id")
    return value if isinstance(value, str) and value else None


__all__ = [
    "AdapterDispatch",
    "BusSettings",
    "DispatchOutcome",
    "UnknownOutcomeError",
    "worker_identity",
    "AUTHENTICATED_CLIENT_ID_KEY",
    "CommandConflict",
]
