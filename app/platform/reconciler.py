"""The reconciliation authority for adapter-executed commands.

An operation whose provider outcome is unknown sits in
``reconciliation_required`` with its outbox row quarantined. The reconciler
(``middleware-reconciler`` process, or the same code invoked in tests):

1. claims the quarantined outbox row with a lease (``FOR UPDATE SKIP LOCKED``),
2. asks the owning adapter to read the provider state back (``reconcile``),
3. normalises the answer,
4. compares expected vs actual,
5. transitions the ledger — ``MATCHED`` → ``completed``; ``NOT_FOUND`` (the
   effect provably never happened) → ``queued`` + a bounded retry of the same
   outbox row; ``MISMATCH`` → stays parked with the evidence, dead-lettered
   after the bounded reconciliation budget; ``UNAVAILABLE`` → stays parked
   and is retried on the next cycle, dead-lettered after the budget;
   ``UNSUPPORTED`` (the adapter has no read surface for this command — a
   deterministic answer that no retry changes) → dead-lettered at once with
   the reason recorded, so an acknowledged but unverifiable write never sits
   in the backlog burning the budget,
6. appends the immutable audit rows (command audit + outbox reconciliation audit).

It never issues a provider write merely because a readback failed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from app.commands import CommandNotFound, CommandService, redact_metadata
from app.core.config import Settings
from app.platform.adapter import AdapterContext, ReadbackResult, ReadbackStatus
from app.platform.metrics import KernelMetrics
from app.platform.registry import AdapterRegistry
from app.platform.bus import worker_identity

logger = logging.getLogger("codestra.platform.reconciler")

DEFAULT_RECONCILIATION_BUDGET = 6


@dataclass(frozen=True)
class ReconciliationClaim:
    outbox_id: int
    tenant_id: str
    command_id: UUID
    reconciliation_attempts: int


class ReconciliationSource(Protocol):
    """Where quarantined adapter-command rows come from (Postgres outbox or memory)."""

    async def claim(self, *, reconciler_id: str, lease_seconds: float) -> ReconciliationClaim | None: ...

    async def resolve(self, claim: ReconciliationClaim, *, reconciler_id: str, action: str, reason: str) -> None: ...

    async def release(self, claim: ReconciliationClaim, *, reconciler_id: str, reason: str) -> None: ...

    async def backlog(self) -> int: ...


@dataclass(frozen=True)
class ReconciliationDecision:
    command_id: UUID
    adapter_id: str | None
    readback: ReadbackResult | None
    action: str
    final_state: str


class Reconciler:
    def __init__(
        self,
        *,
        settings: Settings,
        commands: CommandService,
        registry: AdapterRegistry,
        source: ReconciliationSource,
        metrics: KernelMetrics,
        http: Any = None,
        budget: int = DEFAULT_RECONCILIATION_BUDGET,
        lease_seconds: float = 60.0,
        timeout_seconds: float = 30.0,
        reconciler_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.commands = commands
        self.registry = registry
        self.source = source
        self.metrics = metrics
        self.http = http
        self.budget = budget
        self.lease_seconds = lease_seconds
        self.timeout_seconds = timeout_seconds
        self.reconciler_id = reconciler_id or worker_identity("reconciler")

    async def run_once(self) -> ReconciliationDecision | None:
        claim = await self.source.claim(reconciler_id=self.reconciler_id, lease_seconds=self.lease_seconds)
        if claim is None:
            return None
        try:
            return await self._reconcile(claim)
        finally:
            try:
                self.metrics.reconciliation_backlog.set(await self.source.backlog())
            except Exception:  # metrics must not break the loop
                logger.debug("reconciliation_backlog_probe_failed", exc_info=True)

    async def run_forever(self, *, poll_seconds: float = 2.0) -> None:
        while True:
            decision = await self.run_once()
            if decision is None:
                await asyncio.sleep(poll_seconds)

    async def _reconcile(self, claim: ReconciliationClaim) -> ReconciliationDecision:
        try:
            operation = await self.commands.get(claim.tenant_id, claim.command_id)
        except CommandNotFound:
            await self.source.resolve(claim, reconciler_id=self.reconciler_id, action="dead_letter", reason="command row missing")
            return ReconciliationDecision(claim.command_id, None, None, "dead_letter", "missing")

        if operation.state == "completed":
            await self.source.resolve(claim, reconciler_id=self.reconciler_id, action="complete", reason="operation already completed")
            return ReconciliationDecision(claim.command_id, None, None, "complete", "completed")
        if operation.state in {"failed", "dead_lettered", "cancelled"}:
            await self.source.resolve(claim, reconciler_id=self.reconciler_id, action="dead_letter", reason=f"operation is terminal ({operation.state})")
            return ReconciliationDecision(claim.command_id, None, None, "dead_letter", operation.state)
        if operation.state != "reconciliation_required":
            # A worker still owns it (dispatching/accepted/readback_pending with a
            # live lease) or it was re-queued; leave it for the bus.
            await self.source.release(claim, reconciler_id=self.reconciler_id, reason=f"operation is {operation.state}; not awaiting reconciliation")
            return ReconciliationDecision(claim.command_id, None, None, "release", operation.state)

        ownership = self.registry.ownership(operation.command_type)
        if ownership is None:
            await self.source.release(claim, reconciler_id=self.reconciler_id, reason="no adapter owns this command in this process")
            return ReconciliationDecision(claim.command_id, None, None, "release", operation.state)
        adapter = self.registry.adapter(ownership.adapter_id)
        attempt = await self.commands.latest_attempt(claim.tenant_id, claim.command_id)
        envelope = await self.commands.load_envelope(claim.tenant_id, claim.command_id)
        context = AdapterContext(
            tenant_id=operation.tenant_id,
            command_id=str(operation.command_id),
            correlation_id=operation.correlation_id,
            attempt=attempt,
            timeout_seconds=self.timeout_seconds,
            environment=self.settings.app_env,
            deployment_sha=self.settings.source_sha,
            http=self.http,
            payload=envelope.payload,
        )
        self.metrics.adapter_requests.labels(adapter=adapter.adapter_id, operation="reconcile").inc()
        started = time.perf_counter()
        try:
            readback = await asyncio.wait_for(adapter.reconcile(operation, context), timeout=self.timeout_seconds)
        except Exception as exc:  # noqa: BLE001
            readback = ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        finally:
            self.metrics.adapter_latency.labels(adapter=adapter.adapter_id, operation="reconcile").observe(time.perf_counter() - started)

        evidence = {
            "schema_version": "1.0",
            "status": readback.status.value.lower(),
            "provider_operation_id": readback.provider_operation_id or operation.provider_operation_id,
            **redact_metadata(dict(readback.evidence)),
        }
        actor = self.reconciler_id
        family = operation.command_type.split(".", 1)[0]
        exhausted = claim.reconciliation_attempts >= self.budget or readback.status is ReadbackStatus.UNSUPPORTED

        if readback.status is ReadbackStatus.MATCHED:
            await self.commands.reconcile(
                claim.tenant_id,
                claim.command_id,
                matched=True,
                actor_id=actor,
                reason="reconciliation read-back matched",
                provider_operation_id=readback.provider_operation_id,
                evidence=evidence,
                idempotency_key=(
                    f"reconcile-worker:{claim.command_id}:"
                    f"{operation.resource_version}:{claim.reconciliation_attempts}:matched"
                ),
                expected_version=operation.resource_version,
            )
            await self.source.resolve(claim, reconciler_id=actor, action="complete", reason="reconciliation read-back matched")
            self.metrics.reconciliation_decisions.labels(adapter=adapter.adapter_id, result="completed").inc()
            self.metrics.commands_completed.labels(command_family=family, adapter=adapter.adapter_id).inc()
            return ReconciliationDecision(claim.command_id, adapter.adapter_id, readback, "complete", "completed")

        if readback.status is ReadbackStatus.NOT_FOUND and not exhausted:
            # The provider has no trace of the effect: re-executing is safe.
            await self.commands.transition(
                claim.tenant_id, claim.command_id, new_state="queued", actor_id=actor,
                reason="reconciliation proved no provider effect; re-queued", expected_attempt=attempt,
            )
            await self.source.resolve(claim, reconciler_id=actor, action="retry", reason="reconciliation proved no provider effect")
            self.metrics.reconciliation_decisions.labels(adapter=adapter.adapter_id, result="requeued").inc()
            return ReconciliationDecision(claim.command_id, adapter.adapter_id, readback, "retry", "queued")

        if readback.status is ReadbackStatus.MISMATCH:
            await self.commands.reconcile(
                claim.tenant_id,
                claim.command_id,
                matched=False,
                actor_id=actor,
                reason="reconciliation read-back mismatch",
                provider_operation_id=readback.provider_operation_id,
                evidence=evidence,
                idempotency_key=(
                    f"reconcile-worker:{claim.command_id}:"
                    f"{operation.resource_version}:{claim.reconciliation_attempts}:mismatch"
                ),
                expected_version=operation.resource_version,
            )
            self.metrics.reconciliation_decisions.labels(adapter=adapter.adapter_id, result="mismatch").inc()
        else:
            self.metrics.reconciliation_decisions.labels(adapter=adapter.adapter_id, result=readback.status.value.lower()).inc()

        if exhausted:
            if readback.status is ReadbackStatus.UNSUPPORTED:
                reason = f"provider read-back unsupported ({readback.safe_error_code or 'no read surface'}); operator verification required"
            else:
                reason = f"reconciliation budget exhausted after {readback.status.value.lower()}"
            await self.commands.transition(claim.tenant_id, claim.command_id, new_state="dead_lettered", actor_id=actor, reason=reason)
            await self.source.resolve(claim, reconciler_id=actor, action="dead_letter", reason=reason)
            self.metrics.commands_failed.labels(command_family=family, adapter=adapter.adapter_id, result="dead_lettered").inc()
            return ReconciliationDecision(claim.command_id, adapter.adapter_id, readback, "dead_letter", "dead_lettered")

        await self.source.release(claim, reconciler_id=actor, reason=f"read-back {readback.status.value.lower()}; will retry")
        return ReconciliationDecision(claim.command_id, adapter.adapter_id, readback, "release", "reconciliation_required")
