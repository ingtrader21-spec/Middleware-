"""In-memory ExecutionBus and reconciliation source.

Used by the in-memory runtime (``ALLOW_IN_MEMORY_STORAGE``) and by the unit
certification suites. They run the *same* :class:`~app.platform.bus.AdapterDispatch`
handler and :class:`~app.platform.reconciler.Reconciler` as the PostgreSQL
processes; only the queue is a list. Semantics mirror
:class:`app.storage.PostgresOutboxStore`: one intent per command, claimed
with a lease, quarantined on unknown outcome, retried with a bounded attempt
budget, dead-lettered afterwards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable
from uuid import UUID

from app.commands import ADAPTER_COMMAND_DESTINATION, MemoryCommandStore, MemoryOutboxIntent
from app.platform.bus import AdapterDispatch, UnknownOutcomeError
from app.platform.reconciler import ReconciliationClaim
from app.storage import DEFAULT_MAX_OUTBOX_ATTEMPTS, OutboxRecord
from app.worker import KnownSafeRetryError


@dataclass
class MemoryBusStats:
    pending: int
    leased: int
    quarantined: int
    completed: int
    dead_lettered: int


@dataclass
class MemoryExecutionBus:
    store: MemoryCommandStore
    dispatch: AdapterDispatch
    max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS
    lease_seconds: float = 60.0
    clock: Callable[[], float] = time.monotonic
    worker_id: str = "memory-bus"
    processed: list[tuple[int, str]] = field(default_factory=list)

    def _claimable(self, intent: MemoryOutboxIntent) -> bool:
        return (
            intent.destination == ADAPTER_COMMAND_DESTINATION
            and intent.completed_at is None
            and intent.dead_lettered_at is None
            and intent.cancelled_at is None
            and intent.reconciliation_required_at is None
            and intent.attempt_count < self.max_attempts
            and intent.next_attempt_at <= self.clock()
            and (intent.lease_until is None or intent.lease_until < self.clock())
        )

    async def run_once(self) -> bool:
        intent = next((item for item in self.store._outbox if self._claimable(item)), None)
        if intent is None:
            return False
        intent.attempt_count += 1
        intent.lease_owner = self.worker_id
        intent.lease_until = self.clock() + self.lease_seconds
        # Quarantine before provider code, exactly like the durable worker.
        intent.reconciliation_required_at = self.clock()
        record = OutboxRecord(
            id=intent.id,
            tenant_id=intent.tenant_id,
            destination=intent.destination,
            event_type=intent.event_type,
            idempotency_key=intent.idempotency_key,
            payload=dict(intent.payload),
            attempt_count=intent.attempt_count,
        )
        try:
            await self.dispatch(record)
        except KnownSafeRetryError as exc:
            intent.reconciliation_required_at = None
            intent.lease_owner = None
            intent.lease_until = None
            intent.last_error = str(exc)[:2048]
            if intent.attempt_count >= self.max_attempts:
                intent.dead_lettered_at = self.clock()
                self.processed.append((intent.id, "dead_lettered"))
            else:
                intent.next_attempt_at = self.clock() + min(3600.0, float(2 ** min(intent.attempt_count, 10)))
                self.processed.append((intent.id, "retry"))
        except UnknownOutcomeError as exc:
            # Stays quarantined; the lease keeps other bus instances away until
            # it expires and the reconciler takes over.
            intent.last_error = str(exc)[:2048]
            self.processed.append((intent.id, "quarantined"))
        except Exception as exc:  # noqa: BLE001 - unknown outcome by definition
            intent.last_error = f"{type(exc).__name__}: {exc}"[:2048]
            self.processed.append((intent.id, "quarantined"))
        else:
            intent.reconciliation_required_at = None
            intent.lease_owner = None
            intent.lease_until = None
            intent.completed_at = self.clock()
            self.processed.append((intent.id, "completed"))
        return True

    async def drain(self, *, limit: int = 1000) -> int:
        count = 0
        while count < limit and await self.run_once():
            count += 1
        return count

    def stats(self) -> MemoryBusStats:
        rows = [item for item in self.store._outbox if item.destination == ADAPTER_COMMAND_DESTINATION]
        return MemoryBusStats(
            pending=sum(1 for item in rows if self._claimable(item)),
            leased=sum(1 for item in rows if item.lease_until is not None and item.lease_until >= self.clock() and item.completed_at is None),
            quarantined=sum(1 for item in rows if item.reconciliation_required_at is not None and item.completed_at is None and item.dead_lettered_at is None),
            completed=sum(1 for item in rows if item.completed_at is not None),
            dead_lettered=sum(1 for item in rows if item.dead_lettered_at is not None),
        )

    def expire_leases(self) -> int:
        """Test hook: simulate lease expiry (worker crash) for every leased row."""
        expired = 0
        for item in self.store._outbox:
            if item.lease_until is not None:
                item.lease_until = self.clock() - 1.0
                expired += 1
        return expired


@dataclass
class MemoryReconciliationSource:
    store: MemoryCommandStore
    clock: Callable[[], float] = time.monotonic
    resolutions: list[tuple[int, str, str]] = field(default_factory=list)

    async def claim(self, *, reconciler_id: str, lease_seconds: float) -> ReconciliationClaim | None:
        for item in self.store._outbox:
            if (
                item.destination == ADAPTER_COMMAND_DESTINATION
                and item.reconciliation_required_at is not None
                and item.completed_at is None
                and item.dead_lettered_at is None
                and (item.lease_until is None or item.lease_until < self.clock())
            ):
                item.lease_owner = reconciler_id
                item.lease_until = self.clock() + lease_seconds
                item.reconciliation_attempts += 1
                return ReconciliationClaim(
                    outbox_id=item.id,
                    tenant_id=item.tenant_id,
                    command_id=UUID(str(item.payload["command_id"])),
                    reconciliation_attempts=item.reconciliation_attempts,
                )
        return None

    def _item(self, claim: ReconciliationClaim, reconciler_id: str) -> MemoryOutboxIntent:
        for item in self.store._outbox:
            if item.id == claim.outbox_id:
                if item.lease_owner != reconciler_id:
                    raise RuntimeError("reconciliation lease is owned by another reconciler")
                return item
        raise RuntimeError("outbox intent does not exist")

    async def resolve(self, claim: ReconciliationClaim, *, reconciler_id: str, action: str, reason: str) -> None:
        item = self._item(claim, reconciler_id)
        item.lease_owner = None
        item.lease_until = None
        item.reconciliation_required_at = None
        item.last_error = reason[:2048]
        if action == "complete":
            item.completed_at = self.clock()
        elif action == "dead_letter":
            item.dead_lettered_at = self.clock()
        elif action == "retry":
            item.next_attempt_at = self.clock()
        else:
            raise ValueError(action)
        self.resolutions.append((item.id, action, reason))

    async def release(self, claim: ReconciliationClaim, *, reconciler_id: str, reason: str) -> None:
        item = self._item(claim, reconciler_id)
        item.lease_owner = None
        item.lease_until = None
        item.last_error = reason[:2048]
        self.resolutions.append((item.id, "release", reason))

    async def backlog(self) -> int:
        return sum(
            1
            for item in self.store._outbox
            if item.destination == ADAPTER_COMMAND_DESTINATION
            and item.reconciliation_required_at is not None
            and item.completed_at is None
            and item.dead_lettered_at is None
        )
