"""Phases 20â€“23 â€” bulkheads, circuit breakers, central retry policy and the
REPROCESS / REEXECUTE distinction.

All of these are owned by the platform; adapters receive their effects
through :class:`app.platform.adapter.AdapterContext` and never re-implement
them.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


# --- retry ------------------------------------------------------------------


class RetryClass(StrEnum):
    SAFE_READ = "SAFE_READ"
    IDEMPOTENT_WRITE = "IDEMPOTENT_WRITE"
    NON_IDEMPOTENT_EFFECT = "NON_IDEMPOTENT_EFFECT"
    CALLBACK = "CALLBACK"
    RECONCILIATION = "RECONCILIATION"


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int
    base_delay_seconds: float
    max_delay_seconds: float
    # Whether a transport timeout (unknown provider outcome) may be retried
    # blindly. Only reads and provably idempotent writes may; everything else
    # must read back / reconcile first.
    retry_unknown_outcome: bool

    def delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter bounded by ``max_delay_seconds``."""
        exp = min(self.max_delay_seconds, self.base_delay_seconds * (2 ** max(0, attempt - 1)))
        return random.uniform(0, exp)


RETRY_POLICIES: dict[RetryClass, RetryPolicy] = {
    RetryClass.SAFE_READ: RetryPolicy(max_attempts=5, base_delay_seconds=0.2, max_delay_seconds=5.0, retry_unknown_outcome=True),
    RetryClass.IDEMPOTENT_WRITE: RetryPolicy(max_attempts=4, base_delay_seconds=0.5, max_delay_seconds=15.0, retry_unknown_outcome=True),
    RetryClass.NON_IDEMPOTENT_EFFECT: RetryPolicy(max_attempts=1, base_delay_seconds=0.0, max_delay_seconds=0.0, retry_unknown_outcome=False),
    RetryClass.CALLBACK: RetryPolicy(max_attempts=6, base_delay_seconds=1.0, max_delay_seconds=60.0, retry_unknown_outcome=True),
    RetryClass.RECONCILIATION: RetryPolicy(max_attempts=3, base_delay_seconds=2.0, max_delay_seconds=30.0, retry_unknown_outcome=True),
}


class OutcomeClass(StrEnum):
    """How an adapter attempt ended, from the platform's point of view."""

    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"  # provider refused deterministically; never retry
    TRANSIENT = "TRANSIENT"  # provider said 'not now'; retry per class
    UNKNOWN = "UNKNOWN"  # timeout / connection lost after send; effect unknown
    CANCELLED = "CANCELLED"


def may_retry(retry_class: RetryClass, outcome: OutcomeClass, attempt: int) -> bool:
    policy = RETRY_POLICIES[retry_class]
    if attempt >= policy.max_attempts:
        return False
    if outcome == OutcomeClass.TRANSIENT:
        return True
    if outcome == OutcomeClass.UNKNOWN:
        return policy.retry_unknown_outcome
    return False


# --- circuit breaker ----------------------------------------------------------


class BreakerState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpen(RuntimeError):
    pass


@dataclass
class CircuitBreaker:
    """Per provider/capability breaker. Failure counting is over consecutive
    attempts; ``open_seconds`` after opening, one probe attempt is admitted
    (HALF_OPEN) and its outcome closes or re-opens the breaker. Health probing
    never creates a live effect: the probe is the next real command."""

    name: str
    failure_threshold: int = 5
    open_seconds: float = 30.0
    half_open_max_probes: int = 1
    clock: Callable[[], float] = time.monotonic
    on_transition: Callable[[str, BreakerState, BreakerState], None] | None = None
    _state: BreakerState = field(default=BreakerState.CLOSED, init=False)
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _probes: int = field(default=0, init=False)

    @property
    def state(self) -> BreakerState:
        if self._state is BreakerState.OPEN and self.clock() - self._opened_at >= self.open_seconds:
            self._transition(BreakerState.HALF_OPEN)
            self._probes = 0
        return self._state

    def _transition(self, target: BreakerState) -> None:
        previous = self._state
        if previous is target:
            return
        self._state = target
        if self.on_transition is not None:
            self.on_transition(self.name, previous, target)

    def admit(self) -> None:
        state = self.state
        if state is BreakerState.CLOSED:
            return
        if state is BreakerState.HALF_OPEN and self._probes < self.half_open_max_probes:
            self._probes += 1
            return
        raise CircuitOpen(f"circuit {self.name} is {state}")

    def record_success(self) -> None:
        self._failures = 0
        if self._state is not BreakerState.CLOSED:
            self._transition(BreakerState.CLOSED)

    def record_failure(self) -> None:
        self._failures += 1
        if self._state is BreakerState.HALF_OPEN or self._failures >= self.failure_threshold:
            self._opened_at = self.clock()
            self._transition(BreakerState.OPEN)


# --- bulkhead -----------------------------------------------------------------


class BulkheadFull(RuntimeError):
    pass


@dataclass
class BulkheadStats:
    capacity: int
    active: int
    waiting: int
    rejected_total: int
    max_wait_seconds: float


class Bulkhead:
    """Bounded concurrency per provider family. A saturated family rejects
    (or times out) instead of consuming workers meant for other families."""

    def __init__(self, name: str, capacity: int, *, max_wait_seconds: float = 0.0) -> None:
        if capacity < 1:
            raise ValueError("bulkhead capacity must be >= 1")
        self.name = name
        self.capacity = capacity
        self.max_wait_seconds = max_wait_seconds
        self._semaphore = asyncio.Semaphore(capacity)
        self._active = 0
        self._waiting = 0
        self._rejected = 0
        self._max_wait = 0.0

    def stats(self) -> BulkheadStats:
        return BulkheadStats(self.capacity, self._active, self._waiting, self._rejected, self._max_wait)

    async def run(self, operation: Callable[[], Awaitable[T]]) -> T:
        started = time.monotonic()
        self._waiting += 1
        try:
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=self.max_wait_seconds or None)
            except asyncio.TimeoutError:
                self._rejected += 1
                raise BulkheadFull(f"bulkhead {self.name} saturated ({self.capacity})") from None
        finally:
            self._waiting -= 1
        self._max_wait = max(self._max_wait, time.monotonic() - started)
        self._active += 1
        try:
            return await operation()
        finally:
            self._active -= 1
            self._semaphore.release()


# --- reprocess vs reexecute ---------------------------------------------------


class ReplayMode(StrEnum):
    """REPROCESS repeats internal processing only (no new provider effect).
    REEXECUTE may issue another provider effect and requires explicit
    authorization plus fresh safety and idempotency decisions. No operator API
    may combine them."""

    REPROCESS = "REPROCESS"
    REEXECUTE = "REEXECUTE"
