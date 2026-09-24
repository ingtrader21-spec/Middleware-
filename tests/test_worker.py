from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import Mock

import pytest

from app.storage import OutboxRecord, PostgresOutboxStore
from app.worker import KnownSafeRetryError, OutboxWorker


class FakeStore:
    def __init__(self, record: OutboxRecord | None) -> None:
        self.record = record
        self.claim_args: dict[str, Any] | None = None
        self.failed: list[tuple[int, dict[str, Any]]] = []
        self.quarantined: list[tuple[int, dict[str, Any]]] = []
        self.renewed: list[tuple[int, dict[str, Any]]] = []
        self.resolved: list[tuple[int, dict[str, Any]]] = []
        self.events: list[str] = []
        self.quarantine_error: Exception | None = None

    async def claim(self, **kwargs):
        self.claim_args = kwargs
        record, self.record = self.record, None
        return record

    async def fail(self, record_id: int, **kwargs):
        self.events.append("fail")
        self.failed.append((record_id, kwargs))

    async def quarantine_unknown_outcome(self, record_id: int, **kwargs):
        self.events.append("quarantine")
        if self.quarantine_error is not None:
            raise self.quarantine_error
        self.quarantined.append((record_id, kwargs))

    async def renew_active_dispatch(self, record_id: int, **kwargs):
        self.events.append("renew")
        self.renewed.append((record_id, kwargs))

    async def resolve_reconciliation(self, record_id: int, **kwargs):
        self.events.append(f"resolve:{kwargs['action']}")
        self.resolved.append((record_id, kwargs))


def record() -> OutboxRecord:
    return OutboxRecord(
        id=1,
        tenant_id="tenant-1",
        destination="provider",
        event_type="codestra.test.event",
        idempotency_key="idem-12345678",
        payload={"ok": True},
        attempt_count=1,
    )


@pytest.mark.asyncio
async def test_worker_refreshes_lease_before_handler_and_resolves_success_as_owner() -> None:
    store = FakeStore(record())
    observed = []

    async def handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        observed.append(item.idempotency_key)

    worker = OutboxWorker(
        store,  # type: ignore[arg-type]
        {"provider": handler},
        lease_seconds=60,
        handler_timeout_seconds=45,
    )
    assert await worker.run_once() is True
    assert observed == ["idem-12345678"]
    assert store.events[0:2] == ["quarantine", "handler"]
    assert store.events[-1] == "resolve:complete"
    assert store.quarantined[0][1]["worker_id"] == worker.worker_id
    assert store.quarantined[0][1]["lease_seconds"] == 60
    assert store.resolved[0][1]["action"] == "complete"
    assert store.resolved[0][1]["worker_id"] == worker.worker_id


@pytest.mark.asyncio
async def test_pre_dispatch_quarantine_failure_prevents_handler_invocation() -> None:
    store = FakeStore(record())
    store.quarantine_error = RuntimeError("database unavailable")
    invoked = False

    async def handler(item: OutboxRecord) -> None:
        nonlocal invoked
        invoked = True

    worker = OutboxWorker(store, {"provider": handler})  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="database unavailable"):
        await worker.run_once()
    assert invoked is False
    assert store.events == ["quarantine"]
    assert not store.resolved


@pytest.mark.asyncio
async def test_handler_timeout_leaves_precommitted_active_quarantine() -> None:
    store = FakeStore(record())

    async def slow_handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        await asyncio.sleep(0.05)

    worker = OutboxWorker(
        store,  # type: ignore[arg-type]
        {"provider": slow_handler},
        lease_seconds=0.1,
        handler_timeout_seconds=0.01,
        max_attempts=8,
    )
    assert await worker.run_once() is True
    assert store.quarantined
    assert store.quarantined[0][1]["lease_seconds"] == 0.1
    assert not store.failed
    assert not store.resolved
    assert store.events[:2] == ["quarantine", "handler"]
    assert store.claim_args is not None
    assert store.claim_args["max_attempts"] == 8
    assert store.claim_args["lease_seconds"] == 0.1


@pytest.mark.asyncio
async def test_heartbeat_continues_while_cancelled_handler_suppresses_cancellation() -> None:
    store = FakeStore(record())
    cancelled = asyncio.Event()

    async def cancellation_suppressing_handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            # Simulate a provider coroutine that performs cleanup / response work
            # after cancellation instead of terminating immediately.
            await asyncio.sleep(0.06)
            return

    worker = OutboxWorker(
        store,  # type: ignore[arg-type]
        {"provider": cancellation_suppressing_handler},
        lease_seconds=0.06,
        handler_timeout_seconds=0.01,
        max_attempts=8,
    )
    assert await worker.run_once() is True
    assert cancelled.is_set()
    assert store.renewed, "lease heartbeat must continue until handler actually terminates"
    assert all(item[1]["worker_id"] == worker.worker_id for item in store.renewed)
    assert all(item[1]["lease_seconds"] == 0.06 for item in store.renewed)
    # A timeout remains an unknown outcome even if the cancellation-suppressing
    # coroutine later returns; do not auto-complete or retry it.
    assert not store.resolved
    assert not store.failed


@pytest.mark.asyncio
async def test_known_safe_retry_reported_after_timeout_stays_quarantined() -> None:
    store = FakeStore(record())

    async def late_safe_retry_handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await asyncio.sleep(0.02)
            raise KnownSafeRetryError("too late to prove safe after timeout")

    worker = OutboxWorker(
        store,  # type: ignore[arg-type]
        {"provider": late_safe_retry_handler},
        lease_seconds=0.06,
        handler_timeout_seconds=0.01,
        max_attempts=8,
    )
    assert await worker.run_once() is True
    assert store.quarantined
    assert not store.failed
    assert not store.resolved


@pytest.mark.asyncio
async def test_generic_handler_exception_leaves_precommitted_active_quarantine() -> None:
    store = FakeStore(record())

    async def ambiguous_handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        raise ConnectionError("provider accepted request then connection reset")

    worker = OutboxWorker(store, {"provider": ambiguous_handler})  # type: ignore[arg-type]
    assert await worker.run_once() is True
    assert store.quarantined
    assert not store.failed
    assert not store.resolved
    assert store.events[0:2] == ["quarantine", "handler"]


@pytest.mark.asyncio
async def test_explicit_known_safe_retry_resolves_quarantine_as_owner() -> None:
    store = FakeStore(record())

    async def safe_retry_handler(item: OutboxRecord) -> None:
        store.events.append("handler")
        raise KnownSafeRetryError("provider rejected request before dispatch")

    worker = OutboxWorker(store, {"provider": safe_retry_handler})  # type: ignore[arg-type]
    assert await worker.run_once() is True
    assert store.quarantined
    assert not store.failed
    assert store.resolved
    assert store.resolved[0][1]["action"] == "retry"
    assert store.resolved[0][1]["max_attempts"] == 8
    assert store.resolved[0][1]["worker_id"] == worker.worker_id
    assert store.events[-1] == "resolve:retry"


@pytest.mark.asyncio
async def test_handler_returning_future_completes_under_owned_quarantine() -> None:
    store = FakeStore(record())
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def handler(item: OutboxRecord) -> asyncio.Future[None]:
        assert item.idempotency_key == "idem-12345678"
        store.events.append("handler")
        asyncio.get_running_loop().call_soon(future.set_result, None)
        return future

    worker = OutboxWorker(Mock(spec=PostgresOutboxStore, wraps=store), {"provider": handler})
    assert await worker.run_once() is True
    assert future.done()
    assert store.events[:2] == ["quarantine", "handler"]
    assert store.events[-1] == "resolve:complete"
    assert store.resolved[0][1]["worker_id"] == worker.worker_id
