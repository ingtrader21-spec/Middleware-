from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any
from uuid import uuid4

import pytest

from app.commands import TEMPORAL_COMMAND_DESTINATION
from app.storage import OutboxRecord
from app.temporal_transport import RECONCILIATION_EVENT_TYPE
from workers.run_outbox import _load_reconciliation_command_id


class _Context(AbstractAsyncContextManager[Any]):
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


class FakeConnection:
    def __init__(self, command_id: str | None) -> None:
        self.command_id = command_id
        self.query = ""
        self.args: tuple[Any, ...] = ()

    async def fetchval(self, query: str, *args: Any) -> str | None:
        self.query = " ".join(query.split())
        self.args = args
        return self.command_id


class FakePool:
    def __init__(self, command_id: str | None) -> None:
        self.connection = FakeConnection(command_id)

    def acquire(self) -> _Context:
        return _Context(self.connection)


def reconciliation_record(command_id: str) -> OutboxRecord:
    return OutboxRecord(
        id=42,
        tenant_id="tenant-1",
        destination=TEMPORAL_COMMAND_DESTINATION,
        event_type=RECONCILIATION_EVENT_TYPE,
        idempotency_key="operation-reconcile:" + "b" * 64,
        payload={
            "command_id": command_id,
            "action": "reconcile",
            "reason": "verify provider state",
        },
        attempt_count=1,
    )


@pytest.mark.asyncio
async def test_lookup_binds_every_claimed_outbox_identity_field() -> None:
    command_id = str(uuid4())
    record = reconciliation_record(command_id)
    pool = FakePool(command_id)

    resolved = await _load_reconciliation_command_id(pool, record)  # type: ignore[arg-type]

    assert resolved == command_id
    assert pool.connection.args == (
        record.id,
        record.tenant_id,
        record.destination,
        record.event_type,
        record.idempotency_key,
    )
    assert "SELECT command_id FROM middleware_outbox" in pool.connection.query
    assert "completed_at IS NULL" in pool.connection.query
    assert "cancelled_at IS NULL" in pool.connection.query
    assert "dead_lettered_at IS NULL" in pool.connection.query


@pytest.mark.asyncio
async def test_lookup_fails_closed_when_outbox_has_no_command_identity() -> None:
    record = reconciliation_record(str(uuid4()))
    pool = FakePool(None)

    assert (
        await _load_reconciliation_command_id(pool, record)  # type: ignore[arg-type]
        is None
    )
