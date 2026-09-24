"""V3 command kernel on disposable PostgreSQL: the same kernel, ExecutionBus
(the real OutboxWorker over middleware_outbox) and reconciler as production,
against the runtime SQL schema — idempotency concurrency proof, execution to
completion through a MATCHED readback, quarantine + reconciliation, lease
expiry recovery, two workers one effect, fencing, cancel, and the denial
audit in middleware_control_audit.

RUNTIME_INTEGRATION_TESTS=1 with a disposable DATABASE_URL (see conftest).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import pytest
import pytest_asyncio

from app.commands import ADAPTER_COMMAND_DESTINATION, CommandConflict, CommandEnvelope, CommandService, PostgresCommandStore
from app.control_plane_auth import ControlPlaneCaller
from app.core.config import Settings
from app.platform.adapter import ReadbackStatus
from app.platform.adapters.fixtures import FixtureAdapter, development_fixtures
from app.platform.bus import BusSettings
from app.platform.kernel import SafetyDenied
from app.platform.principal import KernelPrincipal
from app.platform.runtime import build_platform_runtime, command_policies
from app.storage import PostgresOutboxStore
from app.worker import OutboxWorker

DATABASE_URL = os.getenv("DATABASE_URL", "")
RUN = os.getenv("RUNTIME_INTEGRATION_TESTS") == "1"
pytestmark = pytest.mark.skipif(not RUN, reason="set RUNTIME_INTEGRATION_TESTS=1 against disposable PostgreSQL/Redis")
TENANT = "TEST_SYN"
TABLES = (
    "middleware_outbox_attempt_events",
    "middleware_control_mutations",
    "middleware_control_audit",
    "middleware_operation_mutations",
    "middleware_event_ledger",
    "middleware_reconciliation_audit",
    "middleware_outbox",
    "middleware_inbox",
    "middleware_schema_migrations",
    "middleware_command_audit",
    "middleware_command_attempts",
    "middleware_commands",
)


@pytest_asyncio.fixture
async def pool() -> asyncpg.Pool:
    assert DATABASE_URL, "DATABASE_URL is required"
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)
    migrations = [path.read_text(encoding="utf-8") for path in sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))]
    async with pool.acquire() as conn:
        for table in TABLES:
            await conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
        for migration in migrations:
            await conn.execute(migration)
    try:
        yield pool
    finally:
        await pool.close()


def _settings(monkeypatch) -> Settings:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "false")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    return Settings.from_env()


def _principal() -> KernelPrincipal:
    caller = ControlPlaneCaller(client_id="middleware-api", command_scope="platform.command", status_scope="platform.command.read", allowed_command_prefixes=("test.syn.",), allowed_targets=frozenset({"test-syn"}), connector_commands_allowed=True, compatibility_only=False)
    return KernelPrincipal(subject="user-1", client_id="middleware-api", tenants=(TENANT,), roles=(), scopes=("platform.command", "platform.command.read"), caller=caller)


def _envelope(**updates: Any) -> CommandEnvelope:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": "test.syn.execute.v1",
        "command_version": "1.0",
        "target": "test-syn",
        "tenant_id": TENANT,
        "requested_by": "user-1",
        "correlation_id": "corr-" + uuid4().hex[:12],
        "idempotency_key": "idem-" + uuid4().hex,
        "capability": "TEST_SYN_EXECUTE",
        "payload": {"probe": True},
    }
    value.update(updates)
    return CommandEnvelope.model_validate(value)


class Stack:
    def __init__(self, settings: Settings, pool: asyncpg.Pool, *, worker_id: str = "worker-a", bus_settings: BusSettings | None = None) -> None:
        self.settings = settings
        self.pool = pool
        self.store = PostgresCommandStore(pool, owns_pool=False)
        self.commands = CommandService(store=self.store, policies=command_policies(settings))
        self.platform = build_platform_runtime(settings, commands=self.commands, http=None, pool=pool, service_id="middleware-integration-api", adapters=development_fixtures(), bus_settings=bus_settings)
        assert self.platform.registry_error is None, self.platform.registry_error
        self.platform.dispatch.worker_id = worker_id
        self.outbox = PostgresOutboxStore(pool)
        self.worker = OutboxWorker(self.outbox, {ADAPTER_COMMAND_DESTINATION: self.platform.dispatch}, poll_seconds=0.01, lease_seconds=60.0, handler_timeout_seconds=45.0, max_attempts=3)
        self.worker.worker_id = worker_id

    @property
    def test_syn(self) -> FixtureAdapter:
        return self.platform.registry.adapter("test-syn")  # type: ignore[return-value]

    async def submit(self, command: CommandEnvelope):
        return await self.platform.kernel.submit(command, _principal())

    async def outbox_rows(self, command_id: UUID) -> list[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return await conn.fetch("SELECT * FROM middleware_outbox WHERE tenant_id=$1 AND command_id=$2 ORDER BY id", TENANT, str(command_id))


@pytest.mark.asyncio
async def test_hundred_concurrent_identical_submissions(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    command = _envelope()
    results = await asyncio.gather(*(stack.submit(command) for _ in range(100)))
    assert {item.operation.command_id for item in results} == {command.command_id}
    assert sum(1 for item in results if not item.duplicate) == 1
    assert sum(1 for item in results if item.duplicate) == 99
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM middleware_commands WHERE tenant_id=$1", TENANT) == 1
        assert await conn.fetchval("SELECT count(*) FROM middleware_outbox WHERE tenant_id=$1 AND destination=$2", TENANT, ADAPTER_COMMAND_DESTINATION) == 1
        metadata = await conn.fetchval("SELECT metadata FROM middleware_command_audit WHERE tenant_id=$1 AND command_id=$2 ORDER BY id LIMIT 1", TENANT, str(command.command_id))
    assert '"policy_allow": true' in metadata.replace('":', '": ') or "policy_allow" in metadata
    conflicting = await asyncio.gather(*(stack.submit(command.model_copy(update={"payload": {"probe": "changed"}})) for _ in range(10)), return_exceptions=True)
    assert all(isinstance(item, CommandConflict) for item in conflicting)
    # execute exactly once
    assert await stack.worker.run_once() is True
    assert stack.test_syn.provider_effects == 1
    operation = await stack.commands.get(TENANT, command.command_id)
    assert operation.state == "completed" and operation.readback_evidence_sha256
    rows = await stack.outbox_rows(command.command_id)
    assert len(rows) == 1 and rows[0]["completed_at"] is not None and rows[0]["reconciliation_required_at"] is None
    events = await stack.commands.list_events(TENANT, command.command_id, limit=20)
    assert [event.new_state for event in events] == ["persisted", "queued", "dispatching", "accepted", "readback_pending", "completed"]
    assert [event.event_id for event in events] == sorted(event.event_id for event in events)


@pytest.mark.asyncio
async def test_unknown_outcome_is_quarantined_then_reconciled(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    command = _envelope(payload={"fixture": "unknown"})
    await stack.submit(command)
    assert await stack.worker.run_once() is True
    operation = await stack.commands.get(TENANT, command.command_id)
    assert operation.state == "reconciliation_required"
    rows = await stack.outbox_rows(command.command_id)
    assert rows[0]["reconciliation_required_at"] is not None and rows[0]["completed_at"] is None
    assert await stack.worker.run_once() is False  # quarantined rows are never re-claimed by the bus
    # the reconciler must wait for the worker lease to expire
    async with pool.acquire() as conn:
        await conn.execute("UPDATE middleware_outbox SET lease_until=now() - interval '1 second' WHERE command_id=$1", str(command.command_id))
    reconciler = stack.platform.reconciler
    assert reconciler is not None
    decision = await reconciler.run_once()
    assert decision is not None and decision.action == "complete"
    operation = await stack.commands.get(TENANT, command.command_id)
    assert operation.state == "completed" and operation.readback_evidence["reconciled"] is True
    assert stack.test_syn.provider_effects == 1
    async with pool.acquire() as conn:
        audit = await conn.fetch("SELECT action FROM middleware_reconciliation_audit ORDER BY id")
        claims = await conn.fetchval("SELECT count(*) FROM middleware_control_audit WHERE resource_kind='outbox_reconciliation'")
    assert [row["action"] for row in audit] == ["complete"] and claims == 1


@pytest.mark.asyncio
async def test_lease_expiry_recovers_by_readback_without_resend(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    command = _envelope()
    await stack.submit(command)
    # Simulate a worker that opened the attempt, reached the provider and died.
    await stack.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="dead", reason="q")
    await stack.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="dead", reason="attempt 1")
    stack.test_syn.effects[str(command.command_id)] = 1
    async with pool.acquire() as conn:
        await conn.execute("UPDATE middleware_outbox SET lease_owner='dead', lease_until=now() - interval '1 second', attempt_count=1 WHERE command_id=$1", str(command.command_id))
    assert await stack.worker.run_once() is True
    operation = await stack.commands.get(TENANT, command.command_id)
    assert operation.state == "completed"
    assert stack.test_syn.executed == []  # readback discovered the effect; nothing re-sent
    assert stack.test_syn.effects[str(command.command_id)] == 1


@pytest.mark.asyncio
async def test_two_workers_one_command_one_effect(pool: asyncpg.Pool, monkeypatch) -> None:
    settings = _settings(monkeypatch)
    first = Stack(settings, pool, worker_id="worker-a")
    second = Stack(settings, pool, worker_id="worker-b")
    # both stacks share the ledger; the fixture adapter instances differ, so count effects across both
    command = _envelope()
    await first.submit(command)
    claimed = await asyncio.gather(first.worker.run_once(), second.worker.run_once())
    assert sorted(claimed) == [False, True]
    assert first.test_syn.provider_effects + second.test_syn.provider_effects == 1
    assert (await first.commands.get(TENANT, command.command_id)).state == "completed"


@pytest.mark.asyncio
async def test_stale_attempt_fencing_and_cancel_semantics(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    fresh = _envelope()
    await stack.submit(fresh)
    cancelled = await stack.platform.kernel.cancel(TENANT, fresh.command_id, principal=_principal(), idempotency_key="cancel-0000001", expected_version=1, reason="operator")
    assert cancelled.state == "cancelled"
    rows = await stack.outbox_rows(fresh.command_id)
    assert rows[0]["cancelled_at"] is not None
    assert await stack.worker.run_once() is False  # a cancelled intent is never claimed

    command = _envelope()
    await stack.submit(command)
    await stack.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="w", reason="q")
    await stack.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="w", reason="attempt 1")
    await stack.commands.transition(TENANT, command.command_id, new_state="failed", actor_id="w", reason="x", expected_attempt=1)
    await stack.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="w", reason="retry")
    await stack.commands.transition(TENANT, command.command_id, new_state="dispatching", actor_id="w", reason="attempt 2")
    with pytest.raises(CommandConflict, match="stale attempt fencing"):
        await stack.commands.transition(TENANT, command.command_id, new_state="accepted", actor_id="stale", reason="late", expected_attempt=1)
    assert await stack.commands.latest_attempt(TENANT, command.command_id) == 2
    # A dispatching operation whose worker vanished is recovered by readback, never re-sent.
    stack.test_syn.effects[str(command.command_id)] = 1
    assert await stack.worker.run_once() is True
    assert (await stack.commands.get(TENANT, command.command_id)).state == "completed"
    assert stack.test_syn.executed == []


@pytest.mark.asyncio
async def test_reconciler_requeues_not_found_and_dead_letters_after_budget(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    lost = _envelope()
    stack.test_syn.scripts[str(lost.command_id)] = ["crash", "success"]
    await stack.submit(lost)
    await stack.worker.run_once()
    assert (await stack.commands.get(TENANT, lost.command_id)).state == "reconciliation_required"
    stack.test_syn.effects.pop(str(lost.command_id), None)  # provider has no trace: the effect never happened
    async with pool.acquire() as conn:
        await conn.execute("UPDATE middleware_outbox SET lease_until=now() - interval '1 second' WHERE command_id=$1", str(lost.command_id))
    decision = await stack.platform.reconciler.run_once()
    assert decision.action == "retry" and decision.final_state == "queued"
    assert await stack.worker.run_once() is True
    assert (await stack.commands.get(TENANT, lost.command_id)).state == "completed"

    stuck = _envelope(payload={"fixture": "unknown"})
    await stack.submit(stuck)
    await stack.worker.run_once()
    stack.test_syn.reconcile_as[str(stuck.command_id)] = ReadbackStatus.MISMATCH
    stack.platform.reconciler.budget = 2
    for _ in range(2):
        async with pool.acquire() as conn:
            await conn.execute("UPDATE middleware_outbox SET lease_until=now() - interval '1 second' WHERE command_id=$1", str(stuck.command_id))
        decision = await stack.platform.reconciler.run_once()
    assert decision.action == "dead_letter"
    assert (await stack.commands.get(TENANT, stuck.command_id)).state == "dead_lettered"
    rows = await stack.outbox_rows(stuck.command_id)
    assert rows[0]["dead_lettered_at"] is not None


@pytest.mark.asyncio
async def test_denials_are_audited_and_backlog_is_bounded(pool: asyncpg.Pool, monkeypatch) -> None:
    stack = Stack(_settings(monkeypatch), pool)
    with pytest.raises(SafetyDenied):
        await stack.platform.kernel.submit(_envelope(command_type="crm.contact.create.v1", target="odoo-19", capability="ODOO_WRITE"), KernelPrincipal(subject="user-1", client_id="odoo-integration", tenants=(TENANT,), roles=(), scopes=("platform.command",), caller=ControlPlaneCaller(client_id="odoo-integration", command_scope="platform.command", status_scope="platform.command.read", allowed_command_prefixes=("crm.",), allowed_targets=frozenset({"odoo-19"}), connector_commands_allowed=True, compatibility_only=False)))
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT action, new_state, reason, metadata FROM middleware_control_audit WHERE resource_kind='command_submission'")
    assert row["action"] == "safety_deny" and row["new_state"] == "denied"
    assert "capability" in row["metadata"] and "secret" not in row["metadata"].lower()
    tenant_active, global_active = await stack.commands.backlog(TENANT)
    assert tenant_active == 0 and global_active == 0
    await stack.submit(_envelope())
    assert await stack.commands.backlog(TENANT) == (1, 1)


@pytest.mark.asyncio
async def test_chaos_b_rollback_leaves_no_orphan_command_or_intent(pool: asyncpg.Pool, monkeypatch) -> None:
    """Chaos B: a failure after the command insert but before the outbox intent
    rolls the whole acceptance back (no command, no audit, no intent)."""
    stack = Stack(_settings(monkeypatch), pool)
    command = _envelope()
    original = stack.store.submit_on_connection

    class CrashingConnection:
        """Proxies the pooled connection; the outbox insert raises after the
        command row and its audit are already written inside the transaction."""

        def __init__(self, conn) -> None:
            self._conn = conn

        def __getattr__(self, name):
            return getattr(self._conn, name)

        async def execute(self, query, *args, **kw):
            if "INSERT INTO middleware_outbox" in query:
                raise RuntimeError("simulated crash before the outbox intent")
            return await self._conn.execute(query, *args, **kw)

    async def crash_after_command_insert(conn, envelope, **kwargs):
        return await original(CrashingConnection(conn), envelope, **kwargs)

    stack.store.submit_on_connection = crash_after_command_insert  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated crash"):
        await stack.submit(command)
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM middleware_commands WHERE command_id=$1", str(command.command_id)) == 0
        assert await conn.fetchval("SELECT count(*) FROM middleware_command_audit WHERE command_id=$1", str(command.command_id)) == 0
        assert await conn.fetchval("SELECT count(*) FROM middleware_outbox WHERE command_id=$1", str(command.command_id)) == 0
    stack.store.submit_on_connection = original  # type: ignore[method-assign]
    accepted = await stack.submit(command)  # the client retry is a clean first acceptance
    assert accepted.duplicate is False


@pytest.mark.asyncio
async def test_chaos_j_restart_keeps_operation_idempotency_and_timeline(pool: asyncpg.Pool, monkeypatch) -> None:
    """Chaos J: a fresh process (new container, new adapters, new worker) over the
    same database continues from the durable state; the retry is a replay."""
    settings = _settings(monkeypatch)
    before = Stack(settings, pool, worker_id="worker-before")
    command = _envelope()
    accepted = await before.submit(command)
    assert accepted.duplicate is False
    await before.commands.transition(TENANT, command.command_id, new_state="queued", actor_id="w", reason="q")
    # "restart": everything in memory is gone
    after = Stack(settings, pool, worker_id="worker-after")
    replay = await after.submit(command)
    assert replay.duplicate is True and replay.operation.state == "queued"
    assert await after.worker.run_once() is True
    operation = await after.commands.get(TENANT, command.command_id)
    assert operation.state == "completed"
    events = await after.commands.list_events(TENANT, command.command_id, limit=20)
    assert [event.new_state for event in events] == ["persisted", "queued", "dispatching", "accepted", "readback_pending", "completed"]
    assert after.test_syn.provider_effects == 1 and before.test_syn.provider_effects == 0
