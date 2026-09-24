#!/usr/bin/env python3
from __future__ import annotations

import asyncio

import asyncpg
import httpx

from app.core.config import ConfigurationError, Settings
from app.core.runtime import build_runtime_container
from app.commands import ADAPTER_COMMAND_DESTINATION, ODOO_COMMAND_DESTINATION, TEMPORAL_COMMAND_DESTINATION
from app.nats_transport import NatsJetStreamPublisher
from app.klyrow_odoo_projection import KlyrowOdooProjectionDispatcher
from app.odoo_transport import OdooCommandDispatcher
from app.storage import (
    KLYROW_ODOO_PROJECTION_DESTINATION,
    NATS_JETSTREAM_DESTINATION,
    OutboxRecord,
    PostgresOutboxStore,
)
from app.temporal_runtime import connect_temporal
from app.temporal_transport import TemporalCommandDispatcher
from app.worker import Handler, OutboxWorker

SERVICE_MIDDLEWARE_WORKER = "middleware-worker"


async def _load_reconciliation_command_id(
    pool: asyncpg.Pool,
    record: OutboxRecord,
) -> str | None:
    """Read the trusted command identity from the exact durable outbox row."""

    async with pool.acquire() as conn:
        value = await conn.fetchval(
            """
            SELECT command_id
            FROM middleware_outbox
            WHERE id=$1
              AND tenant_id=$2
              AND destination=$3
              AND event_type=$4
              AND idempotency_key=$5
              AND completed_at IS NULL
              AND cancelled_at IS NULL
              AND dead_lettered_at IS NULL
            """,
            record.id,
            record.tenant_id,
            record.destination,
            record.event_type,
            record.idempotency_key,
        )
    return str(value) if value is not None else None


async def main() -> None:
    settings = Settings.from_env()
    temporal_enabled = settings.temporal_worker_mode != "disabled"
    odoo_enabled = settings.odoo_19_delivery_enabled
    klyrow_odoo_enabled = settings.klyrow_odoo_projection_enabled
    if settings.database_url is None:
        raise ConfigurationError("DATABASE_URL is required for the outbox worker")

    # The worker is the same RuntimeContainer as the API (one pool, one
    # kernel, one policy/safety/adapter registry, one schema check) in the
    # worker role; the container owns the pool and closes it.
    runtime = await build_runtime_container(settings, role="worker", service_id=SERVICE_MIDDLEWARE_WORKER)
    pool = runtime.pool
    assert pool is not None and runtime.platform is not None
    # V3: adapter dispatch is a worker mode of its own — a process whose only
    # enabled capability is owned by a kernel adapter (staging TEST_SYN, or
    # ODOO_WRITE for the CRM wrappers) must drain its adapter-command rows.
    adapter_dispatch_enabled = bool(runtime.platform.registry.enabled_adapter_ids())
    if (
        not settings.outbox_dispatch_enabled
        and not temporal_enabled
        and not odoo_enabled
        and not klyrow_odoo_enabled
        and not adapter_dispatch_enabled
    ):
        await runtime.close()
        raise ConfigurationError(
            "JetStream, Temporal, Odoo and adapter outbox dispatch are all "
            "intentionally disabled"
        )
    publisher: NatsJetStreamPublisher | None = None
    odoo_client: httpx.AsyncClient | None = None
    try:
        handlers: dict[str, Handler] = {}
        # V3: commands owned by a registered adapter execute through the
        # ExecutionBus (lease, quarantine-before-provider, readback, fencing);
        # the bus re-evaluates the Safety Gate per attempt, so a row for a
        # capability closed after enqueue fails closed instead of executing.
        handlers[ADAPTER_COMMAND_DESTINATION] = runtime.platform.dispatch
        if settings.outbox_dispatch_enabled:
            publisher = await NatsJetStreamPublisher.connect(settings)
            handlers[NATS_JETSTREAM_DESTINATION] = publisher.publish
        if temporal_enabled:
            temporal_client = await connect_temporal(settings)

            async def reconciliation_command_id(record: OutboxRecord) -> str | None:
                return await _load_reconciliation_command_id(pool, record)

            temporal_dispatcher = TemporalCommandDispatcher(
                temporal_client,
                settings.temporal_task_queue,
                reconciliation_command_id_lookup=reconciliation_command_id,
            )
            handlers[TEMPORAL_COMMAND_DESTINATION] = temporal_dispatcher.dispatch
        if odoo_enabled:
            # Registered only when ODOO_WRITE is on, so the handler cannot be
            # reached while the capability is closed.
            odoo_client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.odoo_timeout_seconds)
            )
            handlers[ODOO_COMMAND_DESTINATION] = OdooCommandDispatcher(
                client=odoo_client,
                base_url=settings.odoo_19_base_url or "",
                secrets=dict(settings.odoo_tenant_hmac_secrets),
                source_delivery_enabled=settings.odoo_source_delivery_enabled,
                default_secret=settings.odoo_default_hmac_secret or None,
            ).dispatch
        if klyrow_odoo_enabled:
            if odoo_client is None:
                odoo_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(settings.odoo_timeout_seconds)
                )
            handlers[KLYROW_ODOO_PROJECTION_DESTINATION] = (
                KlyrowOdooProjectionDispatcher(
                    client=odoo_client,
                    base_url=settings.odoo_19_base_url or "",
                    secrets=dict(settings.odoo_tenant_hmac_secrets),
                    default_secret=settings.odoo_default_hmac_secret or None,
                ).dispatch
            )
        worker = OutboxWorker(
            PostgresOutboxStore(pool),
            handlers,
        )
        await worker.run_forever()
    finally:
        if publisher is not None:
            await publisher.close()
        if odoo_client is not None:
            await odoo_client.aclose()
        await runtime.close()


if __name__ == "__main__":
    asyncio.run(main())
