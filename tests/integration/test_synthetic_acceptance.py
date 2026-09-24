from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from typing import Any
import uuid

import asyncpg
import httpx
import nats
from nats.js.api import StorageType, StreamConfig
import pytest
from redis.asyncio import Redis
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from app.core.config import Settings
from app.main import create_app
from app.nats_transport import NatsJetStreamPublisher
from app.replay import RedisReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import (
    NATS_JETSTREAM_DESTINATION,
    PostgresInboxStore,
    PostgresOutboxStore,
)
from app.temporal_workflows import (
    ActivityResult,
    ReconciliationRequest,
    ReconciliationWorkflow,
)
from app.worker import OutboxWorker


DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")
NATS_URL = os.getenv("NATS_TEST_URL", "")
STREAM = "CODESTRA_TEST_EVENTS"
SUBJECT_PREFIX = "codestra.test.events"
TASK_QUEUE = "codestra-test-synthetic-acceptance"
SECRET = b"synthetic-e2e-secret-at-least-thirty-two-bytes"
RUN = (
    os.getenv("RUNTIME_INTEGRATION_TESTS") == "1"
    and os.getenv("NATS_INTEGRATION_TESTS") == "1"
    and os.getenv("TEMPORAL_INTEGRATION_TESTS") == "1"
)

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="run only through the disposable synthetic acceptance gate",
)


class SyntheticTokenVerifier:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id

    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        if (
            authorization != "Bearer synthetic-odoo-token"
            or expected_client_id != "odoo-integration"
            or required_scope != "odoo.events.publish"
        ):
            raise AssertionError("synthetic request used an unexpected identity contract")
        return {
            "azp": expected_client_id,
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": self.tenant_id,
        }

    async def ready(self) -> bool:
        return True


class SyntheticReconciliationActivity:
    def __init__(self, event_id: str, tenant_id: str) -> None:
        self.event_id = event_id
        self.tenant_id = tenant_id
        self.calls = 0

    @activity.defn(name="reconcile_operation")
    async def reconcile_operation(
        self,
        request: ReconciliationRequest,
    ) -> ActivityResult:
        self.calls += 1
        assert request.operation_id == self.event_id
        assert request.tenant_id == self.tenant_id
        assert request.reason == "canonical event observed on isolated JetStream"
        return ActivityResult("completed", "synthetic evidence reconciled")


async def apply_migrations(pool: asyncpg.Pool) -> None:
    migrations = sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))
    assert migrations
    async with pool.acquire() as connection:
        for migration in migrations:
            await connection.execute(migration.read_text(encoding="utf-8"))


def signed_request(
    *,
    event_id: str,
    tenant_id: str,
) -> tuple[bytes, dict[str, str]]:
    now = int(time.time())
    occurred_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    event: dict[str, Any] = {
        "event_id": event_id,
        "event_type": "codestra.odoo.activity.completed",
        "event_version": "1.0",
        "occurred_at": occurred_at,
        "received_at": occurred_at,
        "source": "odoo-integration",
        "tenant_id": tenant_id,
        "correlation_id": f"corr-{event_id}",
        "causation_id": "synthetic-acceptance-e2e",
        "idempotency_key": event_id,
        "payload": {
            "synthetic_acceptance": True,
            "external_provider_effects": False,
        },
        "metadata": {"test": "disposable-synthetic-acceptance-v1"},
    }
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    timestamp = str(now)
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "v1",
            "POST",
            "/api/v1/odoo/events",
            timestamp,
            event_id,
            "odoo-integration",
            body_sha,
        )
    ).encode("utf-8")
    signature = hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
    return body, {
        "Authorization": "Bearer synthetic-odoo-token",
        "Content-Type": "application/json",
        "Idempotency-Key": event_id,
        "X-Codestra-Event-Id": event_id,
        "X-Codestra-Event-Type": event["event_type"],
        "X-Codestra-Source": event["source"],
        "X-Codestra-Tenant-Id": tenant_id,
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Signature": f"sha256={signature}",
        "X-Correlation-Id": event["correlation_id"],
    }


@pytest.mark.asyncio
async def test_disposable_api_ledger_redis_jetstream_temporal_journey() -> None:
    assert DATABASE_URL
    assert REDIS_URL
    assert NATS_URL == "nats://127.0.0.1:4222"
    unique = uuid.uuid4().hex
    event_id = f"synthetic-{unique}"
    tenant_id = f"tenant-synthetic-{unique}"

    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)
    redis_client = Redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    nats_client = None
    publisher = None
    try:
        await apply_migrations(pool)
        inbox = PostgresInboxStore(pool)
        await inbox.verify_schema()
        replay = RedisReplayGuard(redis_client)
        assert await replay.ready()

        nats_client = await nats.connect(NATS_URL)
        jetstream = nats_client.jetstream()
        try:
            await jetstream.delete_stream(STREAM)
        except Exception:
            pass
        await jetstream.add_stream(
            config=StreamConfig(
                name=STREAM,
                subjects=[f"{SUBJECT_PREFIX}.>"],
                storage=StorageType.FILE,
                duplicate_window=120.0,
                num_replicas=1,
            )
        )
        consumer = await jetstream.pull_subscribe(
            f"{SUBJECT_PREFIX}.>",
            durable="codestra-test-synthetic-acceptance",
            stream=STREAM,
        )

        settings = Settings.from_env(
            {
                "APP_ENV": "test",
                "DATABASE_URL": DATABASE_URL,
                "REDIS_URL": REDIS_URL,
                "NATS_URL": NATS_URL,
                "NATS_STREAM": STREAM,
                "NATS_SUBJECT_PREFIX": SUBJECT_PREFIX,
                "NATS_DISPATCH_MODE": "isolated",
                "NATS_ALLOW_INSECURE_TEST_CONNECTION": "true",
                "SEND_EVENTS": "true",
                "OUTBOX_DISPATCH_ENABLED": "true",
                "WEBHOOK_SECRET_ODOO_INTEGRATION": SECRET.decode("utf-8"),
            }
        )
        runtime = Runtime(
            settings=settings,
            inbox=inbox,
            replay=replay,
            tokens=SyntheticTokenVerifier(tenant_id),
        )
        app = create_app(settings=settings, runtime=runtime)
        body, headers = signed_request(event_id=event_id, tenant_id=tenant_id)

        # Hold the exact Redis replay key first so the API proves it honors the
        # shared replay guard before any PostgreSQL acceptance occurs.
        replay_token = await replay.acquire(tenant_id, event_id)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://middleware.test",
            ) as client:
                blocked = await client.post(
                    "/api/v1/odoo/events",
                    content=body,
                    headers=headers,
                )
                assert blocked.status_code == 409
                assert blocked.json()["error"]["code"] == "processing_conflict"
                await replay.release(tenant_id, event_id, replay_token)

                accepted = await client.post(
                    "/api/v1/odoo/events",
                    content=body,
                    headers=headers,
                )
                assert accepted.status_code == 202
                assert accepted.json()["duplicate"] is False

                duplicate = await client.post(
                    "/api/v1/odoo/events",
                    content=body,
                    headers=headers,
                )
                assert duplicate.status_code == 200
                assert duplicate.json()["duplicate"] is True

                publisher = await NatsJetStreamPublisher.connect(settings)
                worker = OutboxWorker(
                    PostgresOutboxStore(pool),
                    {NATS_JETSTREAM_DESTINATION: publisher.publish},
                    lease_seconds=10,
                    handler_timeout_seconds=5,
                )
                assert await worker.run_once() is True
                assert await worker.run_once() is False

                messages = await consumer.fetch(1, timeout=3)
                message = messages[0]
                delivered = json.loads(message.data)
                assert delivered["event_id"] == event_id
                assert delivered["tenant_id"] == tenant_id
                assert message.headers is not None
                assert message.headers["X-Codestra-Event-Id"] == event_id

                activities = SyntheticReconciliationActivity(event_id, tenant_id)
                async with await WorkflowEnvironment.start_time_skipping() as temporal:
                    async with Worker(
                        temporal.client,
                        task_queue=TASK_QUEUE,
                        workflows=[ReconciliationWorkflow],
                        activities=[activities.reconcile_operation],
                    ):
                        outcome = await temporal.client.execute_workflow(
                            ReconciliationWorkflow.run,
                            ReconciliationRequest(
                                event_id,
                                tenant_id,
                                "canonical event observed on isolated JetStream",
                            ),
                            id=f"codestra-synthetic-{unique}",
                            task_queue=TASK_QUEUE,
                        )
                assert outcome.status == "completed"
                assert activities.calls == 1
                await message.ack()

        assert await inbox.verify_event_ledger(tenant_id) == {tenant_id: 1}
        stream_info = await jetstream.stream_info(STREAM)
        assert stream_info.state.messages == 1
        async with pool.acquire() as connection:
            database_state = await connection.fetchrow(
                """
                SELECT
                  (SELECT count(*) FROM middleware_inbox
                    WHERE tenant_id=$1 AND event_id=$2) AS inbox_count,
                  (SELECT count(*) FROM middleware_event_ledger
                    WHERE tenant_id=$1 AND event_id=$2) AS ledger_count,
                  (SELECT count(*) FROM middleware_outbox
                    WHERE tenant_id=$1 AND idempotency_key=$2) AS outbox_count,
                  (SELECT count(*) FROM middleware_outbox
                    WHERE tenant_id=$1 AND idempotency_key=$2
                      AND completed_at IS NOT NULL
                      AND dead_lettered_at IS NULL
                      AND reconciliation_required_at IS NULL) AS completed_count,
                  (SELECT count(*) FROM middleware_reconciliation_audit a
                    JOIN middleware_outbox o ON o.id=a.outbox_id
                    WHERE o.tenant_id=$1 AND o.idempotency_key=$2
                      AND a.action='complete') AS completion_audit_count,
                  (SELECT count(*) FROM middleware_commands
                    WHERE tenant_id=$1) AS command_count
                """,
                tenant_id,
                event_id,
            )
        assert dict(database_state) == {
            "inbox_count": 1,
            "ledger_count": 1,
            "outbox_count": 1,
            "completed_count": 1,
            "completion_audit_count": 1,
            "command_count": 0,
        }
    finally:
        if publisher is not None:
            await publisher.close()
        if nats_client is not None and not nats_client.is_closed:
            await nats_client.close()
        await redis_client.aclose()
        await pool.close()
