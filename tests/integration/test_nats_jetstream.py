from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import AsyncIterator

import nats
import pytest
import pytest_asyncio
from nats.js.api import StorageType, StreamConfig
from nats.js.errors import NotFoundError

from app.core.config import Settings
from app.nats_transport import NatsJetStreamPublisher
from app.storage import NATS_JETSTREAM_DESTINATION, OutboxRecord


RUN = os.getenv("NATS_INTEGRATION_TESTS") == "1"
NATS_URL = os.getenv("NATS_TEST_URL", "")
STREAM = "CODESTRA_TEST_EVENTS"
SUBJECT_PREFIX = "codestra.test.events"

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set NATS_INTEGRATION_TESTS=1 against disposable NATS JetStream",
)


def _record(*, record_id: int, event_id: str, idempotency_key: str) -> OutboxRecord:
    return OutboxRecord(
        id=record_id,
        tenant_id="tenant-nats-test",
        destination=NATS_JETSTREAM_DESTINATION,
        event_type="codestra.odoo.contact_updated",
        idempotency_key=idempotency_key,
        payload={
            "event_id": event_id,
            "event_type": "codestra.odoo.contact_updated",
            "event_version": "1.0",
            "occurred_at": "2026-08-28T11:59:59Z",
            "received_at": "2026-08-28T12:00:00Z",
            "source": "integration-test",
            "tenant_id": "tenant-nats-test",
            "correlation_id": "corr-nats-test",
            "causation_id": "cause-nats-test",
            "idempotency_key": idempotency_key,
            "payload": {"contact_id": 42},
            "metadata": {},
        },
        attempt_count=1,
    )


def _settings() -> Settings:
    return Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "NATS_URL": NATS_URL,
            "NATS_STREAM": STREAM,
            "NATS_SUBJECT_PREFIX": SUBJECT_PREFIX,
            "NATS_DISPATCH_MODE": "isolated",
            "NATS_ALLOW_INSECURE_TEST_CONNECTION": "true",
            "SEND_EVENTS": "true",
            "OUTBOX_DISPATCH_ENABLED": "true",
        }
    )


@pytest_asyncio.fixture
async def publisher() -> AsyncIterator[NatsJetStreamPublisher]:
    assert NATS_URL == "nats://127.0.0.1:4222", (
        "NATS_TEST_URL must target the disposable localhost server"
    )
    bootstrap = await nats.connect(NATS_URL)
    jetstream = bootstrap.jetstream()
    try:
        try:
            info = await jetstream.stream_info(STREAM)
        except NotFoundError:
            await jetstream.add_stream(
                config=StreamConfig(
                    name=STREAM,
                    subjects=[f"{SUBJECT_PREFIX}.>"],
                    storage=StorageType.FILE,
                    duplicate_window=2.0,
                    num_replicas=1,
                )
            )
        else:
            assert info.config.subjects == [f"{SUBJECT_PREFIX}.>"]
            await jetstream.purge_stream(STREAM)
    finally:
        await bootstrap.close()

    active = await NatsJetStreamPublisher.connect(_settings())
    try:
        yield active
    finally:
        await active.close()


@pytest.mark.asyncio
async def test_ack_deduplication_and_new_consumer_replay(
    publisher: NatsJetStreamPublisher,
) -> None:
    record = _record(
        record_id=1,
        event_id="evt-nats-dedup",
        idempotency_key="idem-nats-dedup",
    )

    await publisher.publish(record)
    await publisher.publish(record)

    info = await publisher.jetstream.stream_info(STREAM)
    assert info.state.messages == 1

    first = await publisher.jetstream.pull_subscribe(
        f"{SUBJECT_PREFIX}.>",
        durable="codestra-test-consumer-a",
        stream=STREAM,
    )
    messages = await first.fetch(1, timeout=3)
    assert json.loads(messages[0].data)["event_id"] == "evt-nats-dedup"
    assert messages[0].headers["X-Codestra-Tenant-Id"] == "tenant-nats-test"
    await messages[0].ack()

    replay = await publisher.jetstream.pull_subscribe(
        f"{SUBJECT_PREFIX}.>",
        durable="codestra-test-consumer-b",
        stream=STREAM,
    )
    replayed = await replay.fetch(1, timeout=3)
    assert json.loads(replayed[0].data)["event_id"] == "evt-nats-dedup"
    await replayed[0].ack()

    await asyncio.sleep(2.2)
    await publisher.publish(record)
    info = await publisher.jetstream.stream_info(STREAM)
    assert info.state.messages == 2


@pytest.mark.asyncio
async def test_client_reconnects_after_disposable_server_restart(
    publisher: NatsJetStreamPublisher,
) -> None:
    container = os.getenv("NATS_TEST_CONTAINER", "")
    if not container:
        pytest.skip("NATS_TEST_CONTAINER is required for reconnect coverage")

    await publisher.publish(
        _record(
            record_id=2,
            event_id="evt-before-restart",
            idempotency_key="idem-before-restart",
        )
    )
    subprocess.run(
        ["docker", "restart", container],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    for _ in range(100):
        try:
            if publisher.client.is_connected:
                await publisher.client.flush(timeout=0.2)
                break
        except Exception:
            pass
        await asyncio.sleep(0.1)
    assert publisher.client.is_connected

    await publisher.publish(
        _record(
            record_id=3,
            event_id="evt-after-restart",
            idempotency_key="idem-after-restart",
        )
    )
    info = await publisher.jetstream.stream_info(STREAM)
    assert info.state.messages == 2
