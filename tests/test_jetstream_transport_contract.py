from __future__ import annotations

import hashlib
import json

import pytest

from app.eventing.jetstream import (
    EventIdentity,
    JetStreamContractError,
    read_nats_url,
    scoped_subject,
    forward_max_delivery_advisory,
    bind_dead_letter_advisory_consumer,
    process_next_dead_letter_advisory,
)


def event(**changes):
    payload = changes.pop("payload", {"synthetic": True})
    value = {
        "event_id": "evt-synthetic-1",
        "correlation_id": "corr-synthetic-1",
        "tenant_id": "tenant-synthetic",
        "campaign_id": "TEST_SYN",
        "schema_version": 1,
        "idempotency_key": "idem-synthetic-1",
        "payload_hash": hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "payload": payload,
    }
    value.update(changes)
    return value


def test_tenant_campaign_subject_is_exact() -> None:
    assert scoped_subject(event(), "ingress") == (
        "codestra.v1.tenant-synthetic.TEST_SYN.events.ingress"
    )


@pytest.mark.parametrize(
    "change,error",
    [
        ({"tenant_id": ""}, "tenant_id"),
        ({"campaign_id": "wrong.scope"}, "campaign_id"),
        ({"schema_version": 2}, "schema version"),
        ({"payload_hash": "0" * 64}, "payload hash"),
    ],
)
def test_event_contract_fails_closed(change, error) -> None:
    with pytest.raises(JetStreamContractError, match=error):
        EventIdentity.validate(event(**change))


def test_production_nats_reference_requires_protected_tls_file(tmp_path) -> None:
    source = tmp_path / "nats-url"
    source.write_text("tls://nats.internal.codestra.agency:4222\n")
    source.chmod(0o600)
    assert read_nats_url(str(source)).startswith("tls://")
    source.chmod(0o644)
    with pytest.raises(JetStreamContractError, match="permissions"):
        read_nats_url(str(source))


@pytest.mark.asyncio
async def test_max_delivery_advisory_forwards_original_once() -> None:
    class Original:
        data = json.dumps(event()).encode()

    class Ack:
        duplicate = False

    class FakeJetStream:
        def __init__(self):
            self.published = []

        async def get_msg(self, stream, seq):
            assert (stream, seq) == ("CODESTRA_PROCESSING", 42)
            return Original()

        async def publish(self, subject, data, headers):
            self.published.append((subject, data, headers))
            return Ack()

    js = FakeJetStream()
    advisory = json.dumps(
        {
            "stream": "CODESTRA_PROCESSING",
            "consumer": "middleware-processor-v1",
            "stream_seq": 42,
            "deliveries": 5,
        }
    ).encode()
    assert await forward_max_delivery_advisory(js, advisory) == "forwarded"
    assert js.published[0][0].endswith(".events.dead_letter")
    assert js.published[0][2]["Codestra-Failure-Class"] == "max_deliver_exhausted"
    forwarded = json.loads(js.published[0][1])
    assert forwarded["failure"]["delivery_attempts"] == 5
    assert forwarded["failure"]["failed_at"].endswith("+00:00")


def test_dlq_worker_deployment_is_explicit_and_disabled() -> None:
    text = open("deploy/compose.jetstream-dlq-worker.yaml.example").read()
    assert "app.entrypoints.jetstream_dlq_worker" in text
    assert 'JETSTREAM_DLQ_WORKER_ENABLED: "false"' in text
    assert "profiles: [jetstream-dlq-worker]" in text


@pytest.mark.asyncio
async def test_durable_advisory_is_acked_only_after_forwarding() -> None:
    class Message:
        data = json.dumps(
            {
                "stream": "CODESTRA_PROCESSING",
                "consumer": "middleware-processor-v1",
                "stream_seq": 42,
                "deliveries": 5,
            }
        ).encode()
        acked = False
        nacked = False

        async def ack(self):
            self.acked = True

        async def nak(self):
            self.nacked = True

    class Original:
        data = json.dumps(event()).encode()

    class Ack:
        duplicate = False

    class Subscription:
        def __init__(self, message):
            self.message = message

        async def fetch(self, count, timeout):
            assert (count, timeout) == (1, 2)
            return [self.message]

    class FakeJetStream:
        def __init__(self, message):
            self.message = message

        async def pull_subscribe_bind(self, durable, stream):
            assert durable == "middleware-dlq-advisory-v1"
            assert stream == "CODESTRA_DLQ_ADVISORIES_V1"
            return Subscription(self.message)

        async def get_msg(self, stream, seq):
            return Original()

        async def publish(self, subject, data, headers):
            return Ack()

    message = Message()
    js = FakeJetStream(message)
    subscription = await bind_dead_letter_advisory_consumer(js)
    assert (
        await process_next_dead_letter_advisory(js, subscription, timeout=2)
        == "forwarded"
    )
    assert message.acked is True
    assert message.nacked is False


@pytest.mark.asyncio
async def test_advisory_worker_reuses_binding_across_idle_and_message_cycles() -> None:
    class Message:
        data = json.dumps(
            {
                "stream": "CODESTRA_PROCESSING",
                "consumer": "middleware-processor-v1",
                "stream_seq": 42,
                "deliveries": 5,
            }
        ).encode()

        def __init__(self):
            self.acked = False

        async def ack(self):
            self.acked = True

        async def nak(self):
            raise AssertionError("successful forwarding must not NAK")

    class Subscription:
        def __init__(self, outcomes):
            self.outcomes = iter(outcomes)
            self.fetches = 0

        async def fetch(self, count, timeout):
            assert (count, timeout) == (1, 0.01)
            self.fetches += 1
            outcome = next(self.outcomes)
            if isinstance(outcome, Exception):
                raise outcome
            return [outcome]

    class Original:
        data = json.dumps(event()).encode()

    class Ack:
        duplicate = False

    first = Message()
    second = Message()
    subscription = Subscription([TimeoutError(), TimeoutError(), first, second])

    class FakeJetStream:
        def __init__(self):
            self.binds = []

        async def pull_subscribe_bind(self, durable, stream):
            self.binds.append((durable, stream))
            return subscription

        async def get_msg(self, stream, seq):
            return Original()

        async def publish(self, subject, data, headers):
            return Ack()

    js = FakeJetStream()
    worker = await bind_dead_letter_advisory_consumer(js)
    for _ in range(2):
        with pytest.raises(TimeoutError):
            await process_next_dead_letter_advisory(js, worker, timeout=0.01)
    assert (
        await process_next_dead_letter_advisory(js, worker, timeout=0.01) == "forwarded"
    )
    assert (
        await process_next_dead_letter_advisory(js, worker, timeout=0.01) == "forwarded"
    )
    assert js.binds == [("middleware-dlq-advisory-v1", "CODESTRA_DLQ_ADVISORIES_V1")]
    assert subscription.fetches == 4
    assert first.acked and second.acked


@pytest.mark.asyncio
async def test_advisory_forwarding_failure_naks_without_ack() -> None:
    class Message:
        data = b"not-json"
        acked = False
        nacked = False

        async def ack(self):
            self.acked = True

        async def nak(self):
            self.nacked = True

    class Subscription:
        async def fetch(self, count, timeout):
            return [message]

    message = Message()
    with pytest.raises(
        JetStreamContractError, match="invalid maximum-delivery advisory"
    ):
        await process_next_dead_letter_advisory(object(), Subscription(), timeout=1)
    assert message.nacked is True
    assert message.acked is False


@pytest.mark.asyncio
async def test_worker_restart_rebinds_existing_durable_consumer() -> None:
    class FakeJetStream:
        def __init__(self):
            self.binds = []

        async def pull_subscribe_bind(self, durable, stream):
            self.binds.append((durable, stream))
            return object()

    js = FakeJetStream()
    await bind_dead_letter_advisory_consumer(js)
    await bind_dead_letter_advisory_consumer(js)
    assert js.binds == [
        ("middleware-dlq-advisory-v1", "CODESTRA_DLQ_ADVISORIES_V1"),
        ("middleware-dlq-advisory-v1", "CODESTRA_DLQ_ADVISORIES_V1"),
    ]
