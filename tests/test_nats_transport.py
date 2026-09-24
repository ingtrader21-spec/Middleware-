from __future__ import annotations

import json

import pytest

from app.nats_transport import (
    NatsJetStreamPublisher,
    NatsTransportError,
    event_subject,
)
from app.storage import NATS_JETSTREAM_DESTINATION, OutboxRecord


class FakeClient:
    is_closed = False

    async def drain(self) -> None:
        self.is_closed = True


class FakeJetStream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, dict[str, str], int]] = []

    async def publish(
        self,
        subject: str,
        body: bytes,
        *,
        headers: dict[str, str],
        timeout: int,
    ) -> object:
        self.calls.append((subject, body, headers, timeout))
        return type("Ack", (), {"stream": "CODESTRA_EVENTS"})()


def record(**overrides: object) -> OutboxRecord:
    values: dict[str, object] = {
        "id": 7,
        "tenant_id": "tenant-a",
        "destination": NATS_JETSTREAM_DESTINATION,
        "event_type": "codestra.odoo.contact_updated",
        "idempotency_key": "idem-event-7",
        "payload": {
            "tenant_id": "tenant-a",
            "event_type": "codestra.odoo.contact_updated",
            "correlation_id": "corr-7",
            "causation_id": "cause-7",
            "event_id": "event-7",
            "payload": {"contact_id": 42},
        },
        "attempt_count": 1,
    }
    values.update(overrides)
    return OutboxRecord(**values)  # type: ignore[arg-type]


def test_event_subject_is_domain_separated() -> None:
    assert event_subject(
        "codestra.events",
        "codestra.odoo.contact_updated",
    ) == "codestra.events.odoo.contact_updated"
    assert event_subject(
        "codestra.events",
        "codestra.events.call_disposition_updated",
    ) == "codestra.events.call_disposition_updated"
    with pytest.raises(NatsTransportError):
        event_subject("codestra.events", "unscoped.event")


@pytest.mark.asyncio
async def test_publish_preserves_tenant_idempotency_and_correlation() -> None:
    jetstream = FakeJetStream()
    publisher = NatsJetStreamPublisher(
        client=FakeClient(),
        jetstream=jetstream,
        stream="CODESTRA_EVENTS",
        subject_prefix="codestra.events",
    )

    await publisher.publish(record())

    subject, body, headers, timeout = jetstream.calls[0]
    assert subject == "codestra.events.odoo.contact_updated"
    assert json.loads(body)["payload"] == {"contact_id": 42}
    assert headers["X-Codestra-Tenant-Id"] == "tenant-a"
    assert headers["X-Codestra-Event-Id"] == "event-7"
    assert headers["X-Correlation-ID"] == "corr-7"
    assert headers["X-Causation-ID"] == "cause-7"
    assert len(headers["Nats-Msg-Id"]) == 64
    assert timeout == 10


@pytest.mark.asyncio
async def test_publish_fails_before_transport_on_envelope_mismatch() -> None:
    jetstream = FakeJetStream()
    publisher = NatsJetStreamPublisher(
        client=FakeClient(),
        jetstream=jetstream,
        stream="CODESTRA_EVENTS",
        subject_prefix="codestra.events",
    )

    with pytest.raises(NatsTransportError):
        await publisher.publish(
            record(payload={"tenant_id": "tenant-b", "event_type": "wrong"})
        )
    assert jetstream.calls == []
