from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from .storage import NATS_JETSTREAM_DESTINATION, OutboxRecord


_EVENT_TYPE = re.compile(
    r"^codestra\.(?P<name>[a-z0-9_]+(?:\.[a-z0-9_]+)+)$"
)


class NatsTransportError(RuntimeError):
    """Raised before publish when an outbox row violates the NATS contract."""


def event_subject(prefix: str, event_type: str) -> str:
    match = _EVENT_TYPE.fullmatch(event_type)
    if match is None:
        raise NatsTransportError("event type cannot be mapped to a NATS subject")
    if event_type.startswith(f"{prefix}."):
        return event_type
    return f"{prefix}.{match.group('name')}"


@dataclass(slots=True)
class NatsJetStreamPublisher:
    """Publish canonical outbox events and require a JetStream acknowledgement."""

    client: Any
    jetstream: Any
    stream: str
    subject_prefix: str

    @classmethod
    async def connect(cls, settings: Settings) -> "NatsJetStreamPublisher":
        if settings.nats_url is None:
            raise NatsTransportError("NATS runtime configuration is incomplete")

        import nats

        connect_options: dict[str, Any] = {}
        if settings.nats_credentials_file is not None:
            connect_options["user_credentials"] = str(
                settings.nats_credentials_file
            )
        client = await nats.connect(
            servers=[settings.nats_url],
            connect_timeout=5,
            max_reconnect_attempts=-1,
            reconnect_time_wait=1,
            name="codestra-middleware-worker",
            **connect_options,
        )
        jetstream = client.jetstream()
        try:
            info = await jetstream.stream_info(settings.nats_stream)
            required_subject = f"{settings.nats_subject_prefix}.>"
            if info.config.subjects != [required_subject]:
                raise NatsTransportError(
                    "JetStream subjects must exactly match the configured domain"
                )
        except Exception:
            await client.close()
            raise
        return cls(
            client=client,
            jetstream=jetstream,
            stream=settings.nats_stream,
            subject_prefix=settings.nats_subject_prefix,
        )

    async def publish(self, record: OutboxRecord) -> None:
        if record.destination != NATS_JETSTREAM_DESTINATION:
            raise NatsTransportError("outbox row targets an unsupported destination")
        if record.payload.get("tenant_id") != record.tenant_id:
            raise NatsTransportError("outbox tenant does not match event envelope")
        if record.payload.get("event_type") != record.event_type:
            raise NatsTransportError("outbox event type does not match event envelope")

        subject = event_subject(self.subject_prefix, record.event_type)
        body = json.dumps(
            record.payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        message_id = hashlib.sha256(
            f"{record.tenant_id}\0{record.idempotency_key}".encode("utf-8")
        ).hexdigest()
        headers = {
            "Nats-Msg-Id": message_id,
            "X-Codestra-Tenant-Id": record.tenant_id,
            "X-Codestra-Event-Type": record.event_type,
            "X-Codestra-Idempotency-Key": record.idempotency_key,
        }
        event_id = record.payload.get("event_id")
        if isinstance(event_id, str) and event_id:
            headers["X-Codestra-Event-Id"] = event_id
        correlation_id = record.payload.get("correlation_id")
        if isinstance(correlation_id, str) and correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        causation_id = record.payload.get("causation_id")
        if isinstance(causation_id, str) and causation_id:
            headers["X-Causation-ID"] = causation_id

        # Completion is allowed only after the server returns a JetStream ack.
        ack = await self.jetstream.publish(
            subject,
            body,
            headers=headers,
            timeout=10,
        )
        if getattr(ack, "stream", None) != self.stream:
            raise NatsTransportError(
                "JetStream acknowledgement came from an unexpected stream"
            )

    async def close(self) -> None:
        if self.client is not None and not self.client.is_closed:
            await self.client.drain()
