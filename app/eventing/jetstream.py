"""Fail-closed JetStream publishing and dead-letter forwarding."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class JetStreamContractError(RuntimeError):
    pass


SUBJECT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DLQ_ADVISORY_STREAM = "CODESTRA_DLQ_ADVISORIES_V1"
DLQ_ADVISORY_CONSUMER = "middleware-dlq-advisory-v1"


@dataclass(frozen=True)
class EventIdentity:
    event_id: str
    correlation_id: str
    tenant_id: str
    campaign_id: str
    schema_version: int
    idempotency_key: str
    payload_hash: str

    @classmethod
    def validate(cls, event: dict[str, Any]) -> "EventIdentity":
        required = {
            "event_id", "correlation_id", "tenant_id", "campaign_id",
            "schema_version", "idempotency_key", "payload_hash", "payload",
        }
        if required - event.keys():
            raise JetStreamContractError("event identity is incomplete")
        digest = hashlib.sha256(
            json.dumps(event["payload"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if digest != event["payload_hash"]:
            raise JetStreamContractError("payload hash differs from envelope")
        if event["schema_version"] != 1:
            raise JetStreamContractError("schema version is unsupported")
        for field in ("event_id", "correlation_id", "idempotency_key"):
            if not isinstance(event[field], str) or not event[field].strip():
                raise JetStreamContractError(f"{field} is invalid")
        for field in ("tenant_id", "campaign_id"):
            if not isinstance(event[field], str) or not SUBJECT_SEGMENT_RE.fullmatch(event[field]):
                raise JetStreamContractError(f"{field} is invalid")
        return cls(**{field: event[field] for field in cls.__annotations__})


def scoped_subject(event: dict[str, Any], stage: str) -> str:
    identity = EventIdentity.validate(event)
    if stage not in {"ingress", "processing", "results", "callbacks", "retry", "dead_letter"}:
        raise JetStreamContractError("event stage is invalid")
    return f"codestra.v1.{identity.tenant_id}.{identity.campaign_id}.events.{stage}"


async def publish_event(js, event: dict[str, Any], stage: str):
    identity = EventIdentity.validate(event)
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return await js.publish(
        scoped_subject(event, stage),
        body,
        headers={"Nats-Msg-Id": identity.event_id},
    )


async def forward_max_delivery_advisory(js, advisory_payload: bytes) -> str:
    try:
        advisory = json.loads(advisory_payload)
        stream = advisory["stream"]
        consumer = advisory["consumer"]
        sequence = int(advisory["stream_seq"])
        deliveries = int(advisory["deliveries"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise JetStreamContractError("invalid maximum-delivery advisory") from exc
    original = await js.get_msg(stream, seq=sequence)
    event = json.loads(original.data)
    identity = EventIdentity.validate(event)
    event["failure"] = {
        "failure_class": "max_deliver_exhausted",
        "failed_at": datetime.now(UTC).isoformat(),
        "delivery_attempts": deliveries,
    }
    dead_letter_data = json.dumps(
        event, sort_keys=True, separators=(",", ":")
    ).encode()
    acknowledgement = await js.publish(
        scoped_subject(event, "dead_letter"),
        dead_letter_data,
        headers={
            "Nats-Msg-Id": f"dead-letter:{stream}:{consumer}:{identity.event_id}",
            "Codestra-Original-Stream": stream,
            "Codestra-Original-Consumer": consumer,
            "Codestra-Failure-Class": "max_deliver_exhausted",
        },
    )
    return "duplicate" if acknowledgement.duplicate else "forwarded"


async def bind_dead_letter_advisory_consumer(js):
    """Bind the preprovisioned durable consumer once per worker process."""
    return await js.pull_subscribe_bind(
        durable=DLQ_ADVISORY_CONSUMER,
        stream=DLQ_ADVISORY_STREAM,
    )


async def process_next_dead_letter_advisory(
    js, subscription, timeout: float = 1.0
) -> str:
    """Forward and ACK one advisory from the durable platform consumer."""
    message = (await subscription.fetch(1, timeout=timeout))[0]
    try:
        result = await forward_max_delivery_advisory(js, message.data)
    except Exception:
        await message.nak()
        raise
    await message.ack()
    return result


def read_nats_url(path: str) -> str:
    source = Path(path)
    if not source.is_file() or source.stat().st_mode & 0o077:
        raise JetStreamContractError("NATS URL file is missing or permissions are unsafe")
    value = source.read_text().strip()
    if not value.startswith("tls://"):
        raise JetStreamContractError("production NATS transport must use TLS")
    return value
