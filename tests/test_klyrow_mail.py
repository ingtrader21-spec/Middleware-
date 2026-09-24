import asyncio
import hashlib
import hmac
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from app.api.internal.klyrow_mail import KLYROW_DELIVERY_EVENT_TYPES, KlyrowDeliveryEvent, KlyrowInboundEvent, KlyrowUsageEvent, _authenticate, receive_klyrow_mail
from app.core.config import settings
from app.workers.klyrow_mail_odoo import DeliveryFailure, _odoo_payload


def event_payload() -> dict:
    return {
        "event_id": "event-12345678",
        "source_system": "klyrow",
        "event_type": "inbound.received",
        "timestamp": "2026-08-23T00:00:00Z",
        "tenant_id": "tenant-a",
        "inbound_id": "inbound-12345678",
        "provider_event_id": "postal:12345678",
        "route_id": "route-a",
        "destination_kind": "odoo_helpdesk",
        "destination_ref": "support",
        "disposition": "ACCEPT",
        "recipient": "support@codestra.co",
        "sender": "Sender <sender@example.net>",
        "subject": "Help",
        "message_id": "<message@example.net>",
        "text": "hello",
        "html": None,
        "attachments": [],
    }


def signed_request(
    body: bytes, secret: bytes, *, signature: str | None = None
) -> Request:
    timestamp = str(int(time.time()))
    event_id = "event-12345678"
    canonical = timestamp.encode() + b"\n" + event_id.encode() + b"\nklyrow\n" + body
    digest = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    headers = [
        (b"x-source-system", b"klyrow"),
        (b"x-klyrow-timestamp", timestamp.encode()),
        (b"x-klyrow-event-id", event_id.encode()),
        (b"x-klyrow-signature", (signature or digest).encode()),
    ]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/internal/provider-events/klyrow",
            "headers": headers,
        }
    )


def test_klyrow_hmac_binds_exact_body_and_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = b"s" * 64
    path = tmp_path / "hmac"
    path.write_bytes(secret)
    monkeypatch.setattr(settings, "klyrow_mail_hmac_secret_file", str(path))
    body = json.dumps(event_payload(), separators=(",", ":")).encode()
    event = KlyrowInboundEvent.model_validate_json(body)
    _authenticate(signed_request(body, secret), body, event)
    with pytest.raises(Exception) as exc:
        _authenticate(
            signed_request(body, secret, signature="sha256=" + "0" * 64), body, event
        )
    assert getattr(exc.value, "status_code", None) == 401

    canonical_body = json.dumps(
        {**event_payload(), "event_type": "klyrow.email.inbound_received"},
        separators=(",", ":"),
    ).encode()
    canonical_event = KlyrowInboundEvent.model_validate_json(canonical_body)
    _authenticate(signed_request(canonical_body, secret), canonical_body, canonical_event)


def test_delivery_event_schema_and_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = b"d" * 64
    path = tmp_path / "hmac"
    path.write_bytes(secret)
    monkeypatch.setattr(settings, "klyrow_mail_hmac_secret_file", str(path))
    payload = {
        "event_id": "event-delivery-12345678",
        "schema_version": "1.0",
        "source_system": "klyrow",
        "event_type": "klyrow.email.delivered",
        "event_version": "1.0",
        "occurred_at": "2026-08-23T03:00:00Z",
        "tenant_id": "tenant-a",
        "operation_id": "operation-a",
        "payload_hash": "a" * 64,
        "message_id": "message-a",
        "provider_message_id": "postal-a",
        "stream": "transactional",
        "recipient_reference": "sha256:recipient",
        "status": "delivered",
        "provider": "postal",
        "correlation_id": "correlation-a",
        "causation_id": "causation-a",
        "attempt": 1,
        "metadata": {"synthetic": True},
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    event = KlyrowDeliveryEvent.model_validate_json(body)
    timestamp = str(int(time.time()))
    canonical = timestamp.encode() + b"\n" + event.event_id.encode() + b"\nklyrow\n" + body
    signature = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    request = Request({"type": "http", "method": "POST", "path": "/internal/provider-events/klyrow", "headers": [
        (b"x-source-system", b"klyrow"), (b"x-klyrow-timestamp", timestamp.encode()),
        (b"x-klyrow-event-id", event.event_id.encode()), (b"x-klyrow-signature", signature.encode()),
    ]})
    _authenticate(request, body, event)
    with pytest.raises(Exception):
        KlyrowDeliveryEvent.model_validate({**payload, "event_version": "2.0"})
    with pytest.raises(Exception):
        KlyrowDeliveryEvent.model_validate({**payload, "occurred_at": "2026-08-23T03:00:00"})

    for event_type in KLYROW_DELIVERY_EVENT_TYPES:
        value = KlyrowDeliveryEvent.model_validate({**payload, "event_type": event_type})
        assert value.event_type == event_type
    with pytest.raises(Exception):
        KlyrowDeliveryEvent.model_validate({**payload, "event_type": "klyrow.email.inbound_received"})


def test_usage_event_schema_and_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = b"u" * 64
    path = tmp_path / "hmac"
    path.write_bytes(secret)
    monkeypatch.setattr(settings, "klyrow_mail_hmac_secret_file", str(path))
    payload = {
        "event_id": "usage-event-12345678",
        "source_system": "klyrow",
        "event_type": "klyrow.usage.recorded",
        "timestamp": "2026-09-04T00:00:00Z",
        "usage_event_id": "usage-event-12345678",
        "tenant_id": "tenant-a",
        "message_id": "message-a",
        "stream": "TRANSACTIONAL",
        "billable_units": 1,
        "provider_result_category": "DELIVERED",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    event = KlyrowUsageEvent.model_validate_json(body)
    timestamp = str(int(time.time()))
    canonical = timestamp.encode() + b"\n" + event.event_id.encode() + b"\nklyrow\n" + body
    signature = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    request = Request({"type": "http", "method": "POST", "path": "/internal/provider-events/klyrow", "headers": [
        (b"x-source-system", b"klyrow"), (b"x-klyrow-timestamp", timestamp.encode()),
        (b"x-klyrow-event-id", event.event_id.encode()), (b"x-klyrow-signature", signature.encode()),
    ]})
    _authenticate(request, body, event)


def test_usage_event_is_persisted_before_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = b"p" * 64
    secret_path = tmp_path / "hmac"
    secret_path.write_bytes(secret)
    monkeypatch.setattr(settings, "klyrow_mail_hmac_secret_file", str(secret_path))
    monkeypatch.setattr(settings, "klyrow_mail_ingress_enabled", True)
    event_id = "usage-event-persist-12345678"
    payload = {
        "event_id": event_id,
        "source_system": "klyrow",
        "event_type": "klyrow.usage.recorded",
        "timestamp": "2026-09-04T00:00:00Z",
        "usage_event_id": "usage-event-persist-12345678",
        "tenant_id": "tenant-a",
        "message_id": "message-a",
        "stream": "TRANSACTIONAL",
        "billable_units": 1,
        "provider_result_category": "DELIVERED",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    canonical = timestamp.encode() + b"\n" + event_id.encode() + b"\nklyrow\n" + body
    signature = "sha256=" + hmac.new(secret, canonical, hashlib.sha256).hexdigest()

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request({
        "type": "http", "method": "POST", "path": "/internal/provider-events/klyrow",
        "headers": [
            (b"content-type", b"application/json"), (b"x-source-system", b"klyrow"),
            (b"x-klyrow-timestamp", timestamp.encode()),
            (b"x-klyrow-event-id", event_id.encode()),
            (b"x-klyrow-signature", signature.encode()),
        ],
    }, receive=receive)

    class EmptyResult:
        def mappings(self):
            return self

        def first(self):
            return None

    database = AsyncMock()
    database.execute.return_value = EmptyResult()
    result = asyncio.run(receive_klyrow_mail(request, database))

    assert result == {"accepted": True, "duplicate": False, "status": "complete"}
    assert database.execute.await_count == 2
    insert_parameters = database.execute.await_args_list[1].args[1]
    assert insert_parameters["event_id"] == event_id
    assert insert_parameters["stream"] == "transactional"
    database.commit.assert_awaited_once()


def test_odoo_payload_normalizes_sender_and_attachments():
    payload = event_payload()
    payload["references"] = "<one@example.net> <two@example.net>"
    payload["attachments"] = [
        {
            "filename": "safe.txt",
            "content_type": "text/plain",
            "size": 4,
            "sha256": hashlib.sha256(b"safe").hexdigest(),
            "data_b64": "c2FmZQ==",
        }
    ]
    result = _odoo_payload(
        {
            "payload": payload,
            "event_id": payload["event_id"],
            "idempotency_key": "postal:12345678",
            "inbound_id": payload["inbound_id"],
            "provider_event_id": payload["provider_event_id"],
            "recipient": payload["recipient"],
        }
    )
    assert result["sender"] == "sender@example.net"
    assert result["references"] == ["<one@example.net>", "<two@example.net>"]
    assert result["attachments"][0]["mimetype"] == "text/plain"


def test_odoo_payload_rejects_invalid_sender():
    payload = event_payload()
    payload["sender"] = "not-an-address"
    with pytest.raises(DeliveryFailure) as exc:
        _odoo_payload(
            {
                "payload": payload,
                "event_id": payload["event_id"],
                "idempotency_key": "postal:12345678",
                "inbound_id": payload["inbound_id"],
                "provider_event_id": payload["provider_event_id"],
                "recipient": payload["recipient"],
            }
        )
    assert exc.value.permanent is True
