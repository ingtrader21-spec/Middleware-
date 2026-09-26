from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, Response
from fastapi.routing import APIRoute
from starlette.requests import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.internal.telnexa_events import (
    PATH,
    TelnexaDeliveryEvent,
    _effective_status,
    _project_message,
    receive_telnexa_event,
    router,
)
from app.communications import CommunicationMessage, MemoryCommunicationsStore
from app.core.config import settings


API_KEY = "telnexa-api-key-fixture"
HMAC_SECRET = b"telnexa-hmac-secret-fixture-that-is-long-enough"


class _Result:
    def __init__(self, value=None):
        self.value = value

    def mappings(self):
        return self

    def first(self):
        return self.value


class _Session:
    def __init__(self, message: CommunicationMessage | None):
        self.message = message
        self.inbox: dict[str, object] = {}
        self.updated_payload: dict[str, object] | None = None
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.info: dict[str, str] = {}
        self.commit_count = 0
        self.rollback_count = 0

    async def execute(self, statement, parameters=None):
        sql = str(statement)
        values = parameters or {}
        self.calls.append((sql, values))
        if "SELECT payload_hash,processing_status" in sql:
            if not self.inbox:
                return _Result()
            return _Result(self.inbox.copy())
        if "INSERT INTO telnexa_delivery_event_inbox" in sql:
            self.inbox = {
                "payload_hash": values["hash"],
                "processing_status": "pending",
            }
            return _Result()
        if "SELECT payload FROM middleware_communication_messages" in sql:
            if self.message is None:
                return _Result()
            return _Result({"payload": self.message.model_dump(mode="json")})
        if "UPDATE middleware_communication_messages" in sql:
            self.updated_payload = json.loads(values["payload"])
            return _Result()
        if "UPDATE telnexa_delivery_event_inbox" in sql:
            if "processing_status='retry'" in sql:
                self.inbox["processing_status"] = "retry"
            if "processing_status='complete'" in sql:
                self.inbox["processing_status"] = "complete"
            return _Result()
        return _Result()

    async def commit(self):
        self.commit_count += 1

    async def rollback(self):
        self.rollback_count += 1


def _request(body: bytes, headers: dict[str, str]) -> Request:
    timestamp = headers["X-Timestamp"]
    event_id = headers["X-Event-Id"]
    signature = hmac.new(
        HMAC_SECRET,
        f"{timestamp}\n{event_id}\ntelnexa\n".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    raw_headers = [(b"content-type", b"application/json")]
    raw_headers.extend((key.lower().encode(), value.encode()) for key, value in headers.items())
    raw_headers.append((b"x-signature", f"sha256={signature}".encode()))

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": PATH,
            "headers": raw_headers,
        },
        receive=receive,
    )


def _message() -> CommunicationMessage:
    now = datetime.now(UTC)
    return CommunicationMessage(
        messageId=uuid4(),
        tenantId="tenant-1",
        channel="sms",
        direction="outbound",
        status="dispatched",
        correlationId="correlation-1",
        idempotencyKey="odoo-sms:idempotency-1",
        provider="telnexa",
        providerReference="provider-1",
        createdAt=now,
        acceptedAt=now,
        dispatchedAt=now,
        updatedAt=now,
    )


def _event(message: CommunicationMessage, *, event_id: str = "delivery-1") -> bytes:
    return json.dumps(
        {
            "event_id": event_id,
            "event_type": "sms.message.delivered.v1",
            "event_version": "1.0",
            "schema_version": "1.0",
            "timestamp": str(int(time.time())),
            "occurred_at": "2026-09-12T00:00:00Z",
            "tenant_id": message.tenantId,
            "correlation_id": message.correlationId,
            "idempotency_key": message.idempotencyKey,
            "message_id": str(message.messageId),
            "provider_reference": "telnexa-provider-1",
            "status": "delivered",
            "provider_status": "DELIVRD",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _headers(body: bytes, *, event_id: str = "delivery-1") -> dict[str, str]:
    payload = json.loads(body)
    return {
        "Authorization": f"Bearer {API_KEY}",
        "X-Event-Id": event_id,
        "X-Timestamp": payload["timestamp"],
        "Idempotency-Key": payload["idempotency_key"],
    }


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "telnexa_event_ingress_enabled", True)
    monkeypatch.setattr(settings, "sms_delivery", True)
    monkeypatch.setattr(settings, "telnexa_event_api_key", API_KEY)
    monkeypatch.setattr(settings, "telnexa_event_api_key_file", "")
    monkeypatch.setattr(settings, "telnexa_event_hmac_secret", HMAC_SECRET.decode())
    monkeypatch.setattr(settings, "telnexa_event_hmac_secret_file", "")
    monkeypatch.setattr(settings, "telnexa_event_signature_ttl_seconds", 300)
    monkeypatch.setattr(settings, "telnexa_event_request_max_bytes", 1_048_576)


def _receive(request: Request, database: _Session) -> dict[str, object]:
    return asyncio.run(
        receive_telnexa_event(request, Response(), cast(AsyncSession, database))
    )


def test_exact_route_is_registered_with_closed_event_schema() -> None:
    app = FastAPI()
    app.include_router(router)
    route = next(item for item in router.routes if getattr(item, "path", None) == PATH)
    assert isinstance(route, APIRoute)
    assert route.methods is not None
    assert "POST" in route.methods
    schema = TelnexaDeliveryEvent.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) >= {
        "event_id",
        "event_type",
        "message_id",
        "provider_status",
    }


def test_hmac_delivery_is_durable_and_exact_replay_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    database = _Session(message)

    first = _receive(_request(body, _headers(body)), database)
    second = _receive(_request(body, _headers(body)), database)

    assert first["accepted"] is True
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert database.commit_count == 2
    assert database.inbox["processing_status"] == "complete"
    assert database.updated_payload is not None
    assert database.updated_payload["status"] == "delivered"
    assert database.updated_payload["providerReference"] == "telnexa-provider-1"


def test_signature_tamper_and_mismatched_replay_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    tampered = _request(body, _headers(body))
    tampered.scope["headers"][-1] = (b"x-signature", b"sha256=" + b"0" * 64)
    with pytest.raises(HTTPException) as error:
        _receive(tampered, _Session(message))
    assert error.value.status_code == 401

    database = _Session(message)
    _receive(_request(body, _headers(body)), database)
    changed = body.replace(b"DELIVRD", b"FAILED")
    changed_headers = _headers(changed)
    changed_headers["X-Event-Id"] = "delivery-1"
    with pytest.raises(HTTPException) as replay_error:
        _receive(_request(changed, changed_headers), database)
    assert replay_error.value.status_code == 409


def test_ingress_requires_both_fail_closed_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "telnexa_event_ingress_enabled", True)
    monkeypatch.setattr(settings, "sms_delivery", False)
    database = _Session(None)
    message = _message()
    body = _event(message)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), database)
    assert error.value.status_code == 503
    assert error.value.detail == "sms_delivery_disabled"
    assert database.commit_count == 0


def test_missing_communication_message_is_retryable_not_acknowledged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    database = _Session(None)
    body = _event(message)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), database)
    assert error.value.status_code == 503
    assert error.value.detail == "communication_message_unavailable"
    assert database.inbox["processing_status"] == "retry"
    assert database.commit_count == 1


def test_authenticated_delayed_retry_can_finish_existing_inbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    database = _Session(None)
    body = _event(message)
    with pytest.raises(HTTPException):
        _receive(_request(body, _headers(body)), database)
    assert database.inbox["processing_status"] == "retry"

    timestamp = int(json.loads(body)["timestamp"])
    monkeypatch.setattr(
        "app.api.internal.telnexa_events.time.time",
        lambda: timestamp + 301,
    )
    database.message = message
    result = _receive(_request(body, _headers(body)), database)

    assert result["duplicate"] is True
    assert database.inbox["processing_status"] == "complete"
    assert database.updated_payload is not None
    assert database.updated_payload["status"] == "delivered"


def test_stale_first_delivery_is_rejected_before_inbox_insert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    timestamp = int(json.loads(body)["timestamp"])
    monkeypatch.setattr(
        "app.api.internal.telnexa_events.time.time",
        lambda: timestamp + 301,
    )
    database = _Session(message)

    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), database)

    assert error.value.status_code == 401
    assert error.value.detail == "expired_telnexa_signature"
    assert database.inbox == {}


def test_nonterminal_callbacks_are_monotonic() -> None:
    assert _effective_status("dispatched", "queued") == ("dispatched", True)
    assert _effective_status("queued", "accepted") == ("queued", True)
    assert _effective_status("accepted", "dispatched") == ("dispatched", False)


def test_projection_refreshes_the_active_communications_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    store = MemoryCommunicationsStore()
    request = _request(body, _headers(body))
    request.scope["app"] = SimpleNamespace(
        state=SimpleNamespace(
            runtime=SimpleNamespace(
                communications=SimpleNamespace(store=store),
            ),
        ),
    )

    _receive(request, _Session(message))

    assert store.messages[(message.tenantId, message.messageId)].status == "delivered"
    assert len(store.events[(message.tenantId, message.messageId)]) == 1


def test_chunked_body_limit_is_enforced_before_json_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "telnexa_event_request_max_bytes", 16)
    message = _message()
    body = _event(message)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), _Session(message))
    assert error.value.status_code == 413


def test_message_projection_rejects_cross_tenant_or_non_sms_records() -> None:
    message = _message()
    event = TelnexaDeliveryEvent.model_validate(
        json.loads(_event(message))
    )
    with pytest.raises(HTTPException) as error:
        _project_message(event, {**message.model_dump(mode="json"), "tenantId": "other"})
    assert error.value.status_code == 409
