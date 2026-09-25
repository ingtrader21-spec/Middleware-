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
    VERIFY_PATH,
    TelnexaDeliveryEvent,
    _effective_status,
    _project_message,
    receive_telnexa_event,
    reconcile_telnexa_inbox,
    router,
)
from app.communications import CommunicationMessage, MemoryCommunicationsStore
from app.core.config import Settings, settings
from app.telnexa_callback_identity import CLIENT_CERT_DER_HEADER
from scripts.telnexa_callback_harness import (
    issue_authority,
    issue_client_leaf,
    run_harness,
)


API_KEY = "telnexa-api-key-fixture"
HMAC_SECRET = b"telnexa-hmac-secret-fixture-that-is-long-enough"
AUTHORITY = issue_authority()
CLIENT = issue_client_leaf(AUTHORITY)
TRUSTED_PEER = ("10.250.241.2", 44321)


class _Result:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def mappings(self):
        return self

    def first(self):
        return self.value

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.value


class _Nested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    def __init__(self, message: CommunicationMessage | None):
        self.message = message
        self.inbox_rows: dict[str, dict[str, object]] = {}
        self.updated_payload: dict[str, object] | None = None
        self.timeline: list[dict[str, object]] = []
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.commit_count = 0
        self.rollback_count = 0

    @property
    def inbox(self) -> dict[str, object]:
        return self.inbox_rows.get("delivery-1", {})

    def begin_nested(self):
        return _Nested()

    def _retry_rows(self, values, *, same_message: bool):
        rows = [
            {"event_id": key, "payload_hash": row["payload_hash"], "payload": row["payload"]}
            for key, row in self.inbox_rows.items()
            if row["processing_status"] == "retry"
            and (
                not same_message
                or (
                    row["tenant_id"] == values["tenant_id"]
                    and row["message_id"] == str(values["message_id"])
                    and key != values["event_id"]
                )
            )
        ]
        rows.sort(key=lambda row: (row["payload"]["occurred_at"], row["event_id"]))
        return rows[: values["limit"]]

    async def execute(self, statement, parameters=None):
        sql = str(statement)
        values = parameters or {}
        self.calls.append((sql, values))
        if "SELECT payload_hash,processing_status" in sql:
            row = self.inbox_rows.get(values["event_id"])
            return _Result(None if row is None else dict(row))
        if "INSERT INTO telnexa_delivery_event_inbox" in sql:
            payload = json.loads(values["payload"])
            self.inbox_rows[values["event_id"]] = {
                "payload_hash": values["hash"],
                "processing_status": "pending",
                "attempts": 0,
                "payload": payload,
                "tenant_id": payload["tenant_id"],
                "message_id": payload["message_id"],
                "last_error": None,
            }
            return _Result()
        if "SELECT payload FROM middleware_communication_messages" in sql:
            if self.message is None or str(self.message.messageId) != str(values["message_id"]):
                return _Result()
            return _Result({"payload": self.message.model_dump(mode="json")})
        if "UPDATE middleware_communication_messages" in sql:
            self.updated_payload = json.loads(values["payload"])
            self.message = CommunicationMessage.model_validate(self.updated_payload)
            return _Result()
        if "INSERT INTO middleware_communication_events" in sql:
            self.timeline.append(json.loads(values["payload"]))
            return _Result()
        if "SELECT event_id,payload_hash,payload FROM telnexa_delivery_event_inbox" in sql:
            return _Result(
                rows=self._retry_rows(values, same_message="tenant_id=:tenant_id" in sql)
            )
        if "UPDATE telnexa_delivery_event_inbox" in sql:
            row = self.inbox_rows[values["event_id"]]
            if "RETURNING processing_status" in sql:
                row["attempts"] = int(row["attempts"]) + 1
                row["processing_status"] = (
                    "dead_letter" if row["attempts"] >= values["max_attempts"] else "retry"
                )
                row["last_error"] = values["error"]
                return _Result(row["processing_status"])
            if "processing_status='complete'" in sql:
                row["processing_status"] = "complete"
                row["attempts"] = int(row["attempts"]) + 1
            if "processing_status='dead_letter'" in sql:
                row["processing_status"] = "dead_letter"
                row["last_error"] = values.get("error", "invalid_inbox_payload")
            return _Result()
        return _Result()

    async def commit(self):
        self.commit_count += 1

    async def rollback(self):
        self.rollback_count += 1


def _request(
    body: bytes,
    headers: dict[str, str],
    *,
    certificate: str | None = CLIENT.der_b64,
    peer: tuple[str, int] = TRUSTED_PEER,
    path: str = PATH,
) -> Request:
    timestamp = headers["X-Timestamp"]
    event_id = headers["X-Event-Id"]
    signature = hmac.new(
        HMAC_SECRET,
        f"{timestamp}\n{event_id}\ntelnexa\n".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    raw_headers = [(b"content-type", b"application/json")]
    raw_headers.extend((key.lower().encode(), value.encode()) for key, value in headers.items())
    if certificate is not None:
        raw_headers.append((CLIENT_CERT_DER_HEADER.lower().encode(), certificate.encode()))
    raw_headers.append((b"x-signature", f"sha256={signature}".encode()))

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": raw_headers,
            "client": peer,
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


def _event(
    message: CommunicationMessage,
    *,
    event_id: str = "delivery-1",
    event_type: str = "sms.message.delivered.v1",
    status: str = "delivered",
    occurred_at: str = "2026-09-12T00:00:00Z",
) -> bytes:
    return json.dumps(
        {
            "event_id": event_id,
            "event_type": event_type,
            "event_version": "1.0",
            "schema_version": "1.0",
            "timestamp": str(int(time.time())),
            "occurred_at": occurred_at,
            "tenant_id": message.tenantId,
            "correlation_id": message.correlationId,
            "idempotency_key": message.idempotencyKey,
            "message_id": str(message.messageId),
            "provider_reference": "telnexa-provider-1",
            "status": status,
            "provider_status": "DELIVRD" if status == "delivered" else status.upper(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _headers(body: bytes, *, event_id: str | None = None) -> dict[str, str]:
    payload = json.loads(body)
    return {
        "Authorization": f"Bearer {API_KEY}",
        "X-Event-Id": event_id or payload["event_id"],
        "X-Timestamp": payload["timestamp"],
        "Idempotency-Key": payload["idempotency_key"],
    }


@pytest.fixture(autouse=True)
def _client_ca(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch):
    ca_file = tmp_path_factory.mktemp("telnexa-ca") / "ca.pem"
    ca_file.write_bytes(AUTHORITY.pem)
    monkeypatch.setattr(settings, "telnexa_event_client_ca_file", str(ca_file))
    monkeypatch.setattr(settings, "telnexa_event_trusted_proxy_cidrs", "10.250.241.0/29")
    monkeypatch.setattr(settings, "telnexa_event_client_cert_sha256", "")
    monkeypatch.setattr(settings, "telnexa_event_reconcile_max_attempts", 12)
    monkeypatch.setattr(settings, "telnexa_event_reconcile_batch_size", 100)
    return ca_file


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


def test_ingress_requires_private_mtls_identity_before_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    rogue = issue_client_leaf(issue_authority())
    cases = [
        ({"certificate": None}, 401, "telnexa_client_certificate_required"),
        ({"certificate": rogue.der_b64}, 403, "untrusted_telnexa_client_certificate"),
        ({"peer": ("203.0.113.9", 1)}, 403, "untrusted_telnexa_callback_peer"),
    ]
    for overrides, status_code, detail in cases:
        database = _Session(message)
        with pytest.raises(HTTPException) as error:
            _receive(_request(body, _headers(body), **overrides), database)
        assert (error.value.status_code, error.value.detail) == (status_code, detail)
        assert database.calls == []


def test_unconfigured_trust_contract_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "telnexa_event_trusted_proxy_cidrs", "")
    message = _message()
    body = _event(message)
    database = _Session(message)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), database)
    assert error.value.status_code == 503
    assert error.value.detail == "telnexa_callback_identity_unavailable"
    assert database.calls == []


def test_fingerprint_pin_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    monkeypatch.setattr(settings, "telnexa_event_client_cert_sha256", "b" * 64)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), _Session(message))
    assert error.value.status_code == 403

    monkeypatch.setattr(settings, "telnexa_event_client_cert_sha256", CLIENT.sha256)
    assert _receive(_request(body, _headers(body)), _Session(message))["accepted"] is True


def test_verified_identity_is_persisted_as_projection_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message)
    database = _Session(message)
    _receive(_request(body, _headers(body)), database)

    assert database.updated_payload is not None
    identity = database.updated_payload["metadata"]["callbackIdentity"]
    assert identity["certificateSha256"] == CLIENT.sha256
    assert identity["uriSan"] == settings.telnexa_event_client_uri_san
    assert database.timeline[0]["metadata"]["callbackIdentity"] == identity
    assert database.timeline[0]["metadata"]["reconciledFromInbox"] is False


def test_ingress_refuses_synthetic_events_before_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    body = _event(message, event_id="synthetic-delivery-1")
    database = _Session(message)
    with pytest.raises(HTTPException) as error:
        _receive(_request(body, _headers(body)), database)
    assert error.value.status_code == 422
    assert error.value.detail == "synthetic_telnexa_event_rejected"
    assert database.calls == []


def test_earlier_retry_callbacks_are_reconciled_in_occurrence_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    database = _Session(None)
    early = _event(
        message,
        event_id="status-early",
        event_type="sms.message.status.v1",
        status="dispatched",
        occurred_at="2026-09-12T00:00:00Z",
    )
    with pytest.raises(HTTPException) as error:
        _receive(_request(early, _headers(early)), database)
    assert error.value.detail == "communication_message_unavailable"
    assert database.inbox_rows["status-early"]["processing_status"] == "retry"

    database.message = message
    late = _event(message, event_id="delivered-late", occurred_at="2026-09-12T00:05:00Z")
    result = _receive(_request(late, _headers(late)), database)

    assert result["reconciled_event_ids"] == ["status-early"]
    assert result["communication_status"] == "delivered"
    assert database.inbox_rows["status-early"]["processing_status"] == "complete"
    assert database.inbox_rows["delivered-late"]["processing_status"] == "complete"
    assert [item["metadata"]["providerEventId"] for item in database.timeline] == [
        "status-early",
        "delivered-late",
    ]
    assert database.timeline[0]["metadata"]["reconciledFromInbox"] is True
    assert "callbackIdentity" not in database.timeline[0]["metadata"]
    assert database.commit_count == 2


def test_orphan_callback_is_dead_lettered_at_policy_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "telnexa_event_reconcile_max_attempts", 2)
    message = _message()
    body = _event(message)
    database = _Session(None)
    with pytest.raises(HTTPException):
        _receive(_request(body, _headers(body)), database)
    assert database.inbox["processing_status"] == "retry"

    second = _receive(_request(body, _headers(body)), database)
    assert second["status"] == "dead_letter"
    assert second["duplicate"] is True
    assert database.inbox["processing_status"] == "dead_letter"

    database.message = message
    third = _receive(_request(body, _headers(body)), database)
    assert third["status"] == "dead_letter"
    assert database.updated_payload is None


def test_reconciliation_sweep_completes_retries_and_dead_letters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    message = _message()
    orphan = _message()
    database = _Session(None)
    bodies = {
        "status-early": _event(
            message,
            event_id="status-early",
            event_type="sms.message.status.v1",
            status="dispatched",
            occurred_at="2026-09-12T00:00:00Z",
        ),
        "delivered-late": _event(
            message, event_id="delivered-late", occurred_at="2026-09-12T00:05:00Z"
        ),
        "orphan": _event(orphan, event_id="orphan"),
    }
    for body in bodies.values():
        with pytest.raises(HTTPException):
            _receive(_request(body, _headers(body)), database)
    database.message = message

    summary = asyncio.run(
        reconcile_telnexa_inbox(cast(AsyncSession, database), max_attempts=2, batch_size=10)
    )

    assert summary["scanned"] == 3
    assert summary["completed"] == ["status-early", "delivered-late"]
    assert summary["dead_lettered"] == ["orphan"]
    assert summary["retried"] == []
    assert database.inbox_rows["orphan"]["processing_status"] == "dead_letter"
    assert database.updated_payload is not None
    assert database.updated_payload["status"] == "delivered"
    assert all(item["metadata"]["reconciledFromInbox"] for item in database.timeline)


def test_reconciliation_sweep_bounds_are_enforced() -> None:
    with pytest.raises(ValueError):
        asyncio.run(
            reconcile_telnexa_inbox(
                cast(AsyncSession, _Session(None)), max_attempts=0, batch_size=10
            )
        )


def test_verify_route_is_registered_without_database_dependency() -> None:
    route = next(
        item for item in router.routes if getattr(item, "path", None) == VERIFY_PATH
    )
    assert isinstance(route, APIRoute)
    assert route.methods == {"POST"}
    assert not route.dependant.dependencies


def test_signed_synthetic_harness_passes_with_zero_database_effects() -> None:
    run = asyncio.run(run_harness())
    evidence = run.as_json()
    assert evidence["effect"] == "none"
    assert evidence["database_calls"] == 0
    failed = [case["name"] for case in evidence["cases"] if not case["passed"]]
    assert failed == []
    assert evidence["case_count"] >= 20


def test_settings_require_trust_contract_when_callbacks_enabled(tmp_path) -> None:
    base = {
        "telnexa_event_synthetic_verify_enabled": True,
        "telnexa_event_api_key": API_KEY,
        "telnexa_event_hmac_secret": HMAC_SECRET.decode(),
    }
    candidate = settings.model_copy(update=base)
    with pytest.raises(ValueError, match="TRUSTED_PROXY_CIDRS"):
        Settings.validate_telnexa_callback_trust(
            candidate.model_copy(update={"telnexa_event_trusted_proxy_cidrs": ""})
        )
    with pytest.raises(ValueError, match="small private"):
        Settings.validate_telnexa_callback_trust(
            candidate.model_copy(
                update={"telnexa_event_trusted_proxy_cidrs": "0.0.0.0/0"}
            )
        )
    with pytest.raises(ValueError, match="SPIFFE"):
        Settings.validate_telnexa_callback_trust(
            candidate.model_copy(
                update={
                    "telnexa_event_trusted_proxy_cidrs": "10.250.241.0/29",
                    "telnexa_event_client_ca_file": str(tmp_path / "ca.pem"),
                    "telnexa_event_client_uri_san": "https://telnexa.example",
                }
            )
        )
    Settings.validate_telnexa_callback_trust(
        candidate.model_copy(
            update={
                "telnexa_event_trusted_proxy_cidrs": "10.250.241.0/29",
                "telnexa_event_client_ca_file": str(tmp_path / "ca.pem"),
            }
        )
    )
