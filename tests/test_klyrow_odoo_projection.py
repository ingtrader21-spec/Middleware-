from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from dataclasses import replace
from datetime import UTC, datetime

import httpx
import pytest

from app.klyrow_odoo_projection import (
    PROJECTION_PATH,
    KlyrowOdooProjectionDispatcher,
    KlyrowProjectionError,
)
from app.api.internal.klyrow_events import operation_id_for_klyrow_event
from app.models import EventEnvelope
from app.storage import KLYROW_ODOO_PROJECTION_DESTINATION, OutboxRecord
from app.worker import KnownSafeRetryError


BASE_URL = "https://odoo.internal.invalid"
SECRET = b"synthetic-klyrow-odoo-signing-secret-32-bytes"
EVENT_ID = "evt_usage_1"
OPERATION_ID = operation_id_for_klyrow_event(EVENT_ID)


def _record() -> OutboxRecord:
    source = {
        "id": EVENT_ID,
        "type": "klyrow.usage.daily",
        "version": 1,
        "source": "klyrow",
        "tenant_id": "tenant-1",
        "correlation_id": "correlation-1",
        "causation_id": "cause-1",
        "occurred_at": "2026-09-13T00:00:00Z",
        "data": {
            "date": "2026-09-12",
            "unit": "accepted_message",
            "quantity": 3,
            "snapshot_at": "2026-09-13T00:00:00Z",
        },
    }
    envelope = EventEnvelope(
        event_id=source["id"],
        event_type="codestra." + source["type"],
        event_version="1.0",
        occurred_at=datetime(2026, 9, 13, tzinfo=UTC),
        received_at=datetime(2026, 9, 13, tzinfo=UTC),
        source="klyrow-gateway",
        tenant_id="tenant-1",
        correlation_id="correlation-1",
        causation_id="cause-1",
        idempotency_key=source["id"],
        payload={
            "operation_id": OPERATION_ID,
            "source_event": source,
            "trace_context": {
                "traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
            },
        },
        metadata={
            "operation_id": OPERATION_ID,
            "wire_event_type": source["type"],
            "wire_source": "klyrow",
        },
    )
    return OutboxRecord(
        id=1,
        tenant_id=envelope.tenant_id,
        destination=KLYROW_ODOO_PROJECTION_DESTINATION,
        event_type=envelope.event_type,
        idempotency_key=envelope.idempotency_key,
        payload=envelope.model_dump(mode="json"),
        attempt_count=1,
    )


def _dispatcher(handler) -> KlyrowOdooProjectionDispatcher:
    return KlyrowOdooProjectionDispatcher(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        base_url=BASE_URL,
        secrets={},
        default_secret=SECRET,
    )


def _proved(request: httpx.Request, status: str = "APPLIED") -> httpx.Response:
    payload = json.loads(request.content)
    return httpx.Response(
        200,
        json={
            "operation_id": payload["operation_id"],
            "status": status,
            "payload_sha256": hashlib.sha256(request.content).hexdigest(),
        },
    )


def test_projection_is_signed_and_exact_success_is_accepted() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _proved(request)

    asyncio.run(_dispatcher(handler).dispatch(_record()))
    request = requests[0]
    assert request.url.path == PROJECTION_PATH
    canonical = b"\n".join(
        (
            request.headers["X-Codestra-Timestamp"].encode(),
            request.headers["X-Codestra-Event-ID"].encode(),
            b"POST",
            PROJECTION_PATH.encode(),
            b"tenant-1",
            b"correlation-1",
            b"evt_usage_1",
            request.content,
        )
    )
    expected = hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
    assert request.headers["X-Codestra-Signature"] == "sha256=" + expected
    assert json.loads(request.content)["event_type"] == "klyrow.usage.daily"


def test_odoo_outage_retries_then_duplicate_recovery_creates_one_logical_record() -> (
    None
):
    calls = 0
    logical_records: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("odoo unavailable", request=request)
        payload = json.loads(request.content)
        logical_records.add(payload["operation_id"])
        return _proved(request, "DUPLICATE" if calls > 2 else "APPLIED")

    dispatcher = _dispatcher(handler)
    record = _record()
    with pytest.raises(KnownSafeRetryError):
        asyncio.run(dispatcher.dispatch(record))
    asyncio.run(dispatcher.dispatch(record))
    asyncio.run(dispatcher.dispatch(record))
    assert logical_records == {OPERATION_ID}


def test_missing_business_entity_is_preserved_for_safe_retry() -> None:
    dispatcher = _dispatcher(lambda _: httpx.Response(404))
    with pytest.raises(KnownSafeRetryError, match="not available"):
        asyncio.run(dispatcher.dispatch(_record()))


def test_reconciliation_retry_repairs_a_deliberately_missing_projection() -> None:
    calls = 0
    repaired: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(404)
        payload = json.loads(request.content)
        repaired.add(payload["operation_id"])
        return _proved(request)

    dispatcher = _dispatcher(handler)
    record = _record()
    with pytest.raises(KnownSafeRetryError):
        asyncio.run(dispatcher.dispatch(record))
    asyncio.run(dispatcher.dispatch(record))
    assert repaired == {OPERATION_ID}


def test_wrong_destination_or_unproved_ack_never_completes() -> None:
    wrong = replace(_record(), destination="nats-jetstream")
    with pytest.raises(KlyrowProjectionError, match="unsupported destination"):
        asyncio.run(_dispatcher(lambda _: httpx.Response(200)).dispatch(wrong))

    with pytest.raises(KlyrowProjectionError, match="status 200"):
        asyncio.run(
            _dispatcher(
                lambda _: httpx.Response(200, json={"status": "APPLIED"})
            ).dispatch(_record())
        )


def test_tampered_source_event_or_operation_binding_never_reaches_odoo() -> None:
    record = _record()
    tampered = json.loads(json.dumps(record.payload))
    tampered["payload"]["source_event"]["correlation_id"] = "other-correlation"
    record = replace(record, payload=tampered)

    with pytest.raises(KlyrowProjectionError, match="binding is invalid"):
        asyncio.run(_dispatcher(lambda _: httpx.Response(200)).dispatch(record))

    record = _record()
    tampered = json.loads(json.dumps(record.payload))
    tampered["payload"]["operation_id"] = "op_00000000000000000000000000000000"
    record = replace(record, payload=tampered)
    with pytest.raises(KlyrowProjectionError, match="binding is invalid"):
        asyncio.run(_dispatcher(lambda _: httpx.Response(200)).dispatch(record))


def test_ambiguous_server_failure_requires_readback_before_retry() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(500)
        return httpx.Response(404)

    with pytest.raises(KnownSafeRetryError, match="proved.*absent"):
        asyncio.run(_dispatcher(handler).dispatch(_record()))
    assert [(request.method, request.url.path) for request in requests] == [
        ("POST", PROJECTION_PATH),
        ("GET", f"{PROJECTION_PATH}/{OPERATION_ID}"),
    ]
