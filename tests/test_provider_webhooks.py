import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response

from app.api.v1 import provider_webhooks
from app.db.models import IntegrationDelivery, OdooResultDelivery, OutboxEvent


VICIDIAL = {
    "call_id": "stage2-test-001",
    "phone_number": "+15555550199",
    "disposition": "ANSWER",
    "call_time": 67,
    "campaign_id": "stage2-verification",
}


class Request:
    def __init__(self, payload, *, content_type="application/json"):
        self.raw = json.dumps(payload, separators=(",", ":")).encode()
        self.headers = {"content-type": content_type}

    async def stream(self):
        yield self.raw


class Session:
    def __init__(self, existing=None):
        self.existing = existing
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, *_args, **_kwargs):
        return None

    async def scalar(self, _query):
        return self.existing

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        self.added[0].id = 17

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


_STAMP: dict[str, object] = {"value": None, "at": 0.0}


def timestamp():
    # Refreshed at most once a minute: an import-time timestamp goes stale
    # (beyond the 300-second signature window) in a long full-suite run, while
    # the signature and the header of one request must agree.
    now = time.time()
    if _STAMP["value"] is None or now - float(_STAMP["at"]) > 60:
        _STAMP["value"] = str(int(now))
        _STAMP["at"] = now
    return str(_STAMP["value"])


def signature(request, secret, ts=None):
    # Provider contract: HMAC-SHA256 over "{timestamp}." + raw body.
    ts = timestamp() if ts is None else ts
    return hmac.new(
        secret.encode(), f"{ts}.".encode() + request.raw, hashlib.sha256
    ).hexdigest()


@pytest.mark.asyncio
async def test_valid_signature_persists_odoo_intent_and_platform_event(monkeypatch):
    request = Request(VICIDIAL)
    session = Session()
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    monkeypatch.setattr(provider_webhooks.settings, "odoo_write_enabled", True)
    response = Response()
    result = await provider_webhooks.vicidial_call_result(
        request, response, signature(request, "v" * 32), timestamp(), session
    )
    assert result["accepted"] is True
    assert response.status_code == 202
    assert any(
        isinstance(item, IntegrationDelivery) and item.status == "pending"
        for item in session.added
    )
    assert any(
        isinstance(item, OdooResultDelivery)
        and item.status == "PENDING"
        and item.standard_result_json["operation"] == "log_call_result"
        for item in session.added
    )
    assert any(
        isinstance(item, OutboxEvent) and item.topic == "call_disposition_updated"
        for item in session.added
    )
    record = next(
        item for item in session.added if item.__class__.__name__ == "IdempotencyRecord"
    )
    assert record.status_code == 202


@pytest.mark.asyncio
async def test_invalid_signature_is_rejected(monkeypatch):
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    with pytest.raises(HTTPException) as raised:
        await provider_webhooks.vicidial_call_result(
            Request(VICIDIAL), Response(), "0" * 64, timestamp(), Session()
        )
    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_duplicate_call_id_is_safe_noop(monkeypatch):
    request = Request(VICIDIAL)
    digest = hashlib.sha256(request.raw).hexdigest()
    existing = SimpleNamespace(
        request_hash=digest,
        response={"accepted": True, "event_id": "vicidial:stage2-test-001"},
    )
    session = Session(existing)
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    response = Response()
    result = await provider_webhooks.vicidial_call_result(
        request, response, signature(request, "v" * 32), timestamp(), session
    )
    assert result == existing.response
    assert response.status_code == 202
    assert "x-idempotent-replay" not in response.headers
    assert session.added == []
    assert session.commits == 1


def test_disposition_map_covers_all_required_codes():
    assert set(provider_webhooks.DISPOSITION_MAP) == {
        "ANSWER",
        "NOANSWER",
        "BUSY",
        "SVUNREACH",
        "DONTCALL",
        "CALLBK",
        "VOICEMAIL",
        "SALE",
        "DROP",
        "NI",
    }


@pytest.mark.asyncio
async def test_odoo_write_is_disabled_by_flag(monkeypatch):
    request = Request(VICIDIAL)
    session = Session()
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    monkeypatch.setattr(provider_webhooks.settings, "odoo_write_enabled", False)
    result = await provider_webhooks.vicidial_call_result(
        request, Response(), signature(request, "v" * 32), timestamp(), session
    )
    delivery = next(
        item for item in session.added if isinstance(item, IntegrationDelivery)
    )
    assert delivery.status == "disabled"
    assert not any(isinstance(item, OdooResultDelivery) for item in session.added)
    assert result["odoo_write"] == "disabled"


@pytest.mark.asyncio
async def test_telnexa_valid_signature_publishes_sms_received(monkeypatch):
    request = Request(
        {
            "message_id": "sms-stage2-001",
            "from": "+15555550199",
            "body": "Hello",
            "received_at": "2026-08-29T06:00:00Z",
        }
    )
    session = Session()
    monkeypatch.setattr(provider_webhooks.settings, "telnexa_webhook_secret", "t" * 32)
    result = await provider_webhooks.telnexa_inbound_sms(
        request, Response(), signature(request, "t" * 32), timestamp(), session
    )
    assert result["accepted"] is True
    assert any(
        isinstance(item, OutboxEvent) and item.topic == "sms_received"
        for item in session.added
    )


@pytest.mark.asyncio
async def test_stale_timestamp_is_rejected_before_persistence(monkeypatch):
    request = Request(VICIDIAL)
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    monkeypatch.setattr(provider_webhooks.settings, "signature_ttl_seconds", 300)
    stale = str(int(time.time()) - 301)
    with pytest.raises(HTTPException) as raised:
        await provider_webhooks.vicidial_call_result(
            request,
            Response(),
            signature(request, "v" * 32, stale),
            stale,
            Session(),
        )
    assert raised.value.status_code == 403
    assert "window" in raised.value.detail


@pytest.mark.asyncio
async def test_captured_signature_cannot_be_replayed_with_fresh_timestamp(monkeypatch):
    request = Request(VICIDIAL)
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    monkeypatch.setattr(provider_webhooks.settings, "signature_ttl_seconds", 300)
    captured = signature(request, "v" * 32, str(int(time.time()) - 200))
    with pytest.raises(HTTPException) as raised:
        await provider_webhooks.vicidial_call_result(
            request, Response(), captured, timestamp(), Session()
        )
    assert raised.value.status_code == 403
    assert raised.value.detail == "webhook signature is invalid"


@pytest.mark.asyncio
async def test_missing_timestamp_is_rejected(monkeypatch):
    request = Request(VICIDIAL)
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    with pytest.raises(HTTPException) as raised:
        await provider_webhooks.vicidial_call_result(
            request, Response(), signature(request, "v" * 32), None, Session()
        )
    assert raised.value.status_code == 403


@pytest.mark.asyncio
async def test_non_json_and_oversized_bodies_are_rejected_before_verification(
    monkeypatch,
):
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    non_json = Request(VICIDIAL, content_type="text/plain")
    with pytest.raises(HTTPException) as content_type_error:
        await provider_webhooks.vicidial_call_result(
            non_json,
            Response(),
            signature(non_json, "v" * 32),
            timestamp(),
            Session(),
        )
    assert content_type_error.value.status_code == 415

    monkeypatch.setattr(provider_webhooks.settings, "request_max_bytes", 16)
    oversized = Request(VICIDIAL)
    with pytest.raises(HTTPException) as oversized_error:
        await provider_webhooks.vicidial_call_result(
            oversized,
            Response(),
            signature(oversized, "v" * 32),
            timestamp(),
            Session(),
        )
    assert oversized_error.value.status_code == 413


@pytest.mark.asyncio
async def test_changed_payload_for_existing_event_is_rejected(monkeypatch):
    request = Request(VICIDIAL)
    changed = Request({**VICIDIAL, "comments": "changed"})
    existing = SimpleNamespace(
        request_hash=hashlib.sha256(request.raw).hexdigest(),
        response={"accepted": True, "event_id": "vicidial:stage2-test-001"},
    )
    monkeypatch.setattr(provider_webhooks.settings, "vicidial_webhook_secret", "v" * 32)
    session = Session(existing)
    with pytest.raises(HTTPException) as raised:
        await provider_webhooks.vicidial_call_result(
            changed,
            Response(),
            signature(changed, "v" * 32),
            timestamp(),
            session,
        )
    assert raised.value.status_code == 409
    assert session.rollbacks == 1
