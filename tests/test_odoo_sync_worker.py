import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from app.adapters.odoo import sync
from app.core.config import settings


def _record() -> dict[str, object]:
    payload = {"name": "TEST_SYN_EVENT", "tenant_id": "COD"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {
        "event_id": "TEST_SYN_EVENT_1",
        "event_type": "campaign.event",
        "schema_version": "1.0",
        "payload": payload,
        "payload_hash": f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        "correlation_id": "TEST_SYN_CORRELATION",
        "lease_token": "test-lease",
        "lease_generation": 1,
    }


def test_outbox_record_hash_is_verified():
    payload, digest = sync._validate_record(_record())
    assert payload["tenant_id"] == "COD"
    assert len(digest) == 64


def test_modified_outbox_record_is_rejected():
    record = _record()
    record["payload"] = {"name": "modified"}
    with pytest.raises(sync.OdooSyncError, match="payload hash"):
        sync._validate_record(record)


def test_runtime_client_binds_token_nonce_hash_and_integer_timestamp(monkeypatch):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(200, json={"status": "ok"})

    monkeypatch.setattr(settings, "odoo_base_url", "https://odoo.test")
    client = sync.OdooRuntimeClient(
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        access_token="test-token",
    )
    result = asyncio.run(
        client.request(
            "POST",
            "/api/v1/integration/test",
            {"test": True},
            idempotency_key="test-key",
            correlation_id="test-correlation",
            causation_id="test-causation",
        )
    )
    asyncio.run(client.aclose())
    assert result == {"status": "ok"}
    assert captured["authorization"] == "Bearer test-token"
    assert captured["x-codestra-timestamp"].isdigit()
    assert len(captured["x-codestra-nonce"]) == 48
    assert len(captured["x-codestra-body-sha256"]) == 64


def test_sync_cycle_claims_persists_then_acknowledges(monkeypatch):
    record = _record()
    client = AsyncMock()
    client.request.side_effect = [
        {"capabilities": ["outbox.claim", "outbox.acknowledge"]},
        {"records": [record]},
        {"delivery_state": "delivered"},
    ]
    monkeypatch.setattr(
        sync.OdooRuntimeClient, "create", AsyncMock(return_value=client)
    )
    persist = AsyncMock(return_value=(False, 1))
    monkeypatch.setattr(sync, "persist_intake", persist)
    result = asyncio.run(sync.run_sync_cycle())
    assert result == {
        "status": "processed",
        "claimed": 1,
        "accepted": 1,
        "duplicates": 0,
    }
    persist.assert_awaited_once_with(record)
    assert client.request.await_count == 3
    ack = client.request.await_args_list[2]
    assert ack.args[1].endswith("/TEST_SYN_EVENT_1/acknowledgements")
    client.aclose.assert_awaited_once()


def test_sync_cycle_fails_closed_on_incompatible_capabilities(monkeypatch):
    client = AsyncMock()
    client.request.return_value = {"capabilities": ["outbox.claim"]}
    monkeypatch.setattr(
        sync.OdooRuntimeClient, "create", AsyncMock(return_value=client)
    )
    with pytest.raises(sync.OdooSyncError, match="capability"):
        asyncio.run(sync.run_sync_cycle())
    client.aclose.assert_awaited_once()
