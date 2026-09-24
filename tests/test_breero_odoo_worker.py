from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import httpx

from app.core.config import Settings
from app.workers.breero_odoo import (
    DeliveryFailure,
    RestrictedOdooTransport,
    ROUTES,
    build_odoo_envelope,
)


def test_worker_is_disabled_and_credentials_are_file_backed():
    value = Settings()
    assert value.breero_odoo_delivery_enabled is False
    assert value.breero_odoo_api_key_file == ""
    source = Path("app/workers/breero_odoo.py").read_text()
    assert "FOR UPDATE SKIP LOCKED" in source
    assert "lease_token=:token" in source
    assert '"breero.sync.event"' in source
    assert '"process_breero_event"' in source
    assert "res.users" not in source


def test_four_routes_only():
    assert ROUTES == {
        "BREERO_CUSTOMER_REQUESTS",
        "BREERO_SUPPORT_BUSINESS",
        "BREERO_PROVIDER_RECRUITMENT",
        "BREERO_LEAD_DISPUTES",
    }


def test_complete_ingress_contract_is_forwarded_to_odoo():
    event_id, aggregate_id = uuid4(), uuid4()
    occurred_at = datetime(2026, 8, 13, tzinfo=timezone.utc)
    envelope = build_odoo_envelope(
        {
            "event_id": event_id,
            "event_type": "breero.service_request.created",
            "schema_version": 1,
            "aggregate_id": aggregate_id,
            "aggregate_version": 2,
            "occurred_at": occurred_at,
            "idempotency_key": "breero-test-1",
            "source": "breero",
            "payload": {"submission_id": "synthetic-only"},
        }
    )
    assert envelope == {
        "event_id": str(event_id),
        "event_type": "breero.service_request.created",
        "schema_version": 1,
        "aggregate_id": str(aggregate_id),
        "aggregate_version": 2,
        "occurred_at": occurred_at.isoformat(),
        "idempotency_key": "breero-test-1",
        "source": "breero",
        "payload": {"submission_id": "synthetic-only"},
    }


@pytest.mark.asyncio
async def test_missing_secret_is_permanent(monkeypatch):
    monkeypatch.setattr(
        "app.workers.breero_odoo.settings.breero_odoo_api_key_file", "/missing"
    )
    with pytest.raises(DeliveryFailure) as caught:
        await RestrictedOdooTransport().deliver({}, "idem")
    assert caught.value.permanent and caught.value.code == "credential_unavailable"


@pytest.mark.asyncio
async def test_transport_authenticates_before_execute_kw(monkeypatch, tmp_path):
    secret = tmp_path / "odoo-key"
    secret.write_text("protected-test-value")
    monkeypatch.setattr(
        "app.workers.breero_odoo.settings.breero_odoo_api_key_file", str(secret)
    )
    monkeypatch.setattr(
        "app.workers.breero_odoo.settings.breero_odoo_url", "https://odoo.invalid"
    )
    monkeypatch.setattr(
        "app.workers.breero_odoo.settings.breero_odoo_database", "test_db"
    )
    monkeypatch.setattr(
        "app.workers.breero_odoo.settings.breero_odoo_username", "restricted.user"
    )
    requests = []

    async def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": 42})
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "result": {"odoo_model": "crm.lead", "odoo_record_id": 7},
            },
        )

    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr("app.workers.breero_odoo.httpx.AsyncClient", client)
    ack = await RestrictedOdooTransport().deliver({"event_id": "synthetic"}, "idem")
    assert ack == {"odoo_model": "crm.lead", "odoo_record_id": 7}
    assert b'"service":"common"' in requests[0].content
    assert b'"authenticate"' in requests[0].content
    assert b'"service":"object"' in requests[1].content
    assert b'42' in requests[1].content


def test_migration_and_entrypoint_are_non_destructive_and_disabled():
    entry = Path("app/entrypoints/breero_odoo_worker.py").read_text()
    assert "if not settings.breero_odoo_delivery_enabled" in entry
    migration = Path("migrations/versions/0044_breero_integration.py").read_text()
    assert "ON DELETE RESTRICT" in migration
