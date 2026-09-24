from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient
import pytest

from app.communications import CommunicationsNotFound, PostgresCommunicationsStore
from app.main import create_app
from tests.test_communications_sms import _message, _runtime, _token


def headers(scope="odoo.sms.command.write", tenant="tenant-1", key="odoo-sms:fixture-1"):
    return {
        "Authorization": "Bearer " + _token("odoo-sms", [scope], tenant_id=tenant),
        "X-Tenant-ID": tenant,
        "X-Correlation-ID": "odoo-fixture-1",
        "Idempotency-Key": key,
    }


def test_odoo_submission_and_get_only_recovery_are_tenant_bound(test_settings):
    runtime = _runtime(test_settings)
    with TestClient(create_app(settings=test_settings, runtime=runtime)) as client:
        created = client.post("/v1/communications/messages", json=_message(), headers=headers())
        assert created.status_code == 202, created.text
        path = "/v1/communications/messages/by-idempotency"
        for _ in range(2):
            read = client.get(path, headers=headers("odoo.sms.status.read"))
            assert read.status_code == 200, read.text
            assert read.json() == created.json()
        assert len(runtime.commands.store.submitted) == 1
        assert client.get(path, headers=headers()).status_code == 403
        missing_key = headers("odoo.sms.status.read")
        del missing_key["Idempotency-Key"]
        assert client.get(path, headers=missing_key).status_code == 400
        assert client.get(path, headers=headers("odoo.sms.status.read", "other-tenant")).status_code == 404
        assert client.get(path, headers=headers("odoo.sms.status.read", key="missing-1")).status_code == 404
        forged = headers("odoo.sms.status.read")
        forged["X-Tenant-ID"] = "other-tenant"
        assert client.get(path, headers=forged).status_code == 403
        email = {"channel": "email", "from": "sender@example.com", "to": ["recipient@example.com"], "content": {"text": "fixture"}}
        assert client.post("/v1/communications/messages", json=email, headers=headers()).status_code == 403


def test_readback_remains_available_when_delivery_is_disabled(test_settings):
    runtime = _runtime(test_settings)
    with TestClient(create_app(settings=test_settings, runtime=runtime)) as client:
        accepted = client.post("/v1/communications/messages", json=_message(), headers=headers()).json()
        runtime.communications.commands = _runtime(test_settings, sms_enabled=False).commands
        result = client.get("/v1/communications/messages/by-idempotency", headers=headers("odoo.sms.status.read"))
        assert result.status_code == 200
        assert result.json()["messageId"] == accepted["messageId"]


@pytest.mark.parametrize("method,path", [
    ("POST", "/v1/commands"),
    ("POST", "/v1/sms/commands"),
    ("GET", "/v1/operations"),
    ("GET", "/v1/operations/00000000-0000-4000-8000-000000000001"),
    ("POST", "/v1/operations/00000000-0000-4000-8000-000000000001/cancel"),
    ("POST", "/v1/operations/00000000-0000-4000-8000-000000000001/reconcile"),
    ("GET", "/v1/communications/messages"),
    ("GET", "/v1/communications/messages/00000000-0000-4000-8000-000000000001"),
    ("GET", "/v1/communications/usage"),
])
def test_sms_identity_cannot_enter_generic_api_routes(test_settings, method, path):
    runtime = _runtime(test_settings)
    with TestClient(create_app(settings=test_settings, runtime=runtime)) as client:
        for scope in ("odoo.sms.command.write", "odoo.sms.status.read"):
            response = client.request(method, path, headers=headers(scope))
            assert response.status_code == 403, response.text
            assert response.json()["error"]["code"] == "authorization_denied"
    assert not runtime.commands.store.submitted


def test_postgres_readback_queries_shared_durable_store(test_settings):
    import asyncio

    runtime = _runtime(test_settings)
    with TestClient(create_app(settings=test_settings, runtime=runtime)) as client:
        payload = client.post("/v1/communications/messages", json=_message(), headers=headers()).json()
    connection = AsyncMock()
    connection.fetchval.return_value = payload
    pool = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=connection)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    store = PostgresCommunicationsStore(pool)
    result = asyncio.run(store.message_by_idempotency("tenant-1", "odoo-sms:fixture-1"))
    assert str(result.messageId) == payload["messageId"]
    assert connection.fetchval.call_args.args[1:] == ("tenant-1", "POST /v1/communications/messages", "odoo-sms:fixture-1")
    assert store.messages == {}  # no dependence on this process's startup cache
    connection.fetchval.return_value = None
    with pytest.raises(CommunicationsNotFound):
        asyncio.run(store.message_by_idempotency("other-tenant", "odoo-sms:fixture-1"))
