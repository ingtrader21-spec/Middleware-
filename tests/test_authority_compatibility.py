from fastapi.testclient import TestClient
from uuid import UUID

from app.commands import CommandService, MemoryCommandStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore
from tests.test_commands import CommandTokenVerifier, command_payload, enabled_policy


REQUIRED = {
    "/api/v1/operations",
    "/api/v1/operations/{operation_id}",
    "/api/v1/operations/{operation_id}/cancel",
    "/api/v1/operations/{operation_id}/retry",
    "/api/v1/inbox",
    "/api/v1/inbox/{record_id}",
    "/api/v1/outbox",
    "/api/v1/outbox/{record_id}",
    "/api/v1/policy/decisions",
    "/api/v1/reconciliation/operations",
    "/api/v1/reconciliation/operations/{record_id}",
    "/api/v1/reconciliation/operations/{record_id}/resolve",
    "/api/v1/quarantine/events",
    "/api/v1/quarantine/events/{record_id}",
    "/api/v1/quarantine/events/{record_id}/release",
    "/api/v1/quarantine/events/{record_id}/discard",
}


def _app(test_settings):
    commands = CommandService(MemoryCommandStore(), enabled_policy())
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=CommandTokenVerifier(),
        commands=commands,
    )
    return create_app(settings=test_settings, runtime=runtime)


def test_compatibility_routes_are_real_runtime_operations(test_settings):
    schema = _app(test_settings).openapi()
    assert REQUIRED <= set(schema["paths"])
    for path in REQUIRED:
        assert not any(operation.get("deprecated") for operation in schema["paths"][path].values())


def test_compatibility_operation_read_is_authenticated_and_tenant_scoped(test_settings):
    body = command_payload()
    command_headers = {
        "Authorization": "Bearer legacy-command-token",
        "X-Tenant-ID": body["tenant_id"],
        "X-Correlation-ID": body["correlation_id"],
        "Idempotency-Key": body["idempotency_key"],
    }
    with TestClient(_app(test_settings)) as client:
        assert client.get("/api/v1/operations", headers={"X-Tenant-ID": "tenant-1"}).status_code == 401
        assert client.post("/v1/commands", json=body, headers=command_headers).status_code == 202
        read = {"Authorization": "Bearer legacy-status-token", "X-Tenant-ID": body["tenant_id"]}
        response = client.get(f"/api/v1/operations/{body['command_id']}", headers=read)
        assert response.status_code == 200
        assert response.json()["command_id"] == body["command_id"]
        denied = client.get(
            f"/api/v1/operations/{body['command_id']}",
            headers={"Authorization": "Bearer legacy-status-token", "X-Tenant-ID": "tenant-2"},
        )
        assert denied.status_code == 403


def test_operation_retry_is_versioned_idempotent_and_failed_only(test_settings):
    body = command_payload()
    headers = {
        "Authorization": "Bearer legacy-command-token",
        "X-Tenant-ID": body["tenant_id"],
        "X-Correlation-ID": body["correlation_id"],
        "Idempotency-Key": body["idempotency_key"],
    }
    app = _app(test_settings)
    with TestClient(app) as client:
        assert client.post("/v1/commands", json=body, headers=headers).status_code == 202
        store = app.state.runtime.commands.store
        import asyncio
        command_id = UUID(body["command_id"])
        asyncio.run(store.transition(body["tenant_id"], command_id, new_state="queued", actor_id="worker", reason="queued"))
        asyncio.run(store.transition(body["tenant_id"], command_id, new_state="dispatching", actor_id="worker", reason="dispatch"))
        asyncio.run(store.transition(body["tenant_id"], command_id, new_state="failed", actor_id="worker", reason="known safe failure"))
        mutation = {**headers, "Idempotency-Key": "retry-operation-key"}
        first = client.post(
            f"/api/v1/operations/{body['command_id']}/retry",
            headers=mutation,
            json={"expected_version": 1, "reason": "known_safe_retry"},
        )
        assert first.status_code == 200
        assert first.json()["state"] == "QUEUED"
        replay = client.post(
            f"/api/v1/operations/{body['command_id']}/retry",
            headers=mutation,
            json={"expected_version": 1, "reason": "known_safe_retry"},
        )
        assert replay.status_code == 200 and replay.json()["duplicate"] is True
        conflict = client.post(
            f"/api/v1/operations/{body['command_id']}/retry",
            headers=mutation,
            json={"expected_version": 1, "reason": "changed_reason"},
        )
        assert conflict.status_code == 409
