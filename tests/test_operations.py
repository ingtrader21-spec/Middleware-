from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.commands import CommandEnvelope, CommandService, MemoryCommandStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore
from tests.test_commands import CommandTokenVerifier, command_payload, enabled_policy


def _client(test_settings, store: MemoryCommandStore) -> TestClient:
    runtime = Runtime(settings=test_settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=CommandTokenVerifier(), commands=CommandService(store, enabled_policy()))
    return TestClient(create_app(settings=test_settings, runtime=runtime))


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer legacy-status-token", "X-Tenant-ID": "tenant-1"}


def test_operation_reads_are_tenant_scoped_paginated_and_redacted(test_settings) -> None:
    store = MemoryCommandStore()
    commands = [CommandEnvelope.model_validate(command_payload(command_id=str(uuid4()), idempotency_key=f"idempotency-{index}")) for index in range(3)]
    import asyncio
    for command in commands:
        asyncio.run(store.submit(command, authenticated_client_id="test-client"))
    asyncio.run(store.transition("tenant-1", commands[0].command_id, new_state="queued", actor_id="worker", reason="queued"))
    asyncio.run(store.transition("tenant-1", commands[0].command_id, new_state="dispatching", actor_id="worker", reason="dispatch"))
    store._events[("tenant-1", commands[0].command_id)][-1].safe_metadata.update({"access_token": "never-return", "nested": {"password": "never-return"}})

    with _client(test_settings, store) as client:
        first = client.get("/v1/operations?limit=2", headers=_headers())
        assert first.status_code == 200
        assert len(first.json()["items"]) == 2
        assert first.json()["next_cursor"]
        second = client.get("/v1/operations", params={"limit": 2, "cursor": first.json()["next_cursor"]}, headers=_headers())
        assert second.status_code == 200
        assert len(second.json()["items"]) == 1
        assert {row["command_id"] for row in first.json()["items"]}.isdisjoint({row["command_id"] for row in second.json()["items"]})
        assert client.get("/v1/operations?cursor=bad", headers=_headers()).status_code == 400
        assert client.get("/v1/operations?limit=101", headers=_headers()).status_code == 400
        assert client.get("/v1/operations?state=fictional", headers=_headers()).status_code == 400
        filtered = client.get("/v1/operations?state=SUBMITTED&command_type=crm.contact.create.v1", headers=_headers())
        assert [row["command_id"] for row in filtered.json()["items"]] == [str(commands[0].command_id)]
        events = client.get(f"/v1/operations/{commands[0].command_id}/events?limit=1", headers=_headers())
        assert events.json()["next_cursor"]
        events2 = client.get(f"/v1/operations/{commands[0].command_id}/events", params={"cursor": events.json()["next_cursor"]}, headers=_headers())
        assert events2.json()["items"][0]["new_state"] == "QUEUED"
        all_events = client.get(f"/v1/operations/{commands[0].command_id}/events", headers=_headers()).json()["items"]
        assert all_events[-1]["safe_metadata"]["access_token"] == "[REDACTED]"
        attempts = client.get(f"/v1/operations/{commands[0].command_id}/attempts", headers=_headers()).json()["items"]
        assert attempts[0]["attempt_number"] == 1
        assert "error_detail" not in attempts[0]


def test_operation_list_empty_and_cross_tenant_is_non_disclosing(test_settings) -> None:
    store = MemoryCommandStore()
    with _client(test_settings, store) as client:
        assert client.get("/v1/operations", headers=_headers()).json() == {"items": [], "next_cursor": None}
        missing = client.get(f"/v1/operations/{uuid4()}", headers=_headers())
        assert missing.status_code == 404


def test_versioned_cancel_and_reconcile_are_idempotent_and_provider_free(test_settings) -> None:
    import asyncio
    store = MemoryCommandStore()
    cancel_command = CommandEnvelope.model_validate(command_payload(command_id=str(uuid4()), idempotency_key="cancel-command-key"))
    reconcile_command = CommandEnvelope.model_validate(command_payload(command_id=str(uuid4()), idempotency_key="reconcile-command-key"))
    asyncio.run(store.submit(cancel_command, authenticated_client_id="test-client"))
    asyncio.run(store.submit(reconcile_command, authenticated_client_id="test-client"))
    for state in ("queued", "dispatching", "accepted", "readback_pending"):
        asyncio.run(store.transition("tenant-1", reconcile_command.command_id, new_state=state, actor_id="worker", reason=state))
    mutation_headers = {**_headers(), "Authorization": "Bearer legacy-command-token", "X-Correlation-ID": "mutation-correlation", "Idempotency-Key": "mutation-idempotency"}
    with _client(test_settings, store) as client:
        cancelled = client.post(f"/v1/operations/{cancel_command.command_id}/cancel", json={"expected_version": 1, "reason": "operator_requested"}, headers=mutation_headers)
        assert cancelled.status_code == 200
        assert cancelled.json()["state"] == "CANCELLED"
        assert cancelled.json()["resource_version"] == 2
        replay = client.post(f"/v1/operations/{cancel_command.command_id}/cancel", json={"expected_version": 1, "reason": "operator_requested"}, headers=mutation_headers)
        assert replay.status_code == 200 and replay.json()["duplicate"] is True
        changed = client.post(f"/v1/operations/{cancel_command.command_id}/cancel", json={"expected_version": 1, "reason": "changed_reason"}, headers=mutation_headers)
        assert changed.status_code == 409
        reconciled = client.post(f"/v1/operations/{reconcile_command.command_id}/reconcile", json={"expected_version": 1, "reason": "ambiguous_provider_result"}, headers={**mutation_headers, "Idempotency-Key": "reconcile-mutation"})
        assert reconciled.status_code == 200
        assert reconciled.json()["state"] == "RECONCILIATION_REQUIRED"
        assert reconciled.json()["resource_version"] == 2
