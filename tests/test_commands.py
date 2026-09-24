from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.commands import (
    CommandCapabilityDisabled,
    CommandConflict,
    CommandEnvelope,
    CommandPolicy,
    CommandPolicyRegistry,
    CommandService,
    CommandState,
    MemoryCommandStore,
    command_digest,
    decode_readback_evidence,
    verify_readback_evidence_digest,
)
from app.main import create_app
from app.provider_canary import provider_evidence_digest
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


def command_payload(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": "crm.contact.create.v1",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "user-123",
        "correlation_id": "correlation-123",
        "idempotency_key": "idempotency-123",  # gitleaks:allow test fixture
        "capability": "ODOO_WRITE",
        "payload": {"contact_id": "contact-1"},
    }
    value.update(updates)
    return value


def enabled_policy() -> CommandPolicyRegistry:
    return CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="crm.",
                target="odoo-19",
                capability="ODOO_WRITE",
                readback_required=True,
            ),
        ),
        {"ODOO_WRITE": True},
    )


@pytest.mark.asyncio
async def test_memory_command_ledger_is_idempotent_and_state_guarded() -> None:
    store = MemoryCommandStore()
    command = CommandEnvelope.model_validate(command_payload())

    first = await store.submit(command, authenticated_client_id="test-client")
    duplicate = await store.submit(command, authenticated_client_id="test-client")
    assert first.state == "persisted"
    assert duplicate.duplicate is True

    conflicting = command.model_copy(update={"payload": {"contact_id": "changed"}})
    with pytest.raises(CommandConflict):
        await store.submit(conflicting, authenticated_client_id="test-client")

    with pytest.raises(CommandConflict):
        await store.submit(command, authenticated_client_id="another-client")

    queued = await store.transition(
        command.tenant_id,
        command.command_id,
        new_state="queued",
        actor_id="temporal:test",
        reason="workflow accepted intent",
    )
    assert queued.state == "queued"
    with pytest.raises(CommandConflict):
        await store.transition(
            command.tenant_id,
            command.command_id,
            new_state="completed",
            actor_id="temporal:test",
            reason="completion cannot skip read-back",
        )


@pytest.mark.asyncio
async def test_memory_command_ledger_preserves_legacy_retry_idempotency() -> None:
    store = MemoryCommandStore()
    command = CommandEnvelope.model_validate(command_payload())
    first = await store.submit(command, authenticated_client_id="test-client")
    legacy_entry = (command_digest(command), first)
    store._commands[(command.tenant_id, command.command_id)] = legacy_entry
    store._idempotency[(command.tenant_id, command.idempotency_key)] = legacy_entry

    duplicate = await store.submit(
        command,
        authenticated_client_id="post-upgrade-client",
    )

    assert duplicate.duplicate is True


@pytest.mark.asyncio
async def test_memory_command_ledger_persists_redacted_readback_evidence() -> None:
    store = MemoryCommandStore()
    command = CommandEnvelope.model_validate(command_payload())
    await store.submit(command, authenticated_client_id="test-client")
    with pytest.raises(CommandConflict, match="only on completion"):
        await store.transition(
            command.tenant_id,
            command.command_id,
            new_state="queued",
            actor_id="temporal:test",
            reason="invalid early proof",
            readback_evidence={"status": "delivered"},
        )
    states: tuple[CommandState, ...] = (
        "queued",
        "dispatching",
        "accepted",
        "readback_pending",
    )
    for state in states:
        await store.transition(
            command.tenant_id,
            command.command_id,
            new_state=state,
            actor_id="temporal:test",
            reason=f"transition to {state}",
        )
    observation = {"provider_reference": "provider-operation-1", "status": "ringing"}
    awaiting = await store.transition(
        command.tenant_id,
        command.command_id,
        new_state="reconciliation_required",
        actor_id="temporal:test",
        reason="validated provider observation remains nonterminal",
        provider_operation_id="provider-operation-1",
        readback_evidence=observation,
    )
    assert awaiting.readback_evidence == observation
    assert awaiting.readback_evidence_sha256 == provider_evidence_digest(observation)
    store = MemoryCommandStore()
    await store.submit(command, authenticated_client_id="test-client")
    for state in states:
        await store.transition(
            command.tenant_id, command.command_id, new_state=state,
            actor_id="temporal:test", reason=f"transition to {state}",
        )
    evidence = {"provider_reference": "provider-operation-1", "status": "matched"}
    completed = await store.transition(
        command.tenant_id,
        command.command_id,
        new_state="completed",
        actor_id="temporal:test",
        reason="provider read-back matched",
        provider_operation_id="provider-operation-1",
        readback_evidence=evidence,
    )
    assert completed.readback_evidence == evidence
    assert completed.readback_evidence_sha256 == provider_evidence_digest(evidence)
    fetched = await store.get(command.tenant_id, command.command_id)
    assert fetched.readback_evidence_sha256 == completed.readback_evidence_sha256


def test_postgres_jsonb_readback_text_is_decoded_before_api_serialization() -> None:
    evidence = {"provider_reference": "provider-operation-1", "status": "matched"}
    assert decode_readback_evidence(json.dumps(evidence)) == evidence
    digest = provider_evidence_digest(evidence)
    assert verify_readback_evidence_digest(json.dumps(evidence), digest) == (
        evidence,
        digest,
    )
    with pytest.raises(RuntimeError, match="invalid JSON"):
        decode_readback_evidence("not-json")
    with pytest.raises(RuntimeError, match="JSON object"):
        decode_readback_evidence("[]")
    with pytest.raises(RuntimeError, match="does not match"):
        verify_readback_evidence_digest(evidence, "sha256:" + "0" * 64)


@pytest.mark.asyncio
async def test_command_policy_fails_closed() -> None:
    command = CommandEnvelope.model_validate(command_payload())
    service = CommandService(MemoryCommandStore(), enabled_policy())

    with pytest.raises(CommandCapabilityDisabled):
        await service.submit(
            command,
            authenticated_subject="different-user",
            authenticated_client_id="test-client",
        )
    with pytest.raises(CommandCapabilityDisabled):
        await CommandService(
            MemoryCommandStore(),
            CommandPolicyRegistry(enabled_policy().policies, {"ODOO_WRITE": False}),
        ).submit(
            command,
            authenticated_subject="user-123",
            authenticated_client_id="test-client",
        )
    with pytest.raises(CommandCapabilityDisabled):
        await service.submit(
            command.model_copy(update={"target": "another-adapter"}),
            authenticated_subject="user-123",
            authenticated_client_id="test-client",
        )


class CommandTokenVerifier:
    _TOKENS = {
        "middleware.request.forward": "legacy-command-token",
        "middleware.status.read": "legacy-status-token",
    }

    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        assert expected_client_id == "kong-gateway"
        if authorization != f"Bearer {self._TOKENS[required_scope]}":
            from app.security import AuthenticationError

            raise AuthenticationError("invalid command token")
        return {
            "azp": "kong-gateway",
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "tenant-1",
            "sub": "user-123",
        }

    async def ready(self) -> bool:
        return True


def test_command_api_accepts_duplicate_and_serves_tenant_scoped_status(
    test_settings,
) -> None:
    command_store = MemoryCommandStore()
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=CommandTokenVerifier(),
        commands=CommandService(command_store, enabled_policy()),
    )
    body = command_payload()
    headers = {
        "Authorization": "Bearer legacy-command-token",
        "X-Tenant-ID": body["tenant_id"],
        "X-Correlation-ID": body["correlation_id"],
        "Idempotency-Key": body["idempotency_key"],
    }
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        first = client.post("/v1/commands", json=body, headers=headers)
        assert first.status_code == 202, first.text
        assert first.headers["location"] == f"/v1/operations/{body['command_id']}"
        assert first.json()["state"] == "RECEIVED"

        duplicate = client.post("/v1/commands", json=body, headers=headers)
        assert duplicate.status_code == 200, duplicate.text
        assert duplicate.json()["duplicate"] is True
        assert duplicate.json()["state"] == "RECEIVED"

        status = client.get(
            f"/v1/operations/{body['command_id']}",
            headers={
                "Authorization": "Bearer legacy-status-token",
                "X-Tenant-ID": "tenant-1",
            },
        )
        assert status.status_code == 200, status.text
        assert status.json()["state"] == "RECEIVED"

        wrong_tenant = client.get(
            f"/v1/operations/{body['command_id']}",
            headers={
                "Authorization": "Bearer legacy-status-token",
                "X-Tenant-ID": "tenant-2",
            },
        )
        assert wrong_tenant.status_code == 403

        invalid = client.post(
            "/v1/commands",
            json={**body, "unexpected": True},
            headers=headers,
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == "invalid_request"


@pytest.mark.parametrize(
    ("name", "second"),
    (
        ("Authorization", "Bearer duplicate-token"),
        ("X-Tenant-ID", "tenant-2"),
        ("X-Correlation-ID", "correlation-duplicate"),
        ("Idempotency-Key", "idempotency-duplicate"),
    ),
)
def test_command_api_rejects_duplicate_security_headers(
    test_settings,
    name: str,
    second: str,
) -> None:
    command_store = MemoryCommandStore()
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=CommandTokenVerifier(),
        commands=CommandService(command_store, enabled_policy()),
    )
    body = command_payload()
    request_headers = [
        ("Authorization", "Bearer legacy-command-token"),
        ("X-Tenant-ID", body["tenant_id"]),
        ("X-Correlation-ID", body["correlation_id"]),
        ("Idempotency-Key", body["idempotency_key"]),
        (name, second),
    ]
    app = create_app(settings=test_settings, runtime=runtime)

    with TestClient(app) as client:
        response = client.post("/v1/commands", json=body, headers=request_headers)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert not command_store._commands


def test_command_api_authentication_precedes_storage_disclosure(test_settings) -> None:
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=CommandTokenVerifier(),
    )
    body = command_payload()
    request_headers = {
        "Authorization": "Bearer invalid",
        "X-Tenant-ID": body["tenant_id"],
        "X-Correlation-ID": body["correlation_id"],
        "Idempotency-Key": body["idempotency_key"],
    }
    app = create_app(settings=test_settings, runtime=runtime)

    with TestClient(app) as client:
        unauthorized = client.post(
            "/v1/commands", json=body, headers=request_headers,
        )
        unavailable = client.post(
            "/v1/commands",
            json=body,
            headers={
                **request_headers,
                "Authorization": "Bearer legacy-command-token",
            },
        )

    assert unauthorized.status_code == 401
    assert unavailable.status_code == 503
