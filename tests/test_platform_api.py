"""The six /platform/v1 kernel routes on the canonical integration application:
identity matrix, submission semantics, reads, timeline, cancellation, replay,
describe and the error envelope. Tokens are assembled at runtime (never
literal JWTs) and verified by a fake that enforces azp and scope the way the
Keycloak verifier does."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.application import AppProfile, create_app
from app.commands import CommandService, MemoryCommandStore
from app.core.config import Settings
from app.core.runtime import RuntimeContainer
from app.platform.api import ReconciliationResolveRequest
from app.platform.memory import MemoryExecutionBus
from app.platform.runtime import build_platform_runtime, command_policies
from app.replay import MemoryReplayGuard
from app.security import AuthenticationError
from app.storage import MemoryInboxStore

TENANT = "TEST_SYN"


def token(*, azp: str = "middleware-api", scope: str = "platform.command platform.command.read", sub: str = "user-1", tenants: tuple[str, ...] = (TENANT,), roles: tuple[str, ...] = ()) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {"iss": "fake", "aud": "middleware-api", "azp": azp, "sub": sub, "iat": now, "exp": now + 120, "scope": scope, "tenant_ids": list(tenants), "realm_access": {"roles": list(roles)}}
    return jwt.encode(claims, "unit-test-only", algorithm="HS256")


class ClaimsVerifier:
    """Decodes the unit-test token and enforces azp + scope like Keycloak would."""

    async def verify(self, authorization: str, *, expected_client_id: str, required_scope: str) -> dict[str, Any]:
        scheme, _, raw = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw:
            raise AuthenticationError("Authorization must be a Bearer token")
        try:
            claims = jwt.decode(raw, "unit-test-only", algorithms=["HS256"], options={"verify_aud": False})
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("invalid bearer token") from exc
        if claims.get("azp") != expected_client_id:
            raise AuthenticationError("token azp does not match producer")
        if required_scope not in str(claims.get("scope", "")).split():
            raise AuthenticationError("required scope is missing")
        return claims

    async def ready(self) -> bool:
        return True


class Stack:
    def __init__(self, settings: Settings) -> None:
        self.store = MemoryCommandStore()
        commands = CommandService(store=self.store, policies=command_policies(settings))
        self.runtime = RuntimeContainer(settings=settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=ClaimsVerifier(), commands=commands)
        self.runtime.platform = build_platform_runtime(settings, commands=commands, http=None, pool=None, service_id="middleware-integration-api")
        self.bus = MemoryExecutionBus(self.store, self.runtime.platform.dispatch)
        self.app = create_app(settings=settings, runtime=self.runtime, profile=AppProfile.INTEGRATION)

    @property
    def test_syn(self):
        return self.runtime.platform.registry.adapter("test-syn")


@pytest.fixture
def stack(test_settings: Settings) -> Stack:
    return Stack(test_settings)


def command_body(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": "test.syn.execute.v1",
        "command_version": "1.0",
        "target": "test-syn",
        "tenant_id": TENANT,
        "requested_by": "user-1",
        "correlation_id": "corr-" + uuid4().hex[:10],
        "idempotency_key": "idem-" + uuid4().hex,
        "capability": "TEST_SYN_EXECUTE",
        "payload": {"probe": True},
    }
    value.update(updates)
    return value


def headers(body: dict[str, Any], *, bearer: str | None = None, **extra: str) -> dict[str, str]:
    value = {"Authorization": f"Bearer {bearer or token()}", "X-Correlation-ID": body["correlation_id"], "Idempotency-Key": body["idempotency_key"], "Content-Type": "application/json"}
    value.update(extra)
    return value


def submit(client: TestClient, body: dict[str, Any] | None = None, **kwargs: Any):
    body = body or command_body()
    return client.post("/platform/v1/commands", json=body, headers=headers(body, **kwargs)), body


# ----------------------------------------------------------------------------
# identity matrix
# ----------------------------------------------------------------------------
def test_submission_requires_bearer_scope_registered_client_and_tenant(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        body = command_body()
        assert client.post("/platform/v1/commands", json=body).status_code == 401
        no_scope = client.post("/platform/v1/commands", json=body, headers=headers(body, bearer=token(scope="platform.command.read")))
        assert no_scope.status_code == 401
        unknown_client = client.post("/platform/v1/commands", json=body, headers=headers(body, bearer=token(azp="not-a-registered-client")))
        assert unknown_client.status_code == 401
        foreign_tenant = client.post("/platform/v1/commands", json=body, headers=headers(body, bearer=token(tenants=("tenant-b",))))
        assert foreign_tenant.status_code == 403
        wrong_subject = client.post("/platform/v1/commands", json=body, headers=headers(body, bearer=token(sub="someone-else")))
        assert wrong_subject.status_code == 403
        assert wrong_subject.json()["error"]["code"] == "authorization_denied" or wrong_subject.json()["error"]["correlation_id"]


def test_header_and_body_bindings_are_enforced(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        body = command_body()
        mismatch = client.post("/platform/v1/commands", json=body, headers={**headers(body), "Idempotency-Key": "different-key-0001"})
        assert mismatch.status_code == 400
        mismatch = client.post("/platform/v1/commands", json=body, headers={**headers(body), "X-Correlation-ID": "other"})
        assert mismatch.status_code == 400
        missing = client.post("/platform/v1/commands", json=body, headers={"Authorization": headers(body)["Authorization"]})
        assert missing.status_code == 400
        tenant_header = client.post("/platform/v1/commands", json=body, headers={**headers(body), "X-Tenant-ID": "tenant-b"})
        assert tenant_header.status_code == 400
        extra_field = client.post("/platform/v1/commands", json={**body, "role": "admin"}, headers=headers(body))
        assert extra_field.status_code == 400  # canonical control-plane envelope for schema violations


# ----------------------------------------------------------------------------
# submission semantics
# ----------------------------------------------------------------------------
def test_submission_is_accepted_asynchronously_and_replayed_exactly(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        response, body = submit(client)
        assert response.status_code == 202
        assert response.headers["Location"] == f"/platform/v1/operations/{body['command_id']}"
        assert response.headers["X-Correlation-ID"] == body["correlation_id"]
        accepted = response.json()
        assert accepted == {"operation_id": body["command_id"], "command_id": body["command_id"], "state": "RECEIVED", "correlation_id": body["correlation_id"], "duplicate": False}
        assert stack.test_syn.provider_effects == 0
        replay, _ = submit(client, body)
        assert replay.status_code == 200 and replay.json()["duplicate"] is True
        conflict = client.post("/platform/v1/commands", json={**body, "payload": {"probe": "changed"}}, headers=headers(body))
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == "command_conflict"
        assert len(stack.store._outbox) == 1


def test_policy_safety_and_capability_denials_are_403_with_the_error_envelope(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        body = command_body(command_type="crm.contact.create.v1", target="odoo-19", capability="ODOO_WRITE")
        denied = client.post("/platform/v1/commands", json=body, headers=headers(body))
        assert denied.status_code == 403
        envelope = denied.json()["error"]
        assert envelope["code"] == "policy_denied"  # middleware-api has no crm authority
        assert set(envelope) == {"code", "message", "correlation_id", "retryable", "details"}
        assert envelope["correlation_id"] == body["correlation_id"]
        odoo = client.post("/platform/v1/commands", json=body, headers=headers(body, bearer=token(azp="odoo-integration")))
        assert odoo.status_code == 403 and odoo.json()["error"]["code"] == "safety_denied"
        wrong_target = command_body(target="odoo-19")
        assert client.post("/platform/v1/commands", json=wrong_target, headers=headers(wrong_target)).json()["error"]["code"] == "capability_disabled"


# ----------------------------------------------------------------------------
# reads, timeline, cancel, replay, describe
# ----------------------------------------------------------------------------
def test_operation_read_is_tenant_scoped_and_redacted(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        _, body = submit(client)
        read = client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token()}"})
        assert read.status_code == 200
        status = read.json()
        assert status["state"] == "RECEIVED" and status["resource_version"] == 1
        assert "payload" not in status and "readback_evidence" not in status and "last_error" not in status
        assert client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token(tenants=('tenant-b',))}"}).status_code == 404
        assert client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token(scope='platform.command')}"}).status_code == 401
        multi = client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token(tenants=(TENANT, 'tenant-b'))}"})
        assert multi.status_code == 400
        scoped = client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token(tenants=(TENANT, 'tenant-b'))}", "X-Tenant-ID": TENANT})
        assert scoped.status_code == 200
        assert client.get(f"/platform/v1/operations/{uuid4()}", headers={"Authorization": f"Bearer {token()}"}).status_code == 404


def test_timeline_is_append_only_and_monotonic_after_execution(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        _, body = submit(client)
        import asyncio

        asyncio.run(stack.bus.run_once())
        status = client.get(f"/platform/v1/operations/{body['command_id']}", headers={"Authorization": f"Bearer {token()}"}).json()
        assert status["state"] == "COMPLETED"
        assert status["readback_status"] == "MATCHED" and status["readback_evidence_sha256"]
        assert status["provider_operation_id"].startswith("test-syn:")
        timeline = client.get(f"/platform/v1/operations/{body['command_id']}/timeline", headers={"Authorization": f"Bearer {token()}"}).json()
        ids = [item["event_id"] for item in timeline["items"]]
        assert ids == sorted(ids) and len(set(ids)) == len(ids)
        assert [item["new_state"] for item in timeline["items"]] == ["RECEIVED", "QUEUED", "SUBMITTED", "ACCEPTED", "UNKNOWN", "COMPLETED"]
        first = timeline["items"][0]["safe_metadata"]
        assert first["policy_allow"] is True and first["safety_allow"] is True and first["adapter_id"] == "test-syn"
        assert stack.test_syn.provider_effects == 1


def test_cancel_uses_optimistic_concurrency_and_idempotency(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        _, body = submit(client)
        auth = {"Authorization": f"Bearer {token()}", "X-Correlation-ID": "cancel-corr", "Idempotency-Key": "cancel-key-0001"}
        cancelled = client.post(f"/platform/v1/operations/{body['command_id']}/cancel", json={"expected_version": 1, "reason": "operator request"}, headers=auth)
        assert cancelled.status_code == 200 and cancelled.json()["state"] == "CANCELLED" and cancelled.json()["resource_version"] == 2
        assert cancelled.json()["cancelled_at"] is not None
        replay = client.post(f"/platform/v1/operations/{body['command_id']}/cancel", json={"expected_version": 1, "reason": "operator request"}, headers=auth)
        assert replay.status_code == 200
        stale = client.post(f"/platform/v1/operations/{body['command_id']}/cancel", json={"expected_version": 1, "reason": "again"}, headers={**auth, "Idempotency-Key": "cancel-key-0002"})
        assert stale.status_code == 409
        assert client.post(f"/platform/v1/operations/{body['command_id']}/cancel", json={"expected_version": 2, "reason": "x"}, headers={**auth, "Authorization": f"Bearer {token(scope='platform.command.read')}"}).status_code == 401


def test_replay_requires_replay_scope_and_operator_role(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        body = command_body(payload={"fixture": "reject"})
        submit(client, body)
        import asyncio

        asyncio.run(stack.bus.run_once())
        base = {"X-Correlation-ID": "replay-corr", "Idempotency-Key": "replay-key-0001"}
        no_scope = client.post(f"/platform/v1/operations/{body['command_id']}/replay", json={"mode": "REEXECUTE", "expected_version": 1, "reason": "r", "new_idempotency_key": "idem-new-0000001"}, headers={**base, "Authorization": f"Bearer {token()}"})
        assert no_scope.status_code == 401
        no_role = client.post(f"/platform/v1/operations/{body['command_id']}/replay", json={"mode": "REEXECUTE", "expected_version": 1, "reason": "r", "new_idempotency_key": "idem-new-0000001"}, headers={**base, "Authorization": f"Bearer {token(scope='platform.command platform.command.read platform.command.replay')}"})
        assert no_role.status_code == 409 and no_role.json()["error"]["code"] == "replay_not_allowed"
        operator = token(scope="platform.command platform.command.read platform.command.replay", roles=("platform-operator",))
        reexecuted = client.post(f"/platform/v1/operations/{body['command_id']}/replay", json={"mode": "REEXECUTE", "expected_version": 1, "reason": "r", "new_idempotency_key": "idem-new-0000001"}, headers={**base, "Authorization": f"Bearer {operator}"})
        assert reexecuted.status_code == 202
        assert reexecuted.json()["operation_id"] != body["command_id"]
        assert reexecuted.headers["Location"].startswith("/platform/v1/operations/")
        bad_mode = client.post(f"/platform/v1/operations/{body['command_id']}/replay", json={"mode": "AGAIN", "expected_version": 1, "reason": "r"}, headers={**base, "Authorization": f"Bearer {operator}"})
        assert bad_mode.status_code == 400  # canonical control-plane envelope for schema violations


def test_kernel_describe_is_authenticated_and_secret_free(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        assert client.get("/platform/v1/kernel/describe").status_code == 401
        described = client.get("/platform/v1/kernel/describe", headers={"Authorization": f"Bearer {token()}"})
        assert described.status_code == 200
        body = described.json()
        assert body["canonical_service"] == "middleware-integration-api" and body["canonical_port"] == 8095
        assert body["runtime_schema_version"] == 11
        assert body["alembic_schema_head"] == stack.runtime.settings.schema_head
        assert body["provider_effects_enabled"] is False
        assert body["public_contract_digest"]
        assert {row["adapter_id"] for row in body["adapters"]} >= {"test-syn", "odoo-fixture"}
        assert body["safety"]["global_kill_switch"] is False
        text = described.text.lower()
        for forbidden in ("password", "client_secret", "bearer ", "private_key", "hvs."):
            assert forbidden not in text


def test_persistence_outage_is_a_safe_503(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        stack.runtime.platform = None
        response, _ = submit(client)
        assert response.status_code == 503
        assert response.json()["error"]["retryable"] is True


def test_chaos_a_persistence_failure_before_acceptance_is_never_a_202(stack: Stack) -> None:
    """Chaos A: the ledger fails before acceptance -> safe 503, no operation, no intent."""
    from app.storage import StorageError

    async def failing_submit(*_args, **_kwargs):
        raise StorageError("database unavailable")

    stack.runtime.commands.store.submit = failing_submit  # type: ignore[method-assign]
    with TestClient(stack.app) as client:
        response, body = submit(client)
        assert response.status_code == 503
        assert response.json()["error"]["retryable"] is True
        assert stack.store._outbox == [] and stack.store._commands == {}


def test_operational_catalog_surfaces_are_authenticated_and_secret_free(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        assert client.get("/platform/v1/adapters").status_code == 401
        auth = {"Authorization": f"Bearer {token()}"}
        adapters = client.get("/platform/v1/adapters", headers=auth)
        assert adapters.status_code == 200
        rows = adapters.json()["items"]
        assert {row["adapter_id"] for row in rows} >= {"test-syn", "odoo-fixture"}
        assert client.get("/platform/v1/adapters/test-syn", headers=auth).status_code == 200

        connectors = client.get("/platform/v1/connectors", headers=auth)
        assert connectors.status_code == 200
        connector_rows = connectors.json()["items"]
        assert {row["connector_id"] for row in connector_rows} >= {"test-syn", "odoo-19"}
        assert client.get("/platform/v1/connectors/test-syn", headers=auth).status_code == 200

        rendered = adapters.text.lower() + connectors.text.lower()
        for forbidden in ("client_secret", "private_key", "password", "bearer ", "hvs."):
            assert forbidden not in rendered


def test_dead_letter_and_reconciliation_surfaces_are_tenant_scoped(stack: Stack) -> None:
    with TestClient(stack.app) as client:
        auth = {"Authorization": f"Bearer {token()}"}
        assert client.get("/platform/v1/dead-letters", headers=auth).json() == {"items": []}
        assert client.get("/platform/v1/reconciliation", headers=auth).json() == {"items": []}
        assert client.get("/platform/v1/dead-letters", headers={"Authorization": f"Bearer {token(tenants=(TENANT, 'tenant-b'))}"}).status_code == 400
        assert client.get("/platform/v1/reconciliation", headers={"Authorization": f"Bearer {token(scope='platform.command')}"}).status_code == 401
        assert client.get(f"/platform/v1/dead-letters/{uuid4()}", headers=auth).status_code == 404
        assert client.get(f"/platform/v1/reconciliation/{uuid4()}", headers=auth).status_code == 404


def test_reconciliation_resolution_is_idempotent_and_content_bound(stack: Stack) -> None:
    import asyncio
    from uuid import UUID

    with TestClient(stack.app) as client:
        _, body = submit(client)
        command_id = UUID(body["command_id"])
        for state in ("queued", "dispatching", "reconciliation_required"):
            asyncio.run(
                stack.store.transition(
                    TENANT,
                    command_id,
                    new_state=state,
                    actor_id="test",
                    reason="force bounded operator reconciliation",
                )
            )
        current = asyncio.run(stack.store.get(TENANT, command_id))
        operator = token(
            scope="platform.command platform.command.read platform.command.replay",
            roles=("platform-operator",),
        )
        auth = {
            "Authorization": f"Bearer {operator}",
            "X-Correlation-ID": "resolve-corr",
            "Idempotency-Key": "resolve-idem-0001",
        }
        payload = {
            "expected_version": current.resource_version,
            "matched": True,
            "reason": "provider readback matched",
            "provider_operation_id": "provider-op-1",
            "evidence": {"task_id": 9, "profile_id": 5, "listed": True},
        }
        first = client.post(
            f"/platform/v1/reconciliation/{command_id}/resolve",
            json=payload,
            headers=auth,
        )
        assert first.status_code == 200, first.text
        assert first.json()["state"] == "COMPLETED"
        first_version = first.json()["resource_version"]

        replay = client.post(
            f"/platform/v1/reconciliation/{command_id}/resolve",
            json=payload,
            headers=auth,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["state"] == "COMPLETED"
        assert replay.json()["resource_version"] == first_version

        conflict = client.post(
            f"/platform/v1/reconciliation/{command_id}/resolve",
            json={**payload, "evidence": {**payload["evidence"], "listed": False}},
            headers=auth,
        )
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == "command_conflict"


def test_reconciliation_resolution_rejects_oversized_evidence() -> None:
    with pytest.raises(ValidationError, match="16 KiB"):
        ReconciliationResolveRequest(
            expected_version=1,
            matched=True,
            reason="provider readback matched",
            evidence={"blob": "x" * 17_000},
        )
