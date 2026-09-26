"""The 21-case security negative matrix of the V3 kernel — every case fails
closed on the canonical integration application with the REAL Keycloak JWT
verifier (RS256 key pair, JWKS client patched to the test key; issuer,
audience, algorithm, lifetime and required claims are verified for real).

no token; wrong issuer; wrong audience; wrong azp; missing scope; expired
token; forged identity headers; tenant mismatch; cross-tenant operation;
unknown capability; disabled capability; production capability in TEST_SYN;
malformed payload; oversized payload; missing idempotency; idempotency
collision; unauthorized cancel; unauthorized replay; non-replayable state;
terminal cancel; provider-uncertainty replay. Plus: alg=none / HS256
confusion is rejected.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.application import AppProfile, create_app
from app.commands import CommandService, MemoryCommandStore
from app.core.config import Settings
from app.core.runtime import RuntimeContainer
from app.platform.memory import MemoryExecutionBus
from app.platform.runtime import build_platform_runtime, command_policies
from app.replay import MemoryReplayGuard
from app.security import KeycloakJwtVerifier
from app.storage import MemoryInboxStore

TENANT = "TEST_SYN"
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Keys:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def get_signing_key_from_jwt(self, _token: str) -> SimpleNamespace:
        return SimpleNamespace(key=PRIVATE.public_key())

    def fetch_data(self) -> dict[str, Any]:
        return {"keys": [{"kid": "test"}]}


@pytest.fixture
def stack(test_settings: Settings, monkeypatch):
    import app.security as security_module

    monkeypatch.setattr(security_module, "PyJWKClient", Keys)
    store = MemoryCommandStore()
    commands = CommandService(store=store, policies=command_policies(test_settings))
    runtime = RuntimeContainer(settings=test_settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=KeycloakJwtVerifier(test_settings), commands=commands)
    runtime.platform = build_platform_runtime(test_settings, commands=commands, http=None, pool=None, service_id="middleware-integration-api")
    app = create_app(settings=test_settings, runtime=runtime, profile=AppProfile.INTEGRATION)
    return SimpleNamespace(app=app, runtime=runtime, store=store, settings=test_settings, bus=MemoryExecutionBus(store, runtime.platform.dispatch))


def token(settings: Settings, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "azp": "middleware-api",
        "sub": "user-1",
        "iat": now,
        "exp": now + 120,
        "jti": str(uuid4()),
        "scope": "platform.command platform.command.read",
        "tenant_ids": [TENANT],
        "realm_access": {"roles": []},
    }
    key = overrides.pop("_key", PRIVATE)
    algorithm = overrides.pop("_alg", "RS256")
    claims.update(overrides)
    if algorithm == "none":
        return jwt.encode(claims, key=None, algorithm="none")  # type: ignore[arg-type]
    if algorithm == "HS256":
        return jwt.encode(claims, "shared-secret-key-material-32-bytes-minimum", algorithm="HS256")
    return jwt.encode(claims, key, algorithm=algorithm)


def body(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "command_id": str(uuid4()),
        "command_type": "test.syn.execute.v1",
        "command_version": "1.0",
        "tenant_id": TENANT,
        "requested_by": "user-1",
        "correlation_id": "corr-" + uuid4().hex[:8],
        "idempotency_key": "idem-" + uuid4().hex,
        "payload": {"probe": True},
    }
    value.update(updates)
    return value


def headers(request_body: dict[str, Any], bearer: str | None, **extra: str) -> dict[str, str]:
    value = {
        "X-Command-ID": request_body["command_id"],
        "X-Correlation-ID": request_body["correlation_id"],
        "Idempotency-Key": request_body["idempotency_key"],
        "Content-Type": "application/json",
    }
    if bearer is not None:
        value["Authorization"] = f"Bearer {bearer}"
    value.update(extra)
    return value


def submit(client: TestClient, settings: Settings, request_body: dict[str, Any] | None = None, bearer: str | None = "default", **extra: str):
    request_body = request_body or body()
    resolved = token(settings) if bearer == "default" else bearer
    return client.post("/platform/v1/commands", json=request_body, headers=headers(request_body, resolved, **extra))


def test_real_verifier_accepts_a_valid_token(stack) -> None:
    with TestClient(stack.app) as client:
        response = submit(client, stack.settings)
        assert response.status_code == 202, response.text


@pytest.mark.parametrize(
    "case, bearer_overrides, status",
    [
        ("no_token", None, 401),
        ("wrong_issuer", {"iss": "https://evil.invalid/realms/codestra"}, 401),
        ("wrong_audience", {"aud": "someone-else"}, 401),
        ("wrong_azp", {"azp": "kong-gateway"}, 403),
        ("unregistered_azp", {"azp": "not-a-caller"}, 401),
        ("missing_scope", {"scope": "platform.command.read"}, 403),
        ("expired_token", {"exp": int(time.time()) - 10, "iat": int(time.time()) - 130}, 401),
        ("lifetime_over_policy", {"iat": int(time.time()) - 10, "exp": int(time.time()) + 1000}, 403),
        ("alg_none", {"_alg": "none"}, 401),
        ("hs256_confusion", {"_alg": "HS256"}, 401),
        ("foreign_key", {"_key": OTHER_PRIVATE}, 401),
        ("tenant_mismatch", {"tenant_ids": ["tenant-b"]}, 403),
        ("wildcard_tenant", {"tenant_ids": ["*"]}, 403),
        ("wrong_subject", {"sub": "impostor"}, 403),
    ],
)
def test_identity_negative_matrix(stack, case: str, bearer_overrides: dict[str, Any] | None, status: int) -> None:
    with TestClient(stack.app) as client:
        bearer = None if bearer_overrides is None else token(stack.settings, **bearer_overrides)
        response = submit(client, stack.settings, bearer=bearer)
        assert response.status_code == status, (case, response.text)
        assert stack.store._outbox == []


def test_forged_identity_headers_are_ignored(stack) -> None:
    with TestClient(stack.app) as client:
        request_body = body(tenant_id="tenant-b")
        response = submit(client, stack.settings, request_body, **{"X-Tenant-ID": "tenant-b", "X-Forwarded-User": "admin", "X-Auth-Request-User": "admin", "X-Codestra-Tenant-Id": "tenant-b"})
        assert response.status_code == 403  # the token grants TEST_SYN only
        assert stack.store._outbox == []


@pytest.mark.parametrize(
    "case, request_body, status, code",
    [
        ("unknown_capability", body(command_type="nothing.known.v1"), 403, "capability_disabled"),
        ("disabled_capability", body(command_type="crm.contact.create.v1"), 403, "policy_denied"),
        ("production_capability_in_test_syn", body(command_type="telephony.call.originate.v1"), 403, "policy_denied"),
        ("mismatched_target", body(target="odoo-19"), 403, "capability_disabled"),
        ("mismatched_capability", body(capability="ODOO_WRITE"), 403, "capability_disabled"),
        ("malformed_payload", {**body(), "payload": "not-an-object"}, 400, "invalid_request"),
        ("extra_field", {**body(), "roles": ["admin"]}, 400, "invalid_request"),
        ("oversized_payload", body(payload={"blob": "x" * 262_200}), 400, "invalid_request"),
    ],
)
def test_request_negative_matrix(stack, case: str, request_body: dict[str, Any], status: int, code: str) -> None:
    with TestClient(stack.app) as client:
        response = submit(client, stack.settings, request_body)
        assert response.status_code == status, (case, response.text)
        assert response.json()["error"]["code"] == code, case
        assert stack.store._outbox == []


def test_missing_idempotency_and_collision(stack) -> None:
    with TestClient(stack.app) as client:
        request_body = body()
        missing = client.post("/platform/v1/commands", json=request_body, headers={"Authorization": f"Bearer {token(stack.settings)}", "X-Correlation-ID": request_body["correlation_id"]})
        assert missing.status_code == 400
        assert submit(client, stack.settings, request_body).status_code == 202
        collision = submit(client, stack.settings, {**request_body, "payload": {"probe": "different"}})
        assert collision.status_code == 409 and collision.json()["error"]["code"] == "command_conflict"
        assert len(stack.store._outbox) == 1


def test_cancel_and_replay_authorization_and_state_negatives(stack) -> None:
    with TestClient(stack.app) as client:
        request_body = body()
        assert submit(client, stack.settings, request_body).status_code == 202
        operation = request_body["command_id"]
        mutation = {
            "X-Command-ID": operation,
            "X-Correlation-ID": request_body["correlation_id"],
            "Idempotency-Key": "mutation-000001",
        }
        # unauthorized cancel: read-only scope
        denied = client.post(f"/platform/v1/operations/{operation}/cancel", json={"expected_version": 1, "reason": "x"}, headers={**mutation, "Authorization": f"Bearer {token(stack.settings, scope='platform.command.read')}"})
        assert denied.status_code == 403  # scope missing -> authorization_denied
        # cross-tenant cancel is non-disclosing
        foreign = client.post(f"/platform/v1/operations/{operation}/cancel", json={"expected_version": 1, "reason": "x"}, headers={**mutation, "Authorization": f"Bearer {token(stack.settings, tenant_ids=['tenant-b'])}"})
        assert foreign.status_code == 404
        # unauthorized replay: no replay scope / no operator role
        no_scope = client.post(f"/platform/v1/operations/{operation}/replay", json={"mode": "REPROCESS", "expected_version": 1, "reason": "x"}, headers={**mutation, "Authorization": f"Bearer {token(stack.settings)}"})
        assert no_scope.status_code == 403  # replay scope missing -> authorization_denied
        replay_scope = token(stack.settings, scope="platform.command platform.command.read platform.command.replay")
        no_role = client.post(f"/platform/v1/operations/{operation}/replay", json={"mode": "REPROCESS", "expected_version": 1, "reason": "x"}, headers={**mutation, "Authorization": f"Bearer {replay_scope}"})
        assert no_role.status_code == 409 and no_role.json()["error"]["code"] == "replay_not_allowed"
        operator = token(stack.settings, scope="platform.command platform.command.read platform.command.replay", realm_access={"roles": ["platform-operator"]})
        # non-replayable state: REEXECUTE of a live (persisted) operation
        live = client.post(f"/platform/v1/operations/{operation}/replay", json={"mode": "REEXECUTE", "expected_version": 1, "reason": "x", "new_idempotency_key": "idem-new-000000001"}, headers={**mutation, "Authorization": f"Bearer {operator}"})
        assert live.status_code == 409
        # terminal cancel
        cancelled = client.post(f"/platform/v1/operations/{operation}/cancel", json={"expected_version": 1, "reason": "operator"}, headers={**mutation, "Authorization": f"Bearer {token(stack.settings)}"})
        assert cancelled.status_code == 200 and cancelled.json()["state"] == "CANCELLED"
        again = client.post(f"/platform/v1/operations/{operation}/cancel", json={"expected_version": 2, "reason": "again"}, headers={**mutation, "Idempotency-Key": "mutation-000002", "Authorization": f"Bearer {token(stack.settings)}"})
        assert again.status_code == 409
        # provider uncertainty: REEXECUTE must reconcile first
        uncertain = body(payload={"fixture": "unknown"})
        assert submit(client, stack.settings, uncertain).status_code == 202
        asyncio.run(stack.bus.run_once())
        status = client.get(f"/platform/v1/operations/{uncertain['command_id']}", headers={"Authorization": f"Bearer {token(stack.settings)}"}).json()
        assert status["state"] == "RECONCILIATION_REQUIRED"
        uncertain_mutation = {
            "X-Command-ID": uncertain["command_id"],
            "X-Correlation-ID": uncertain["correlation_id"],
            "Idempotency-Key": "mutation-000003",
        }
        blind = client.post(f"/platform/v1/operations/{uncertain['command_id']}/replay", json={"mode": "REEXECUTE", "expected_version": 1, "reason": "x", "new_idempotency_key": "idem-new-000000002"}, headers={**uncertain_mutation, "Authorization": f"Bearer {operator}"})
        assert blind.status_code == 409 and "terminal" in blind.json()["error"]["message"]
        reprocess = client.post(f"/platform/v1/operations/{uncertain['command_id']}/replay", json={"mode": "REPROCESS", "expected_version": 1, "reason": "x"}, headers={**uncertain_mutation, "Idempotency-Key": "mutation-000004", "Authorization": f"Bearer {operator}"})
        assert reprocess.status_code == 202
        assert stack.runtime.platform.registry.adapter("test-syn").provider_effects == 1
