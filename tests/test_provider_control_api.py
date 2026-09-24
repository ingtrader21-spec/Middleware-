from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.commands import CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.main import create_app
from app.provider_control_api import (
    PROVIDER_CONTROL_SPECS,
    is_forbidden_provider_key,
    normalize_payload_key,
)
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError
from app.storage import MemoryInboxStore
from middleware.connector_sdk.standards import is_secret_key_name


class ProviderControlTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        expected = f"Bearer {expected_client_id}:{required_scope}"
        if authorization != expected:
            raise AuthenticationError("invalid provider-control token")
        return {
            "iss": "https://auth.codestra.co/realms/codestra",
            "azp": expected_client_id,
            "aud": "middleware-api",
            "scope": required_scope,
            "tenant_id": "tenant-1",
            "sub": f"service-account-{expected_client_id}",
            "iat": 1_788_000_000,
            "exp": 1_788_000_300,
        }

    async def ready(self) -> bool:
        return True


def _runtime(test_settings, *, capabilities_enabled: bool) -> Runtime:
    loaded = CommandPolicyRegistry.load()
    capabilities = {
        name: capabilities_enabled for name in loaded.capabilities
    }
    commands = CommandService(
        MemoryCommandStore(),
        CommandPolicyRegistry(loaded.policies, capabilities),
    )
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=ProviderControlTokenVerifier(),
        commands=commands,
    )


def _headers(spec, *, idempotency_key: str = "provider-control-idempotency"):
    return {
        "Authorization": (
            f"Bearer {spec.caller_client_id}:{spec.required_scope}"
        ),
        "X-Tenant-ID": "tenant-1",
        "X-Correlation-ID": "provider-control-correlation",
        "Idempotency-Key": idempotency_key,
    }


def test_provider_policy_external_routes_are_registered_exactly(test_settings) -> None:
    app = create_app(
        settings=test_settings,
        runtime=_runtime(test_settings, capabilities_enabled=False),
    )
    policy = json.loads(
        open("config/provider-operation-policy.json", encoding="utf-8").read()
    )
    expected = {
        operation["route"]
        for operation in policy["operations"]
        if operation["externalEffect"] is True
    }
    assert expected == {spec.route for spec in PROVIDER_CONTROL_SPECS}
    assert expected <= set(app.openapi()["paths"])
    for route in expected:
        operation = app.openapi()["paths"][route]["post"]
        assert "provider-control" in operation["tags"]
        assert "durable-control" in operation["tags"]
        for status in ("200", "202"):
            response = operation["responses"][status]
            assert response["content"]["application/json"]["schema"] == {
                "$ref": "#/components/schemas/ProviderControlResponse"
            }


def test_exact_provider_control_routes_reuse_the_durable_operation_engine(
    test_settings,
) -> None:
    runtime = _runtime(test_settings, capabilities_enabled=True)
    app = create_app(settings=test_settings, runtime=runtime)

    with TestClient(app) as client:
        for index, spec in enumerate(PROVIDER_CONTROL_SPECS, start=1):
            operation_id = uuid4()
            headers = _headers(
                spec,
                idempotency_key=f"provider-control-idempotency-{index}",
            )
            body = {
                "operation_id": str(operation_id),
                "payload": {"resource_reference": f"reference-{index}"},
            }
            first = client.post(spec.route, headers=headers, json=body)
            assert first.status_code == 202, first.text
            assert first.headers["location"] == f"/v1/operations/{operation_id}"
            response = first.json()
            assert response["command_id"] == str(operation_id)
            assert response["state"] == "RECEIVED"
            assert response["control_operation"] == spec.operation_id
            assert response["external_effect_dispatched"] is False
            assert "payload" not in response
            assert "persisted" not in json.dumps(response).lower()

            stored = asyncio.run(
                runtime.commands.get("tenant-1", operation_id)  # type: ignore[union-attr]
            )
            assert stored.command_type == spec.command_type
            assert stored.target == spec.target
            assert stored.capability == spec.capability
            assert stored.requested_by == (
                f"service-account-{spec.caller_client_id}"
            )
            events = asyncio.run(
                runtime.commands.list_events(  # type: ignore[union-attr]
                    "tenant-1",
                    operation_id,
                    limit=10,
                )
            )
            assert (
                events[0].safe_metadata["authenticated_client_id"]
                == spec.caller_client_id
            )

            replay = client.post(spec.route, headers=headers, json=body)
            assert replay.status_code == 200, replay.text
            replay_body = replay.json()
            assert replay_body["duplicate"] is True
            assert replay_body["state"] == "RECEIVED"
            assert replay_body["external_effect_dispatched"] is False

            changed = client.post(
                spec.route,
                headers=headers,
                json={
                    **body,
                    "payload": {"resource_reference": "changed"},
                },
            )
            assert changed.status_code == 409, changed.text


def test_provider_control_routes_require_exact_caller_scope_and_tenant(
    test_settings,
) -> None:
    spec = PROVIDER_CONTROL_SPECS[0]
    app = create_app(
        settings=test_settings,
        runtime=_runtime(test_settings, capabilities_enabled=True),
    )
    body = {"operation_id": str(uuid4()), "payload": {"reference": "safe"}}

    with TestClient(app) as client:
        wrong_scope = {
            **_headers(spec),
            "Authorization": f"Bearer {spec.caller_client_id}:wrong.scope",
        }
        assert client.post(spec.route, headers=wrong_scope, json=body).status_code == 401

        wrong_client = {
            **_headers(spec),
            "Authorization": f"Bearer wrong-client:{spec.required_scope}",
        }
        assert client.post(spec.route, headers=wrong_client, json=body).status_code == 401

        wrong_tenant = {**_headers(spec), "X-Tenant-ID": "tenant-2"}
        assert client.post(spec.route, headers=wrong_tenant, json=body).status_code == 403


@pytest.mark.parametrize(
    ("name", "second"),
    (
        ("Authorization", "Bearer duplicate:token"),
        ("X-Tenant-ID", "tenant-2"),
        ("X-Correlation-ID", "provider-control-correlation-2"),
        ("Idempotency-Key", "provider-control-idempotency-2"),
    ),
)
def test_provider_control_routes_reject_duplicate_security_headers(
    test_settings,
    name: str,
    second: str,
) -> None:
    spec = PROVIDER_CONTROL_SPECS[0]
    runtime = _runtime(test_settings, capabilities_enabled=True)
    app = create_app(settings=test_settings, runtime=runtime)
    headers = list(_headers(spec).items()) + [(name, second)]
    body = {"operation_id": str(uuid4()), "payload": {"reference": "safe"}}

    with TestClient(app) as client:
        response = client.post(spec.route, headers=headers, json=body)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert not runtime.commands.store._commands  # type: ignore[union-attr]


def test_provider_control_authentication_precedes_storage_disclosure(
    test_settings,
) -> None:
    spec = PROVIDER_CONTROL_SPECS[0]
    runtime = _runtime(test_settings, capabilities_enabled=True)
    runtime.commands = None
    app = create_app(settings=test_settings, runtime=runtime)
    body = {"operation_id": str(uuid4()), "payload": {"reference": "safe"}}

    with TestClient(app) as client:
        unauthorized = client.post(
            spec.route,
            headers={**_headers(spec), "Authorization": "Bearer invalid"},
            json=body,
        )
        unavailable = client.post(spec.route, headers=_headers(spec), json=body)

    assert unauthorized.status_code == 401
    assert unavailable.status_code == 503


def test_provider_control_routes_fail_closed_when_capability_is_disabled(
    test_settings,
) -> None:
    spec = PROVIDER_CONTROL_SPECS[0]
    app = create_app(
        settings=test_settings,
        runtime=_runtime(test_settings, capabilities_enabled=False),
    )
    with TestClient(app) as client:
        response = client.post(
            spec.route,
            headers=_headers(spec),
            json={"operation_id": str(uuid4()), "payload": {"reference": "safe"}},
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "capability_disabled"


@pytest.mark.parametrize(
    "forbidden_key",
    (
        "provider_token",
        "accessToken",
        "ACCESSTOKEN",
        "clientSecret",
        "CLIENTSECRET",
        "api-key",
        "APIKEY",
        "refresh token",
        "privateKey",
        "secretValue",
        "Authorization",
        "customer_password",
        "vendor.api.key",
    ),
)
def test_provider_control_payload_cannot_carry_provider_credentials(
    test_settings,
    forbidden_key: str,
) -> None:
    spec = PROVIDER_CONTROL_SPECS[0]
    app = create_app(
        settings=test_settings,
        runtime=_runtime(test_settings, capabilities_enabled=True),
    )
    with TestClient(app) as client:
        response = client.post(
            spec.route,
            headers=_headers(
                spec,
                idempotency_key=(
                    "credential-rejection-"
                    + normalize_payload_key(forbidden_key)
                ),
            ),
            json={
                "operation_id": str(uuid4()),
                "payload": {
                    "nested": [
                        {"deeper": {forbidden_key: "must-not-enter-ledger"}}
                    ]
                },
            },
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


@pytest.mark.parametrize(
    "safe_key",
    (
        "token_budget",
        "max_tokens",
        "token_reference",
        "api_key_reference",
        "resource_reference",
    ),
)
def test_ai_provider_control_allows_nonsecret_governance_and_references(
    test_settings,
    safe_key: str,
) -> None:
    spec = next(
        item for item in PROVIDER_CONTROL_SPECS
        if item.operation_id == "ai.inference.request"
    )
    app = create_app(
        settings=test_settings,
        runtime=_runtime(test_settings, capabilities_enabled=True),
    )
    value: object = 2_000 if safe_key in {"token_budget", "max_tokens"} else "ref-1"
    with TestClient(app) as client:
        response = client.post(
            spec.route,
            headers=_headers(
                spec,
                idempotency_key=f"safe-governance-{safe_key.replace('_', '-')}",
            ),
            json={
                "operation_id": str(uuid4()),
                "payload": {
                    "resource_reference": "ai-request-1",
                    "task_type": "document.summary",
                    "schema_version": "1.0",
                    safe_key: value,
                },
            },
        )
    assert response.status_code == 202, response.text
    assert response.json()["external_effect_dispatched"] is False


@pytest.mark.parametrize(
    "key",
    (
        "api_key",
        "APIKEY",
        "client-secret",
        "CLIENTSECRET",
        "accessToken",
        "ACCESSTOKEN",
        "secretValue",
        "private key",
    ),
)
def test_provider_key_normalization_is_at_least_as_strict_as_connector_sdk(
    key: str,
) -> None:
    if is_secret_key_name(key):
        assert is_forbidden_provider_key(key)
    assert is_forbidden_provider_key(key)
