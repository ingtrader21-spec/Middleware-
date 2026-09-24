from __future__ import annotations

from typing import Any
from uuid import uuid4

import jwt
from fastapi.testclient import TestClient

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.communications import CommunicationsService, MemoryCommunicationsStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.security import AuthenticationError, AuthorizationError
from app.storage import MemoryInboxStore


def _token(client_id: str, scopes: list[str], *, tenant_id: str = "tenant-1") -> str:
    return jwt.encode(
        {
            "azp": client_id,
            "scope": " ".join(scopes),
            "aud": "middleware-api",
            "tenant_id": tenant_id,
            "sub": "monitoring-user",
            "iss": "https://auth.codestra.co/realms/codestra",
            "iat": 1_700_000_000,
            "exp": 1_700_000_300,
            "jti": str(uuid4()),
        },
        "test-only-key",
        algorithm="HS256",
    )


class DashboardTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("Authorization must be a Bearer token")
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        if claims.get("azp") != expected_client_id:
            raise AuthorizationError("token azp does not match producer")
        scopes = set(str(claims.get("scope") or "").split())
        if required_scope not in scopes:
            raise AuthorizationError("required scope is missing")
        return claims

    async def ready(self) -> bool:
        return True


def _runtime(test_settings) -> Runtime:
    commands = CommandService(
        MemoryCommandStore(),
        CommandPolicyRegistry(
            (
                CommandPolicy(
                    prefix="email.",
                    target="klyrow-email",
                    capability="EMAIL_DELIVERY",
                    readback_required=True,
                ),
            ),
            {"EMAIL_DELIVERY": True},
        ),
    )
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=DashboardTokenVerifier(),
        commands=commands,
        communications=CommunicationsService(
            store=MemoryCommunicationsStore(),
            commands=commands,
        ),
    )


def _headers(*, scope: str = "health.read", tenant: str = "tenant-1") -> dict[str, str]:
    return {
        "Authorization": "Bearer " + _token("monitoring-readonly", [scope], tenant_id=tenant),
        "X-Tenant-ID": tenant,
        "X-Correlation-ID": "dashboard-correlation-1",
    }


def test_operations_dashboard_requires_monitoring_identity(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        missing = client.get("/v1/operations-dashboard/overview", headers={"X-Tenant-ID": "tenant-1"})
        wrong_scope = client.get("/v1/operations-dashboard/overview", headers=_headers(scope="metrics.read"))

    assert missing.status_code == 401
    assert wrong_scope.status_code == 403


def test_operations_dashboard_exposes_safe_read_models(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        for path in (
            "/v1/operations-dashboard/overview",
            "/v1/operations-dashboard/auth-gateway",
            "/v1/operations-dashboard/routes",
            "/v1/operations-dashboard/providers",
            "/v1/operations-dashboard/messages/lifecycle",
            "/v1/operations-dashboard/webhooks",
            "/v1/operations-dashboard/queues",
            "/v1/operations-dashboard/release-gates",
            "/v1/operations-dashboard/canaries",
        ):
            response = client.get(path, headers=_headers())
            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["schemaVersion"] == "1.0"
            assert payload["tenantId"] == "tenant-1"
            assert "checkedAt" in payload
            assert "secret" not in response.text.lower()
            assert "password" not in response.text.lower()

        tenant = client.get("/v1/operations-dashboard/tenants/tenant-1", headers=_headers())

    assert tenant.status_code == 200
    assert tenant.json()["commands"] == {}


def test_operations_dashboard_enforces_tenant_scope(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        response = client.get(
            "/v1/operations-dashboard/tenants/tenant-2",
            headers=_headers(tenant="tenant-1"),
        )

    assert response.status_code == 403


def test_operations_dashboard_exports_bounded_release_and_canary_metrics(test_settings) -> None:
    app = create_app(settings=test_settings, runtime=_runtime(test_settings))
    with TestClient(app) as client:
        release = client.get("/v1/operations-dashboard/release-gates", headers=_headers())
        canaries = client.get("/v1/operations-dashboard/canaries", headers=_headers())
        auth_denial = client.get(
            "/v1/operations-dashboard/overview",
            headers=_headers(scope="metrics.read"),
        )
        metrics = client.get(
            "/metrics",
            headers={"Authorization": "Bearer " + _token("monitoring-readonly", ["metrics.read"])},
        )

    assert release.status_code == 200
    assert canaries.status_code == 200
    assert auth_denial.status_code == 403
    assert metrics.status_code == 200
    assert "codestra_operations_dashboard_release_gate_state" in metrics.text
    assert 'gate="allExternalEffectsDisabled"' in metrics.text
    assert "codestra_operations_dashboard_canary_state" in metrics.text
    assert 'provider="klyrow-email"' in metrics.text
    assert "codestra_operations_dashboard_auth_failures_total" in metrics.text
    assert "tenant-1" not in metrics.text
