"""Readiness of the deployed integration API is decided by app.core.health.

Without a runtime container the process is never ready and reports which
required dependency is down; with a container every configured component
must be ready. Probes never disclose addresses or credentials.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.application import create_app
from app.core import health
from app.core.config import Settings, settings
from app.entrypoints import integration_api


def _app_without_runtime() -> TestClient:
    # No ``with``: the lifespan does not run, so no container is built.
    return TestClient(integration_api.app)


@pytest.mark.parametrize("dependency", ["postgres", "redis", "keycloak"])
@pytest.mark.parametrize("state", ["unavailable", "not_configured"])
@pytest.mark.parametrize("path", ["/health/ready", "/ready", "/readyz"])
def test_each_required_dependency_blocks_readiness(monkeypatch, dependency, state, path):
    states = {"postgres": "online", "redis": "online", "keycloak": "online", dependency: state}

    async def probe(_settings, *, engine=None):
        return states

    monkeypatch.setattr(health, "dependency_states", probe)
    client = _app_without_runtime()
    response = client.get(path)
    assert response.status_code == 503
    assert response.json()["status"] == "not-ready"
    assert response.json()["dependencies"][dependency] == state
    assert client.get("/health/live").status_code == 200
    dependencies = client.get("/health/dependencies").json()
    assert dependencies[dependency if dependency != "postgres" else "database"] == state


def test_dependencies_online_without_a_runtime_is_still_not_ready(monkeypatch):
    async def probe(_settings, *, engine=None):
        return {"postgres": "online", "redis": "online", "keycloak": "online"}

    monkeypatch.setattr(health, "dependency_states", probe)
    state = integration_api.app.state.runtime_state
    monkeypatch.setattr(state, "runtime", None)
    monkeypatch.setattr(state, "startup_failed", False)
    monkeypatch.setattr(state, "startup_error", None)
    response = _app_without_runtime().get("/health/ready")
    assert response.status_code == 503
    assert response.json()["reason"] == "runtime_unavailable"


def test_all_required_components_ready_with_a_runtime():
    app = create_app(
        settings=Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}),
        service="middleware-integration-api",
    )
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["components"]["inbox_store"] == "ready"
    assert body["components"]["replay_guard"] == "ready"
    # Implicit identity in test: the derived authority is not a dependency.
    assert body["components"]["identity_jwks"] == "not_configured"
    assert body["dependencies"] == {"postgres": "online", "redis": "online", "keycloak": "not_configured"}


def test_probes_reject_missing_keycloak_and_unavailable_database_and_redis(monkeypatch):
    class Unavailable:
        def connect(self):
            raise RuntimeError("SECRET_MUST_NOT_BE_EXPOSED")

    monkeypatch.setattr(settings, "redis_url", "")
    monkeypatch.setattr(settings, "keycloak_issuer", "")
    monkeypatch.setattr(settings, "keycloak_jwks_url", "")
    states = asyncio.run(health.dependency_states(settings, engine=Unavailable()))
    assert states == {"postgres": "unavailable", "redis": "not_configured", "keycloak": "not_configured"}


@pytest.mark.parametrize("failed", [None, "postgres", "redis", "keycloak"])
def test_actual_probe_logic_checks_all_dependency_clients(monkeypatch, failed):
    import json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    database_context = AsyncMock()
    database_connection = AsyncMock()
    database_context.__aenter__.return_value = database_connection
    if failed == "postgres":
        database_connection.execute.side_effect = RuntimeError("private database detail")
    engine = SimpleNamespace(connect=lambda: database_context)
    redis_context = AsyncMock()
    redis_context.__aenter__.return_value = redis_context
    redis_context.ping.return_value = failed != "redis"
    monkeypatch.setattr(health, "Redis", SimpleNamespace(from_url=lambda *_args, **_kwargs: redis_context))
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:6379/15")
    for name, value in {
        "keycloak_issuer": "https://identity.example.invalid/realm",
        "keycloak_audience": "middleware-api",
        "keycloak_authorized_parties": "test-client",
        "keycloak_jwks_url": "https://identity.example.invalid/certs",
    }.items():
        monkeypatch.setattr(settings, name, value)
    public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    jwks = {"keys": [json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))]}
    response = SimpleNamespace(json=lambda: jwks, raise_for_status=lambda: None)
    http = AsyncMock()
    http.__aenter__.return_value = http
    http.get.return_value = response
    if failed == "keycloak":
        http.get.side_effect = RuntimeError("private signing endpoint detail")
    monkeypatch.setattr(health.httpx, "AsyncClient", lambda **_kwargs: http)
    states = asyncio.run(health.dependency_states(settings, engine=engine))
    assert states == {name: "unavailable" if name == failed else "online" for name in ("postgres", "redis", "keycloak")}
    database_connection.execute.assert_awaited_once()
    redis_context.ping.assert_awaited_once()
    redis_context.__aexit__.assert_awaited_once()
    http.get.assert_awaited_once()


def test_runtime_startup_failure_blocks_readiness(monkeypatch):
    async def probe(_settings, *, engine=None):
        return {"postgres": "online", "redis": "online", "keycloak": "online"}

    monkeypatch.setattr(health, "dependency_states", probe)
    state = integration_api.app.state.runtime_state
    monkeypatch.setattr(state, "runtime", None)
    monkeypatch.setattr(state, "startup_failed", True)
    monkeypatch.setattr(state, "startup_error", "RuntimeStartupError")
    monkeypatch.setattr(state, "last_build_attempt", float("inf"))  # no rebuild during the probe

    response = _app_without_runtime().get("/readyz")
    assert response.status_code == 503
    assert response.json()["status"] == "not-ready"
    assert response.json()["reason"] == "RuntimeStartupError"
