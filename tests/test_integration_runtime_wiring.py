from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import webhook_api
from app.entrypoints import integration_api


def test_exact_odoo_event_dispatches_to_durable_webhook_intake(monkeypatch) -> None:
    verified: list[tuple[str, str, str]] = []
    accepted: list[tuple[object, str, bytes, dict[str, str]]] = []

    class Tokens:
        async def verify(
            self,
            authorization: str,
            *,
            expected_client_id: str,
            required_scope: str,
        ) -> dict[str, str]:
            verified.append(
                (authorization, expected_client_id, required_scope)
            )
            return {"sub": "odoo-integration"}

    async def fake_accept(
        runtime,
        route,
        *,
        claims,
        method: str,
        path: str,
        raw_body: bytes,
        headers: dict[str, str],
    ):
        accepted.append((route, path, raw_body, headers))
        assert runtime.tokens.__class__ is Tokens
        assert claims == {"sub": "odoo-integration"}
        assert method == "POST"
        return (
            SimpleNamespace(
                correlation_id="correlation-test-syn",
                model_dump=lambda **_kwargs: {
                    "status": "accepted",
                    "correlation_id": "correlation-test-syn",
                },
            ),
            202,
        )

    monkeypatch.setattr(webhook_api, "accept_webhook", fake_accept)
    app = FastAPI()
    app.state.runtime = SimpleNamespace(
        tokens=Tokens(),
        settings=SimpleNamespace(max_request_body_bytes=1024),
    )
    app.include_router(webhook_api.odoo_event_router)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/odoo/events",
            content=b'{"event_id":"TEST_SYN_EVENT_001"}',
            headers={"Authorization": "Bearer synthetic"},
        )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert response.headers["X-Correlation-ID"] == "correlation-test-syn"
    assert verified == [
        (
            "Bearer synthetic",
            "odoo-integration",
            "odoo.events.publish",
        )
    ]
    assert len(accepted) == 1
    route, path, raw_body, headers = accepted[0]
    assert getattr(route, "path", None) == "/api/v1/odoo/events"
    assert path == "/api/v1/odoo/events"
    assert raw_body == b'{"event_id":"TEST_SYN_EVENT_001"}'
    assert headers["authorization"] == "Bearer synthetic"
    assert headers["content-length"] == str(len(raw_body))


@pytest.mark.asyncio
async def test_integration_entrypoint_owns_canonical_runtime_lifecycle(
    monkeypatch,
) -> None:
    """The lifespan builds the container from the application's settings,
    publishes it as ``app.state.runtime`` and closes it on shutdown."""
    from app.core import health

    class Runtime:
        closed = False

        async def close(self) -> None:
            self.closed = True

    runtime = Runtime()
    state = integration_api.app.state.runtime_state
    configured = state.settings

    async def fake_build_runtime(settings):
        assert settings is configured
        return runtime

    monkeypatch.setattr(health, "build_runtime_container", fake_build_runtime)
    monkeypatch.setattr(state, "runtime", None)
    monkeypatch.setattr(state, "owns_runtime", False)
    monkeypatch.setattr(state, "startup_failed", False)

    async with integration_api.app.router.lifespan_context(integration_api.app):
        assert integration_api.app.state.runtime is runtime
        assert state.owns_runtime is True
        assert runtime.closed is False

    assert runtime.closed is True
    assert integration_api.app.state.runtime is None


@pytest.mark.asyncio
async def test_integration_entrypoint_stays_live_but_unready_when_startup_fails(
    monkeypatch,
) -> None:
    from app.core import health
    from app.core.runtime import RuntimeStartupError

    state = integration_api.app.state.runtime_state

    async def failing_build(settings):
        raise RuntimeStartupError("runtime dependency unavailable: ConnectionRefusedError")

    monkeypatch.setattr(health, "build_runtime_container", failing_build)
    monkeypatch.setattr(state, "runtime", None)
    monkeypatch.setattr(state, "owns_runtime", False)
    monkeypatch.setattr(state, "startup_failed", False)

    async with integration_api.app.router.lifespan_context(integration_api.app):
        assert integration_api.app.state.runtime is None
        assert state.startup_failed is True
        assert state.startup_error == "RuntimeStartupError"
