"""RuntimeContainer: one pool, one client, one verifier; fail-closed startup."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import runtime as runtime_module
from app.core.config import Settings
from app.core.health import RuntimeState, dependencies_from_components, readiness_snapshot
from app.core.runtime import (
    ReadinessReport,
    RuntimeContainer,
    RuntimeStartupError,
    build_runtime_container,
    identity_probe_required,
)
from app.replay import MemoryReplayGuard
from app.storage import MemoryInboxStore


class ReadyVerifier:
    async def verify(self, authorization: str, *, expected_client_id: str, required_scope: str):
        return {}

    async def ready(self) -> bool:
        return True


def test_settings() -> Settings:
    return Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})


def test_in_memory_container_owns_no_infrastructure_and_is_ready() -> None:
    container = asyncio.run(build_runtime_container(test_settings(), tokens=ReadyVerifier()))
    assert container.pool is None and container.redis is None and container.engine is None
    report = asyncio.run(container.readiness())
    assert report.ready
    assert report.components["inbox_store"] == "ready"
    assert report.components["replay_guard"] == "ready"
    assert "alembic_head" not in report.components
    asyncio.run(container.close())
    # Closing twice is safe.
    asyncio.run(container.close())


def test_implicit_identity_is_not_probed_outside_staging_and_production() -> None:
    settings = test_settings()
    assert identity_probe_required(settings) is False
    explicit = Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "KEYCLOAK_ISSUER": "https://ci-identity.example.invalid/realm",
            "KEYCLOAK_AUDIENCE": "middleware-api",
            "KEYCLOAK_JWKS_URL": "http://127.0.0.1:8120/certs.json",
        }
    )
    assert identity_probe_required(explicit) is True
    container = asyncio.run(build_runtime_container(settings, tokens=ReadyVerifier()))
    assert asyncio.run(container.readiness()).components["identity_jwks"] == "not_configured"


def test_readiness_is_bounded_and_names_the_failed_component() -> None:
    class Hanging(MemoryReplayGuard):
        async def ready(self) -> bool:
            await asyncio.sleep(30)
            return True

    settings = test_settings().replace(readiness_timeout_seconds=1)
    container = RuntimeContainer(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=Hanging(),
        tokens=ReadyVerifier(),
    )
    report = asyncio.run(container.readiness())
    assert report.ready is False
    assert report.components["replay_guard"] == "not_ready"
    assert report.components["command_store"] == "not_configured"
    assert dependencies_from_components(report.components) == {
        "postgres": "online",
        "redis": "unavailable",
        "keycloak": "online",
    }


def test_close_releases_every_owned_resource_exactly_once_even_if_a_store_fails() -> None:
    events: list[str] = []

    class FailingInbox(MemoryInboxStore):
        async def close(self) -> None:
            events.append("inbox")
            raise RuntimeError("store close failed")

    class Pool:
        async def close(self) -> None:
            events.append("pool")

    class Redis:
        async def aclose(self) -> None:
            events.append("redis")

    class Engine:
        async def dispose(self) -> None:
            events.append("engine")

    container = RuntimeContainer(
        settings=test_settings(),
        inbox=FailingInbox(),
        replay=MemoryReplayGuard(),
        tokens=ReadyVerifier(),
        pool=Pool(),  # type: ignore[arg-type]
        redis=Redis(),  # type: ignore[arg-type]
        engine=Engine(),  # type: ignore[arg-type]
    )
    asyncio.run(container.close())
    asyncio.run(container.close())
    assert events == ["inbox", "pool", "redis", "engine"]


def test_build_releases_the_pool_when_a_later_dependency_fails(monkeypatch) -> None:
    closed: list[str] = []

    class Pool:
        async def close(self) -> None:
            closed.append("pool")

    async def open_pool(_url: str) -> Pool:
        return Pool()

    async def open_redis(_url: str):
        raise ConnectionRefusedError("redis down")

    monkeypatch.setattr(runtime_module, "_open_pool", open_pool)
    monkeypatch.setattr(runtime_module, "_open_redis", open_redis)
    settings = Settings.from_env(
        {
            "APP_ENV": "test",
            "DATABASE_URL": "postgresql://u:p@127.0.0.1:1/db",
            "REDIS_URL": "redis://127.0.0.1:1/0",
        }
    )
    with pytest.raises(RuntimeStartupError, match="ConnectionRefusedError"):
        asyncio.run(build_runtime_container(settings, tokens=ReadyVerifier()))
    assert closed == ["pool"]


def test_build_refuses_a_database_url_less_configuration() -> None:
    settings = Settings.from_env(
        {"APP_ENV": "test", "DATABASE_URL": "postgresql://u:p@127.0.0.1:1/db", "REDIS_URL": "redis://127.0.0.1:1/0"}
    )
    settings.database_url = ""
    with pytest.raises(RuntimeStartupError, match="DATABASE_URL and REDIS_URL are required"):
        asyncio.run(build_runtime_container(settings, tokens=ReadyVerifier()))


def test_readiness_report_semantics() -> None:
    assert ReadinessReport({"a": "ready", "b": "not_configured"}).ready is True
    assert ReadinessReport({"a": "ready", "b": "not_ready"}).ready is False


def test_runtime_state_rebuilds_at_most_once_per_interval(monkeypatch) -> None:
    attempts: list[int] = []

    async def failing_build(settings: Settings) -> Any:
        attempts.append(1)
        raise RuntimeStartupError("still down")

    monkeypatch.setattr("app.core.health.build_runtime_container", failing_build)
    settings = test_settings().replace(runtime_rebuild_interval_seconds=600)
    state = RuntimeState(settings=settings)
    asyncio.run(state.build())
    assert state.startup_failed is True and state.startup_error == "RuntimeStartupError"

    async def probe():
        return {"postgres": "online", "redis": "online", "keycloak": "online"}

    monkeypatch.setattr("app.core.health.dependency_states", lambda _s, *, engine=None: probe())
    first = asyncio.run(readiness_snapshot(state))
    second = asyncio.run(readiness_snapshot(state))
    assert first.ready is False and second.ready is False
    assert first.reason == "RuntimeStartupError"
    # The startup attempt is the only build within the interval.
    assert len(attempts) == 1

    # Once the interval elapsed, one guarded rebuild is attempted per probe.
    state.last_build_attempt = float("-inf")
    asyncio.run(readiness_snapshot(state))
    assert len(attempts) == 2


def test_runtime_state_publishes_a_successful_rebuild(monkeypatch) -> None:
    container = RuntimeContainer(
        settings=test_settings(),
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=ReadyVerifier(),
    )

    async def build(settings: Settings) -> RuntimeContainer:
        return container

    monkeypatch.setattr("app.core.health.build_runtime_container", build)
    state = RuntimeState(settings=test_settings(), startup_failed=True)
    snapshot = asyncio.run(readiness_snapshot(state))
    assert snapshot.ready is True
    assert state.runtime is container and state.owns_runtime is True
    assert state.startup_failed is False


def test_alembic_head_is_reported_from_the_shared_pool() -> None:
    class Connection:
        def __init__(self, head: str | None) -> None:
            self.head = head

        async def fetchval(self, query: str):
            if "to_regclass" in query:
                return self.head is not None
            return self.head

    class Acquire:
        def __init__(self, head: str | None) -> None:
            self.connection = Connection(head)

        async def __aenter__(self):
            return self.connection

        async def __aexit__(self, *_exc):
            return None

    class Pool:
        def __init__(self, head: str | None) -> None:
            self.head = head

        def acquire(self):
            return Acquire(self.head)

        async def close(self) -> None:
            return None

    settings = test_settings()
    for head, expected in (
        (settings.schema_head, "ready"),
        ("0001_stale", "not_ready"),
        (None, "not_configured"),
    ):
        container = RuntimeContainer(
            settings=settings,
            inbox=MemoryInboxStore(),
            replay=MemoryReplayGuard(),
            tokens=ReadyVerifier(),
            pool=Pool(head),  # type: ignore[arg-type]
        )
        assert asyncio.run(container.readiness()).components["alembic_head"] == expected


def test_dependencies_from_components_never_reports_online_on_a_failure() -> None:
    assert dependencies_from_components(
        {"inbox_store": "ready", "alembic_head": "not_ready", "replay_guard": "ready", "identity_jwks": "not_configured"}
    ) == {"postgres": "unavailable", "redis": "online", "keycloak": "not_configured"}


def test_health_snapshot_without_runtime_uses_settings_probe(monkeypatch) -> None:
    async def probe(_settings, *, engine=None):
        return {"postgres": "unavailable", "redis": "online", "keycloak": "online"}

    monkeypatch.setattr("app.core.health.dependency_states", probe)
    state = RuntimeState(settings=test_settings())
    snapshot = asyncio.run(readiness_snapshot(state))
    assert snapshot.ready is False
    assert snapshot.reason == "runtime_unavailable"
    assert snapshot.dependencies["postgres"] == "unavailable"
    payload = snapshot.payload("middleware-api", test_settings())
    assert payload["status"] == "not-ready" and payload["database"] == "unavailable"
    assert isinstance(SimpleNamespace(**payload).checked_at, str)
