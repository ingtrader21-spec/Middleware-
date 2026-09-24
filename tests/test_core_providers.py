"""The shared-resource providers resolve for every kind of app the routers
run in: the canonical RuntimeContainer app, and a router-only app (standalone
entrypoints, router-level tests) that carries no ``app.state`` at all."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from redis.asyncio import Redis

from app.core import providers
from app.core.config import settings as process_settings
from app.storage import StorageError


def _request(app: FastAPI) -> SimpleNamespace:
    return SimpleNamespace(app=app)


def test_router_only_app_gets_one_process_redis_client(monkeypatch):
    monkeypatch.setattr(process_settings, "redis_url", "redis://redis.test:6379/9")
    app = FastAPI()
    first = providers.get_redis_client(_request(app))  # type: ignore[arg-type]
    second = providers.get_redis_client(_request(app))  # type: ignore[arg-type]
    assert isinstance(first, Redis)
    assert first is second
    assert app.state.redis is first
    assert first.connection_pool.connection_kwargs["host"] == "redis.test"


def test_runtime_redis_client_wins_over_process_fallback():
    app = FastAPI()
    runtime_client = object()
    app.state.runtime = SimpleNamespace(redis=runtime_client)
    assert providers.get_redis_client(_request(app)) is runtime_client  # type: ignore[arg-type]


def test_unconfigured_redis_is_a_storage_error(monkeypatch):
    monkeypatch.setattr(process_settings, "redis_url", "")
    app = FastAPI()
    with pytest.raises(StorageError):
        providers.get_redis_client(_request(app))  # type: ignore[arg-type]


def test_router_only_app_gets_one_process_http_client():
    app = FastAPI()
    first = providers.get_http_client(_request(app))  # type: ignore[arg-type]
    second = providers.get_http_client(_request(app))  # type: ignore[arg-type]
    assert first is second
    assert providers.get_provisioning_http_client(_request(app)) is first  # type: ignore[arg-type]
