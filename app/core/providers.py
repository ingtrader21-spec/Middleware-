"""Dependency providers: the one way handlers obtain shared resources.

Every provider resolves from ``request.app.state`` populated by
:func:`app.application.create_app`; none opens a connection, reads the
environment or builds a verifier. A missing resource raises
:class:`~app.storage.StorageError` (rendered as a 503 by the canonical error
envelope) so a route never runs against a half-built runtime.

Usage::

    from fastapi import Depends
    from app.core.providers import RuntimeDep, SettingsDep, TokenVerifierDep

    @router.get("/example")
    async def example(runtime: RuntimeDep, settings: SettingsDep): ...
"""

from __future__ import annotations

from typing import Annotated

import httpx
from fastapi import Depends, Request
from redis.asyncio import Redis

from app.automation_v2 import AutomationService
from app.commands import CommandService
from app.communications import CommunicationsService
from app.core.config import Settings
from app.core.config import settings as process_settings
from app.core.runtime import RuntimeContainer
from app.db.session import get_session
from app.realtime import RealtimeStore
from app.replay import ReplayGuard
from app.security import TokenVerifier
from app.storage import InboxStore, StorageError

__all__ = [
    "HttpClientDep",
    "ProvisioningHttpClientDep",
    "RedisDep",
    "get_http_client",
    "get_provisioning_http_client",
    "get_redis_client",
    "AutomationDep",
    "CommandsDep",
    "CommunicationsDep",
    "InboxDep",
    "RealtimeDep",
    "ReplayDep",
    "RuntimeDep",
    "SettingsDep",
    "TokenVerifierDep",
    "get_automation_service",
    "get_command_service",
    "get_communications_service",
    "get_inbox_store",
    "get_realtime_store",
    "get_replay_guard",
    "get_runtime",
    "get_session",
    "get_settings",
    "get_token_verifier",
]


def get_settings(request: Request) -> Settings:
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        runtime = getattr(request.app.state, "runtime", None)
        if runtime is None:
            raise StorageError("application settings are unavailable")
        settings = runtime.settings
    return settings


def get_runtime(request: Request) -> RuntimeContainer:
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise StorageError("runtime is unavailable")
    return runtime


def get_token_verifier(request: Request) -> TokenVerifier:
    return get_runtime(request).tokens


def _process_http(app) -> httpx.AsyncClient:
    """One outbound client for a narrow deployed process that runs without a
    RuntimeContainer (the standalone entrypoints); closed at shutdown."""
    client = getattr(app.state, "http", None)
    if client is None:
        # Process lifetime: released when the process exits (these narrow
        # entrypoints have no lifespan of their own).
        client = httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False)
        app.state.http = client
    return client


def get_http_client(request: Request) -> httpx.AsyncClient:
    """The process-wide outbound HTTP client. Handlers never open their own.

    Typed ``Request`` for FastAPI's dependency introspection; a WebSocket (same
    ``.app``) may be passed by direct callers (``cast(Request, websocket)``)."""
    runtime = getattr(request.app.state, "runtime", None)
    client = getattr(runtime, "http", None)
    if client is not None:
        return client
    return _process_http(request.app)


def get_provisioning_http_client(request: Request) -> httpx.AsyncClient:
    """The client that trusts the provisioning service's CA bundle."""
    runtime = getattr(request.app.state, "runtime", None)
    client = getattr(runtime, "http_provisioning", None)
    if client is not None:
        return client
    return get_http_client(request)


def get_redis_client(request: Request) -> Redis:
    """The RuntimeContainer's Redis client; a process without one (in-memory
    runtime, standalone entrypoint, router-only app) gets one shared client per
    process, built from the process settings the handlers used to read."""
    runtime = getattr(request.app.state, "runtime", None)
    client = getattr(runtime, "redis", None)
    if client is not None:
        return client
    client = getattr(request.app.state, "redis", None)
    if client is None:
        settings = getattr(request.app.state, "settings", None) or process_settings
        if not settings.redis_url:
            raise StorageError("Redis is not configured")
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        request.app.state.redis = client
    return client


def get_inbox_store(request: Request) -> InboxStore:
    return get_runtime(request).inbox


def get_replay_guard(request: Request) -> ReplayGuard:
    return get_runtime(request).replay


def get_command_service(request: Request) -> CommandService:
    commands = get_runtime(request).commands
    if commands is None:
        raise StorageError("command ledger is unavailable")
    return commands


def get_communications_service(request: Request) -> CommunicationsService:
    communications = get_runtime(request).communications
    if communications is None:
        raise StorageError("communications store is unavailable")
    return communications


def get_automation_service(request: Request) -> AutomationService:
    automation = get_runtime(request).automation
    if automation is None:
        raise StorageError("automation store is unavailable")
    return automation


def get_realtime_store(request: Request) -> RealtimeStore:
    realtime = get_runtime(request).realtime
    if realtime is None:
        raise StorageError("realtime store is unavailable")
    return realtime


SettingsDep = Annotated[Settings, Depends(get_settings)]
RuntimeDep = Annotated[RuntimeContainer, Depends(get_runtime)]
HttpClientDep = Annotated[httpx.AsyncClient, Depends(get_http_client)]
ProvisioningHttpClientDep = Annotated[httpx.AsyncClient, Depends(get_provisioning_http_client)]
RedisDep = Annotated[Redis, Depends(get_redis_client)]
TokenVerifierDep = Annotated[TokenVerifier, Depends(get_token_verifier)]
InboxDep = Annotated[InboxStore, Depends(get_inbox_store)]
ReplayDep = Annotated[ReplayGuard, Depends(get_replay_guard)]
CommandsDep = Annotated[CommandService, Depends(get_command_service)]
CommunicationsDep = Annotated[CommunicationsService, Depends(get_communications_service)]
AutomationDep = Annotated[AutomationService, Depends(get_automation_service)]
RealtimeDep = Annotated[RealtimeStore, Depends(get_realtime_store)]
