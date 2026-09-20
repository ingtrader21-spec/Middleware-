"""The single runtime container of a Middleware process.

``RuntimeContainer`` owns every shared infrastructure resource exactly once:

* one asyncpg pool (all Postgres-backed stores share it, ``owns_pool=False``),
* one Redis client (the replay guard shares it, ``owns_client=False``),
* the process-wide SQLAlchemy engine from :mod:`app.db.session`,
* one :class:`~app.security.KeycloakJwtVerifier` built from the canonical
  identity settings,
* one outbound ``httpx.AsyncClient`` (every adapter and domain handler that
  calls another service borrows it; nothing opens one per request),
* the :class:`~app.platform.runtime.PlatformRuntime`: the command kernel,
  policy gate, safety gate, adapter registry, execution bus and reconciler.

Application code never opens a pool, client or engine of its own; it asks the
container (``request.app.state.runtime``) or the providers in
:mod:`app.core.providers`.

Startup is fail-closed: :func:`build_runtime_container` releases everything it
opened when any dependency is unavailable and raises, and the application
factory turns that into a live-but-not-ready process. Readiness is a bounded
probe of every configured component; a component that is not configured is
reported as ``not_configured`` and does not block readiness.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

import asyncpg
import httpx
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.automation_policy import AutomationPolicy
from app.automation_v2 import (
    AutomationService,
    MemoryAutomationStore,
    PostgresAutomationStore,
    WorkflowRouter,
)
from app.commands import (
    CommandService,
    MemoryCommandStore,
    PostgresCommandStore,
)
from app.communications import (
    CommunicationsService,
    MemoryCommunicationsStore,
    PostgresCommunicationsStore,
)
from app.core.bootstrap import SERVICE_INTEGRATION_API
from app.core.config import Settings
from app.db.connection import database_connection_authority, native_postgres_dsn
from app.email_production_control import (
    EmailProductionControlService,
    MemoryEmailProductionPolicyStore,
    PostgresEmailProductionPolicyStore,
    ProductionGatedCommunicationsService,
)
from app.realtime import MemoryRealtimeStore, PostgresRealtimeStore, RealtimeStore
from app.replay import MemoryReplayGuard, RedisReplayGuard, ReplayGuard
from app.platform.runtime import PlatformRuntime, build_platform_runtime, command_policies
from app.security import KeycloakJwtVerifier, TokenVerifier
from app.storage import InboxStore, MemoryInboxStore, PostgresInboxStore

if TYPE_CHECKING:
    from app.observability_incidents import IncidentService

logger = logging.getLogger("codestra.runtime")

# One pool serves every asyncpg-backed store; sized for the sum of the former
# per-store pools (10 + 10 + 10 + 5 + 5) without exceeding it.
SHARED_POOL_MIN_SIZE = 1
SHARED_POOL_MAX_SIZE = 20
SHARED_POOL_COMMAND_TIMEOUT_SECONDS = 10
# One outbound HTTP client per process; adapters and handlers borrow it.
SHARED_HTTP_TIMEOUT_SECONDS = 10.0
SHARED_HTTP_MAX_CONNECTIONS = 64


class RuntimeStartupError(RuntimeError):
    """A required runtime dependency could not be initialized."""


@dataclass(frozen=True)
class ReadinessReport:
    components: dict[str, str]

    @property
    def ready(self) -> bool:
        return all(
            status in {"ready", "not_configured"}
            for status in self.components.values()
        )


def _asyncpg_dsn(database_url: str) -> str:
    """Deprecated compatibility wrapper over the canonical DB authority."""
    return native_postgres_dsn(database_url)


@dataclass
class RuntimeContainer:
    """Every shared resource and service of one Middleware process."""

    settings: Settings
    inbox: InboxStore
    replay: ReplayGuard
    tokens: TokenVerifier
    commands: CommandService | None = None
    communications: CommunicationsService | None = None
    incidents: IncidentService | None = None
    automation: AutomationService | None = None
    realtime: RealtimeStore | None = None
    # The V3 command kernel of this process (kernel, policy/safety gates,
    # adapter registry, execution bus handler, reconciler, metrics).
    platform: PlatformRuntime | None = None
    # Owned infrastructure. ``None`` for in-memory (test/development) runtimes
    # and for containers assembled by tests from fakes.
    pool: asyncpg.Pool | None = None
    redis: Redis | None = None
    engine: AsyncEngine | None = None
    http: httpx.AsyncClient | None = None
    # Outbound client for the provisioning service (its own CA bundle when
    # configured); otherwise the same object as ``http``.
    http_provisioning: httpx.AsyncClient | None = None
    # Whether readiness probes the identity authority. False only when the
    # identity is implicit (derived, not configured) in development/test, so a
    # local process never reports the production authority as a dependency.
    probe_identity: bool = True
    _closed: bool = field(default=False, init=False, repr=False)

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------
    async def _engine_ready(self) -> bool:
        assert self.engine is not None
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True

    async def _alembic_head(self) -> bool | None:
        """The ORM schema (Alembic) must sit at the canonical head.

        ``None`` when the database carries no Alembic table at all (a
        runtime-SQL-only database), which readiness reports as
        ``not_configured``; a present but stale head is ``not_ready``.
        """
        assert self.pool is not None
        async with self.pool.acquire() as connection:
            present = await connection.fetchval("SELECT to_regclass('alembic_version') IS NOT NULL")
            if not present:
                return None
            head = await connection.fetchval("SELECT version_num FROM alembic_version")
        return head == self.settings.schema_head

    def _checks(self) -> dict[str, Awaitable[bool | None] | None]:
        checks: dict[str, Awaitable[bool | None] | None] = {
            "inbox_store": self.inbox.ready(),
            "replay_guard": self.replay.ready(),
            "identity_jwks": self.tokens.ready() if self.probe_identity else None,
            "command_store": (
                self.commands.store.ready() if self.commands is not None else None
            ),
            "communications_store": (
                self.communications.store.ready()
                if self.communications is not None
                else None
            ),
            "incident_store": (
                self.incidents.store.ready() if self.incidents is not None else None
            ),
            "automation_store": (
                self.automation.ready() if self.automation is not None else None
            ),
        }
        if self.realtime is not None:
            checks["realtime_store"] = self.realtime.ready()
        if self.platform is not None:
            checks["adapter_registry"] = self.platform.registry_ready()
            checks["platform_adapters"] = self.platform.adapters_ready()
        if self.engine is not None:
            checks["sql_engine"] = self._engine_ready()
        if self.pool is not None:
            checks["alembic_head"] = self._alembic_head()
        return checks

    async def readiness(self) -> ReadinessReport:
        checks = self._checks()

        async def bounded(check: Awaitable[bool | None] | None) -> str:
            if check is None:
                return "not_configured"
            try:
                result = await asyncio.wait_for(
                    check,
                    timeout=self.settings.readiness_timeout_seconds,
                )
            except Exception:
                return "not_ready"
            if result is None:
                return "not_configured"
            return "ready" if result is True else "not_ready"

        results = await asyncio.gather(*(bounded(check) for check in checks.values()))
        return ReadinessReport(dict(zip(checks, results, strict=True)))

    async def ready(self) -> bool:
        return (await self.readiness()).ready

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    async def close(self) -> None:
        """Release every owned resource exactly once; never raise."""
        if self._closed:
            return
        self._closed = True
        closers: list[Awaitable[Any]] = [self.inbox.close(), self.replay.close()]
        if self.communications is not None:
            closers.append(self.communications.store.close())
        if self.automation is not None:
            closers.append(self.automation.close())
        if self.commands is not None:
            closers.append(self.commands.store.close())
        if self.incidents is not None:
            closers.append(self.incidents.store.close())
        if self.realtime is not None:
            closers.append(self.realtime.close())
        for closer in closers:
            try:
                await closer
            except Exception:
                logger.warning("runtime_component_close_failed", exc_info=True)
        # Shared infrastructure closes last, after every store released it.
        if self.pool is not None:
            try:
                await self.pool.close()
            except Exception:
                logger.warning("runtime_pool_close_failed", exc_info=True)
        if self.redis is not None:
            try:
                await self.redis.aclose()
            except Exception:
                logger.warning("runtime_redis_close_failed", exc_info=True)
        if self.engine is not None:
            try:
                await self.engine.dispose()
            except Exception:
                logger.warning("runtime_engine_dispose_failed", exc_info=True)
        for client in {id(c): c for c in (self.http, self.http_provisioning) if c is not None}.values():
            try:
                await client.aclose()
            except Exception:
                logger.warning("runtime_http_close_failed", exc_info=True)


# ----------------------------------------------------------------------
# Construction
# ----------------------------------------------------------------------
def identity_probe_required(settings: Settings) -> bool:
    """Whether readiness must probe the JWKS authority.

    Staging and production always probe it. Development and test probe it
    only when the identity was configured explicitly, so a local process
    never treats the derived production authority as its dependency.
    """
    return settings.identity.explicit or settings.app_env in {"staging", "production"}


_probe_identity = identity_probe_required


def _open_http(verify: bool | str = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(SHARED_HTTP_TIMEOUT_SECONDS),
        limits=httpx.Limits(max_connections=SHARED_HTTP_MAX_CONNECTIONS),
        follow_redirects=False,
        verify=verify,
    )


def _open_http_clients(settings: Settings) -> tuple[httpx.AsyncClient, httpx.AsyncClient]:
    """The shared outbound client and the provisioning-service client (which
    trusts the configured CA bundle when one is set)."""
    http = _open_http()
    ca_file = getattr(settings, "provisioning_service_ca_file", None)
    if isinstance(ca_file, str) and ca_file.strip():
        try:
            return http, _open_http(verify=ca_file)
        except (OSError, ValueError):
            logger.warning("provisioning_ca_bundle_unusable", extra={"path": ca_file})
    return http, http


def _memory_container(settings: Settings, tokens: TokenVerifier) -> RuntimeContainer:
    commands = CommandService(
        store=MemoryCommandStore(),
        policies=command_policies(settings),
    )
    http, http_provisioning = _open_http_clients(settings)
    automation = AutomationService(
        store=MemoryAutomationStore(),
        policy=AutomationPolicy.from_path(),
        workflow_router=WorkflowRouter.load(),
        commands=commands,
        umbrella_controls=settings.umbrella_controls,
    )
    return RuntimeContainer(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=tokens,
        commands=commands,
        platform=build_platform_runtime(
            settings, commands=commands, http=http, pool=None, service_id=SERVICE_INTEGRATION_API
        ),
        http=http,
        http_provisioning=http_provisioning,
        communications=ProductionGatedCommunicationsService(
            store=MemoryCommunicationsStore(),
            commands=commands,
            umbrella_controls=settings.umbrella_controls,
            production_control=EmailProductionControlService(
                store=MemoryEmailProductionPolicyStore(),
                settings=settings,
            ),
            enforce_production_policy=settings.app_env == "production",
        ),
        automation=automation,
        realtime=MemoryRealtimeStore(),
        probe_identity=_probe_identity(settings),
    )


async def _open_pool(settings: Settings, *, application_name: str) -> asyncpg.Pool:
    authority = database_connection_authority(
        settings.database_url,
        environment=settings.app_env,
        application_name=application_name,
        command_timeout=SHARED_POOL_COMMAND_TIMEOUT_SECONDS,
    )
    return await asyncpg.create_pool(
        **authority.asyncpg_pool_kwargs(
            min_size=SHARED_POOL_MIN_SIZE,
            max_size=SHARED_POOL_MAX_SIZE,
        )
    )


async def _open_redis(redis_url: str) -> Redis:
    client = Redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
    try:
        if not await client.ping():
            raise RuntimeStartupError("Redis is not reachable")
    except Exception:
        await client.aclose()
        raise
    return client


ProcessRole = Literal["api", "worker"]


async def build_runtime_container(
    settings: Settings,
    *,
    engine: AsyncEngine | None = None,
    tokens: TokenVerifier | None = None,
    role: ProcessRole = "api",
    service_id: str = SERVICE_INTEGRATION_API,
) -> RuntimeContainer:
    """Open the shared resources and assemble every store and service.

    ``engine`` defaults to the process-wide engine of :mod:`app.db.session`;
    it is disposed by :meth:`RuntimeContainer.close`. Any failure releases what
    was opened and raises :class:`RuntimeStartupError`.

    ``role="worker"`` builds the same container for the worker, scheduler and
    reconciler processes: the same pool, kernel, policy/safety gates, adapter
    registry and schema checks, but no Redis replay guard and no identity
    probe — those processes verify no bearer tokens and ingest no webhooks,
    so an identity or Redis outage must not stop command execution.
    """
    verifier = tokens or KeycloakJwtVerifier(settings)

    if settings.allow_in_memory_storage:
        return _memory_container(settings, verifier)

    if not settings.database_url or (role == "api" and not settings.redis_url):
        raise RuntimeStartupError("DATABASE_URL and REDIS_URL are required")

    pool: asyncpg.Pool | None = None
    redis: Redis | None = None
    container: RuntimeContainer | None = None
    try:
        pool = await _open_pool(settings, application_name=service_id)
        redis = await _open_redis(settings.redis_url) if role == "api" else None

        inbox = PostgresInboxStore(pool, owns_pool=False)
        await inbox.verify_schema()
        command_store = PostgresCommandStore(pool, owns_pool=False)
        if not await command_store.ready():
            raise RuntimeStartupError("command ledger schema is not ready")
        automation_store = PostgresAutomationStore(pool, owns_pool=False)
        if not await automation_store.ready():
            raise RuntimeStartupError("automation v2 schema is unavailable or stale")
        realtime = PostgresRealtimeStore(pool, owns_pool=False)
        communications_store = PostgresCommunicationsStore(pool, owns_pool=False)
        await communications_store._load()

        commands = CommandService(
            store=command_store,
            policies=command_policies(settings),
        )
        http, http_provisioning = _open_http_clients(settings)
        container = RuntimeContainer(
            settings=settings,
            inbox=inbox,
            replay=RedisReplayGuard(redis, owns_client=False) if redis is not None else MemoryReplayGuard(),
            tokens=verifier,
            commands=commands,
            platform=build_platform_runtime(
                settings, commands=commands, http=http, pool=pool, service_id=service_id
            ),
            http=http,
            http_provisioning=http_provisioning,
            communications=ProductionGatedCommunicationsService(
                store=communications_store,
                commands=commands,
                umbrella_controls=settings.umbrella_controls,
                production_control=EmailProductionControlService(
                    store=PostgresEmailProductionPolicyStore(pool),
                    settings=settings,
                ),
                enforce_production_policy=settings.app_env == "production",
            ),
            automation=AutomationService(
                store=automation_store,
                policy=AutomationPolicy.from_path(),
                workflow_router=WorkflowRouter.load(),
                commands=commands,
                umbrella_controls=settings.umbrella_controls,
            ),
            realtime=realtime,
            pool=pool,
            redis=redis,
            engine=engine if engine is not None else _process_engine(),
            probe_identity=_probe_identity(settings) if role == "api" else False,
        )
        report = await container.readiness()
        if not report.ready:
            failed = sorted(
                name for name, status in report.components.items() if status == "not_ready"
            )
            raise RuntimeStartupError(
                "mandatory runtime readiness checks failed during startup: "
                + ", ".join(failed)
            )
        return container
    except Exception as exc:
        if container is not None:
            await container.close()
        else:
            if redis is not None:
                await redis.aclose()
            if pool is not None:
                await pool.close()
        if isinstance(exc, RuntimeStartupError):
            raise
        raise RuntimeStartupError(f"runtime dependency unavailable: {type(exc).__name__}") from exc


def _process_engine() -> AsyncEngine:
    # Imported lazily: app.db.session builds the engine from the global
    # settings at import and must not be pulled in by in-memory test runtimes.
    from app.db.session import get_engine

    return get_engine()
