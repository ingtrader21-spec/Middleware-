"""The single SQLAlchemy engine of the Middleware process.

The engine is created once from the canonical ``app.core.config.settings``
and shared by every ORM router, worker and script through ``SessionFactory``
and ``get_session``. ``RuntimeContainer`` (``app.core.runtime``) references
this engine rather than creating another one, and disposes it on shutdown.

``configure()`` exists for process bootstrap and tests that need the engine
bound to a different DSN; it rebinds the module-level ``engine`` and
``SessionFactory`` in place so consumers that imported those names keep
working.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, settings


TENANT_CONTEXT_GUC = "app.tenant_id"


def _canonical_tenant_id(tenant_id: str | UUID) -> str:
    """Validate and normalize the tenant identifier used by PostgreSQL RLS."""
    value = str(tenant_id).strip()
    if not value:
        raise ValueError("tenant_id is required")
    try:
        return str(UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("tenant_id must be a UUID") from exc


async def set_transaction_tenant_context(
    session: AsyncSession,
    tenant_id: str | UUID,
) -> str:
    """Set the tenant identifier for the current PostgreSQL transaction only.

    ``set_config(..., true)`` is PostgreSQL's transaction-local equivalent of
    ``SET LOCAL``. The value is discarded on COMMIT/ROLLBACK, preventing
    tenant context from leaking through pooled connections.
    """
    normalized = _canonical_tenant_id(tenant_id)
    await session.execute(
        text("SELECT set_config(:setting_name, :tenant_id, true)"),
        {"setting_name": TENANT_CONTEXT_GUC, "tenant_id": normalized},
    )
    return normalized


def _native_asyncpg_dsn(database_url: str) -> str:
    """Return a native asyncpg DSN while preserving libpq TLS query policy."""
    prefix = "postgresql+asyncpg://"
    if database_url.startswith(prefix):
        return "postgresql://" + database_url[len(prefix):]
    return database_url


def _build_engine(config: Settings, database_url: str | None = None) -> AsyncEngine:
    native_dsn = _native_asyncpg_dsn(database_url or config.database_url)
    return create_async_engine(
        "postgresql+asyncpg://",
        pool_pre_ping=True,
        pool_size=config.database_pool_size,
        max_overflow=config.database_max_overflow,
        pool_timeout=config.database_pool_timeout_seconds,
        pool_recycle=config.database_pool_recycle_seconds,
        connect_args={
            "dsn": native_dsn,
            "command_timeout": config.database_command_timeout_seconds,
        },
    )


engine: AsyncEngine = _build_engine(settings)
SessionFactory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine, expire_on_commit=False
)


def get_engine() -> AsyncEngine:
    """Return the process-wide engine."""
    return engine


def configure(config: Settings | None = None, *, database_url: str | None = None) -> AsyncEngine:
    """Rebind the process-wide engine (and ``SessionFactory``) to ``config``.

    The previous engine is left for the caller to dispose; ``RuntimeContainer``
    does so on close. Consumers holding ``SessionFactory`` see the new engine
    because the sessionmaker is reconfigured in place.
    """
    global engine
    resolved = config or settings
    engine = _build_engine(resolved, database_url)
    SessionFactory.configure(bind=engine)
    return engine


async def dispose() -> None:
    """Close every pooled connection of the process-wide engine."""
    await engine.dispose()


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        yield session
