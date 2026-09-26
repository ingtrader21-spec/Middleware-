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
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session as SyncSession

from app.core.config import Settings, settings
from app.db.tenant_context import (
    TENANT_CONTEXT_GUC,
    TENANT_CONTEXT_INFO_KEY,
    canonical_tenant_id,
)


@event.listens_for(SyncSession, "after_begin")
def _restore_transaction_tenant_context(session, transaction, connection) -> None:
    """Re-apply bound tenant context whenever SQLAlchemy opens a transaction.

    A route may commit and continue using the same session. PostgreSQL clears
    SET LOCAL state at commit/rollback, so storing the validated tenant in
    ``session.info`` lets every subsequent transaction restore the same
    transaction-local context without making it connection-persistent.
    """
    tenant_id = session.info.get(TENANT_CONTEXT_INFO_KEY)
    if tenant_id:
        connection.execute(
            text("SELECT set_config(:setting_name, :tenant_id, true)"),
            {"setting_name": TENANT_CONTEXT_GUC, "tenant_id": tenant_id},
        )


async def set_transaction_tenant_context(
    session: AsyncSession,
    tenant_id: str | UUID,
) -> str:
    """Bind validated tenant authority to the session and current transaction.

    ``set_config(..., true)`` is PostgreSQL's transaction-local equivalent of
    ``SET LOCAL``. The value is discarded on COMMIT/ROLLBACK. The validated
    tenant is retained only in the SQLAlchemy session's in-memory ``info``
    map so subsequent transactions on the same request/worker session restore
    the same transaction-local authority.
    """
    normalized = canonical_tenant_id(tenant_id)
    session.info[TENANT_CONTEXT_INFO_KEY] = normalized
    await session.execute(
        text("SELECT set_config(:setting_name, :tenant_id, true)"),
        {"setting_name": TENANT_CONTEXT_GUC, "tenant_id": normalized},
    )
    return normalized


@asynccontextmanager
async def tenant_session(tenant_id: str | UUID):
    """Open a process-wide session already bound to one validated tenant."""
    async with SessionFactory() as session:
        await set_transaction_tenant_context(session, tenant_id)
        yield session


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
