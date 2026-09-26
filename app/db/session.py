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

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, runtime_database_sslmode, settings
from app.db.connection import build_database_connection_authority


def _build_engine(config: Settings, database_url: str | None = None) -> AsyncEngine:
    environment = getattr(config, "app_env", "test")
    runtime_profile = getattr(config, "runtime_profile_id", None)
    profile_sslmode = runtime_database_sslmode(runtime_profile)
    requires_verify_full = (
        environment in {"staging", "production"} and profile_sslmode == "verify-full"
    )
    authority = build_database_connection_authority(
        database_url or config.database_url,
        command_timeout_seconds=config.database_command_timeout_seconds,
        application_name="codestra-middleware/" + (runtime_profile or environment),
        secure_environment=requires_verify_full,
        validate_tls_files=requires_verify_full,
    )
    return create_async_engine(
        authority.sqlalchemy_url,
        pool_pre_ping=True,
        pool_size=config.database_pool_size,
        max_overflow=config.database_max_overflow,
        pool_timeout=config.database_pool_timeout_seconds,
        pool_recycle=config.database_pool_recycle_seconds,
        connect_args=authority.connect_args,
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
