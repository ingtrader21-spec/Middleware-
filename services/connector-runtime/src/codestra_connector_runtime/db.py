"""Database engine, transaction, and tenant-context helpers."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def async_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg_async://", 1)
    return url


def create_engine(database_url: str, *, pool_size: int = 10) -> AsyncEngine:
    return create_async_engine(
        async_url(database_url),
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=pool_size,
    )


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def set_tenant_context(session: AsyncSession, tenant_id: UUID) -> None:
    await session.execute(
        text("SELECT set_config('codestra.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )


@asynccontextmanager
async def tenant_transaction(
    factory: async_sessionmaker[AsyncSession], tenant_id: UUID
) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_id)
            yield session
