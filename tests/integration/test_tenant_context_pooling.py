from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.session import set_transaction_tenant_context

pytestmark = pytest.mark.skipif(
    os.getenv("RUNTIME_INTEGRATION_TESTS") != "1",
    reason="requires disposable PostgreSQL",
)


def _async_dsn() -> str:
    dsn = os.environ["DATABASE_URL"]
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://"):]
    if dsn.startswith("postgres://"):
        return "postgresql+asyncpg://" + dsn[len("postgres://"):]
    return dsn


@pytest.mark.asyncio
async def test_transaction_local_tenant_context_does_not_leak_through_pool() -> None:
    engine = create_async_engine(_async_dsn(), pool_size=1, max_overflow=0)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    try:
        async with sessions() as first:
            async with first.begin():
                await set_transaction_tenant_context(first, tenant_a)
                value = await first.scalar(text("SELECT current_setting('app.tenant_id', true)"))
                assert value == tenant_a

        async with sessions() as reused:
            async with reused.begin():
                inherited = await reused.scalar(
                    text("SELECT current_setting('app.tenant_id', true)")
                )
                assert inherited in (None, "")
                await set_transaction_tenant_context(reused, tenant_b)
                value = await reused.scalar(text("SELECT current_setting('app.tenant_id', true)"))
                assert value == tenant_b
    finally:
        await engine.dispose()
