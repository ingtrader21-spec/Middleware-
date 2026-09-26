"""Shared PostgreSQL tenant-context primitives.

Tenant identity is validated by the authentication/authorization layer before
these helpers are called. These functions only normalize the already-authorized
identifier and bind it to the *current transaction* using PostgreSQL set_config
with is_local=true. They never create connection-persistent tenant state.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

TENANT_CONTEXT_GUC = "app.tenant_id"
TENANT_CONTEXT_INFO_KEY = "codestra.tenant_id"


def canonical_tenant_id(tenant_id: str | UUID) -> str:
    """Normalize a bounded tenant identifier without assuming one SQL type."""
    value = str(tenant_id).strip()
    if not value:
        raise ValueError("tenant_id is required")
    if len(value) > 128:
        raise ValueError("tenant_id exceeds 128 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("tenant_id contains control characters")
    return value


async def set_asyncpg_transaction_tenant_context(
    connection: Any,
    tenant_id: str | UUID,
) -> str:
    """Bind one authorized tenant to an already-open asyncpg transaction."""
    normalized = canonical_tenant_id(tenant_id)
    is_in_transaction = getattr(connection, "is_in_transaction", None)
    if callable(is_in_transaction) and not is_in_transaction():
        raise RuntimeError("tenant context requires an active PostgreSQL transaction")
    await connection.execute(
        "SELECT set_config('app.tenant_id',$1,true)",
        normalized,
    )
    return normalized


@asynccontextmanager
async def asyncpg_tenant_connection(
    pool: Any,
    tenant_id: str | UUID,
) -> AsyncIterator[Any]:
    """Acquire an asyncpg connection and open a tenant-bound transaction."""
    async with pool.acquire() as connection:
        async with connection.transaction():
            await set_asyncpg_transaction_tenant_context(connection, tenant_id)
            yield connection
