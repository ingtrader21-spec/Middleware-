from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, AsyncIterator, Protocol

import asyncpg

from app.db.tenant_context import asyncpg_tenant_connection
from .storage import StorageError


@dataclass(frozen=True)
class RealtimePrincipal:
    tenant_id: str
    campaign_id: str
    agent_id: str
    role: str
    expires_at: datetime


@dataclass(frozen=True)
class RealtimeEvent:
    sequence: int
    tenant_id: str
    campaign_id: str
    agent_id: str
    event_type: str
    payload: dict[str, Any]
    occurred_at: datetime

    def ndjson(self) -> bytes:
        return (json.dumps({
            "sequence": self.sequence,
            "tenant_id": self.tenant_id,
            "campaign_id": self.campaign_id,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat(),
        }, separators=(",", ":"), sort_keys=True) + "\n").encode()


class RealtimeStore(Protocol):
    async def consume_ticket(self, ticket: str, now: datetime, tenant_id: str) -> RealtimePrincipal | None: ...
    async def events_after(self, *, tenant_id: str, campaign_id: str,
                           agent_id: str, after: int, limit: int) -> list[RealtimeEvent]: ...
    async def ready(self) -> bool: ...
    async def close(self) -> None: ...


def ticket_sha256(ticket: str) -> str:
    return hashlib.sha256(ticket.encode()).hexdigest()


class MemoryRealtimeStore:
    """Local/test store with the same atomic, one-use behavior as PostgreSQL."""

    def __init__(self) -> None:
        self._tickets: dict[str, tuple[RealtimePrincipal, bool]] = {}
        self._events: list[RealtimeEvent] = []
        self._lock = asyncio.Lock()

    async def issue_for_test(self, ticket: str, principal: RealtimePrincipal) -> None:
        async with self._lock:
            self._tickets[ticket_sha256(ticket)] = (principal, False)

    async def append_for_test(self, event: RealtimeEvent) -> None:
        async with self._lock:
            self._events.append(event)

    async def consume_ticket(self, ticket: str, now: datetime, tenant_id: str) -> RealtimePrincipal | None:
        digest = ticket_sha256(ticket)
        async with self._lock:
            item = self._tickets.get(digest)
            if (
                item is None
                or item[1]
                or item[0].expires_at <= now
                or item[0].tenant_id != tenant_id
            ):
                return None
            self._tickets[digest] = (item[0], True)
            return item[0]

    async def events_after(self, *, tenant_id: str, campaign_id: str,
                           agent_id: str, after: int, limit: int) -> list[RealtimeEvent]:
        async with self._lock:
            return [event for event in self._events if event.sequence > after
                    and event.tenant_id == tenant_id
                    and event.campaign_id == campaign_id
                    and event.agent_id == agent_id][:limit]

    async def ready(self) -> bool: return True
    async def close(self) -> None: return None


class PostgresRealtimeStore:
    def __init__(self, pool: asyncpg.Pool, *, owns_pool: bool = True) -> None:
        self.pool = pool
        # A pool shared through RuntimeContainer is closed by the container.
        self.owns_pool = owns_pool

    @classmethod
    async def connect(cls, database_url: str) -> PostgresRealtimeStore:
        return cls(await asyncpg.create_pool(database_url, min_size=1, max_size=5))

    async def consume_ticket(
        self, ticket: str, now: datetime, tenant_id: str
    ) -> RealtimePrincipal | None:
        try:
            async with asyncpg_tenant_connection(self.pool, tenant_id) as conn:
                row = await conn.fetchrow(
                    """UPDATE middleware_realtime_tickets SET consumed_at=$3
                       WHERE ticket_sha256=$1 AND tenant_id=$2
                         AND consumed_at IS NULL AND expires_at>$3
                       RETURNING tenant_id,campaign_id,agent_id,role,expires_at""",
                    ticket_sha256(ticket), tenant_id, now,
                )
        except Exception as exc:
            raise StorageError("realtime ticket store is unavailable") from exc
        if row is None:
            return None
        return RealtimePrincipal(**dict(row))

    async def events_after(self, *, tenant_id: str, campaign_id: str,
                           agent_id: str, after: int, limit: int) -> list[RealtimeEvent]:
        try:
            async with asyncpg_tenant_connection(self.pool, tenant_id) as conn:
                rows = await conn.fetch(
                    """SELECT sequence,tenant_id,campaign_id,agent_id,event_type,payload,occurred_at
                       FROM middleware_realtime_events
                       WHERE tenant_id=$1 AND campaign_id=$2 AND agent_id=$3 AND sequence>$4
                       ORDER BY sequence LIMIT $5""",
                    tenant_id, campaign_id, agent_id, after, limit,
                )
        except Exception as exc:
            raise StorageError("realtime event store is unavailable") from exc
        return [RealtimeEvent(**dict(row)) for row in rows]

    async def ready(self) -> bool:
        try:
            return await self.pool.fetchval("SELECT to_regclass('middleware_realtime_tickets') IS NOT NULL") is True
        except Exception:
            return False

    async def close(self) -> None:
        if self.owns_pool:
            await self.pool.close()


async def stream_events(store: RealtimeStore, *, tenant_id: str, campaign_id: str,
                        agent_id: str, after: int, disconnected: Any,
                        poll_seconds: float = 1.0) -> AsyncIterator[bytes]:
    cursor = after
    while not await disconnected():
        events = await store.events_after(tenant_id=tenant_id, campaign_id=campaign_id,
                                          agent_id=agent_id, after=cursor, limit=100)
        if events:
            for event in events:
                cursor = event.sequence
                yield event.ndjson()
        else:
            await asyncio.sleep(poll_seconds)
