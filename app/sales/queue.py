"""Recoverable Redis signal queue for the PostgreSQL-authoritative scraper inbox."""

from __future__ import annotations

import json
from collections.abc import Awaitable
from typing import Any, cast
from uuid import UUID

from redis.asyncio import Redis

from app.core.config import settings


class ScraperRedisQueue:
    """Redis wakes workers; PostgreSQL remains the durable source of work."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis
        environment = settings.environment.lower()
        if environment not in {"test", "staging", "production"}:
            raise ValueError("invalid scraper queue environment")
        self.queue_key = f"codestra:{environment}:middleware:scraper:ready"
        self.signal_prefix = f"{self.queue_key}:signal"

    async def enqueue(self, outbox_id: UUID, correlation_id: str) -> bool:
        marker = f"{self.signal_prefix}:{outbox_id}"
        acquired = await self.redis.set(marker, "1", ex=300, nx=True)
        if not acquired:
            return False
        await cast(
            Awaitable[int],
            self.redis.rpush(
                self.queue_key,
                json.dumps(
                    {"outbox_id": str(outbox_id), "correlation_id": correlation_id},
                    separators=(",", ":"),
                ),
            ),
        )
        return True

    async def claim(self, timeout_seconds: int = 1) -> dict[str, Any] | None:
        item = await cast(
            Awaitable[list[Any] | None],
            self.redis.blpop([self.queue_key], timeout=timeout_seconds),
        )
        if not item:
            return None
        signal = json.loads(item[1])
        await self.redis.delete(f"{self.signal_prefix}:{signal['outbox_id']}")
        return signal
