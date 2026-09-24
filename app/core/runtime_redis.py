"""Best-effort Redis coordination; PostgreSQL remains authoritative."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.metrics import REDIS_ERRORS, REDIS_LATENCY


class RedisKeyType(StrEnum):
    LOCK = "lock"
    REPLAY = "replay"
    RATE = "rate"
    TOKEN = "token"  # nosec B105
    DEDUPE = "dedupe"
    EXECUTION = "execution"
    CIRCUIT = "circuit"


TTL_SECONDS = {
    RedisKeyType.LOCK: 60,
    RedisKeyType.REPLAY: 600,
    RedisKeyType.RATE: 60,
    RedisKeyType.TOKEN: 300,
    RedisKeyType.DEDUPE: 3600,
    RedisKeyType.EXECUTION: 900,
    RedisKeyType.CIRCUIT: 300,
}


def runtime_key(kind: RedisKeyType, *parts: str) -> str:
    clean = []
    for part in parts:
        if not part or any(
            char
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for char in part
        ):
            raise ValueError("unsafe Redis key component")
        clean.append(part)
    environment = settings.redis_runtime_environment.lower()
    if environment not in {"test", "staging", "production"}:
        raise ValueError("invalid Redis runtime environment")
    owner = "n8n" if kind is RedisKeyType.EXECUTION else "middleware"
    return ":".join(
        (settings.redis_runtime_prefix, environment, owner, kind.value, *clean)
    )


@dataclass(frozen=True)
class CoordinationResult:
    acquired: bool
    degraded: bool


class RedisCoordinator:
    """All writes have a TTL and every failure safely degrades to PostgreSQL."""

    def __init__(self, client: Redis | None = None) -> None:
        self.client = client

    async def reserve(
        self, kind: RedisKeyType, value: str, *parts: str
    ) -> CoordinationResult:
        if not settings.redis_runtime_enabled or self.client is None:
            return CoordinationResult(True, True)
        started = time.perf_counter()
        try:
            acquired = bool(
                await self.client.set(
                    runtime_key(kind, *parts),
                    value,
                    ex=TTL_SECONDS[kind],
                    nx=True,
                )
            )
            return CoordinationResult(acquired, False)
        except RedisError:
            REDIS_ERRORS.labels(operation="reserve").inc()
            return CoordinationResult(True, True)
        finally:
            REDIS_LATENCY.labels(operation="reserve").observe(
                time.perf_counter() - started
            )

    async def close(self) -> None:
        if self.client is not None:
            await self.client.aclose()
