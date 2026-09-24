from __future__ import annotations

import json
import secrets
from collections.abc import Awaitable
from typing import Any, cast
from uuid import UUID

from redis.asyncio import Redis

from app.social.providers import SocialError


def retry_delay(
    attempt: int, base_seconds: int = 5, maximum_seconds: int = 300
) -> float:
    if attempt < 1:
        raise ValueError("attempt must be positive")
    ceiling = min(maximum_seconds, base_seconds * (2 ** (attempt - 1)))
    return ceiling * secrets.SystemRandom().uniform(0.5, 1.0)


def classify_failure(error: BaseException) -> str:
    if isinstance(error, SocialError) and error.retryable:
        return "retry"
    return "dead_letter"


class RedisSocialQueue:
    """Small Redis transport; PostgreSQL social_publish_jobs remains source of truth."""

    queue_key = "codestra:social:jobs"
    dead_letter_key = "codestra:social:dead-letter"

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def enqueue(self, job_id: UUID, correlation_id: str) -> None:
        await cast(
            Awaitable[int],
            self.redis.rpush(
                self.queue_key,
                json.dumps({"job_id": str(job_id), "correlation_id": correlation_id}),
            ),
        )

    async def claim(self, timeout_seconds: int = 1) -> dict[str, Any] | None:
        item = await cast(
            Awaitable[list[Any] | None],
            self.redis.blpop([self.queue_key], timeout=timeout_seconds),
        )
        return json.loads(item[1]) if item else None

    async def dead_letter(
        self, job_id: UUID, error_code: str, correlation_id: str
    ) -> None:
        await cast(
            Awaitable[int],
            self.redis.rpush(
                self.dead_letter_key,
                json.dumps(
                    {
                        "job_id": str(job_id),
                        "error_code": error_code,
                        "correlation_id": correlation_id,
                    }
                ),
            ),
        )
