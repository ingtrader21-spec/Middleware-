from __future__ import annotations

import hashlib
import inspect
import json
import secrets
from typing import Protocol

from redis.asyncio import Redis


class ReplayBusy(RuntimeError):
    pass


class ReplayGuard(Protocol):
    async def acquire(self, tenant_id: str, event_id: str) -> str:
        ...

    async def release(self, tenant_id: str, event_id: str, token: str) -> None:
        ...

    async def ready(self) -> bool:
        ...

    async def close(self) -> None:
        ...


class MemoryReplayGuard:
    def __init__(self) -> None:
        self._held: set[tuple[str, str]] = set()

    async def acquire(self, tenant_id: str, event_id: str) -> str:
        key = (tenant_id, event_id)
        if key in self._held:
            raise ReplayBusy("event is already being processed")
        self._held.add(key)
        return "memory"

    async def release(self, tenant_id: str, event_id: str, token: str) -> None:
        self._held.discard((tenant_id, event_id))

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class RedisReplayGuard:
    _RELEASE_SCRIPT = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
      return redis.call('del', KEYS[1])
    end
    return 0
    """

    def __init__(
        self, client: Redis, *, lock_seconds: int = 30, owns_client: bool = True
    ) -> None:
        self.client = client
        self.lock_seconds = lock_seconds
        # A client shared through RuntimeContainer is closed by the container.
        self.owns_client = owns_client

    @classmethod
    async def connect(cls, redis_url: str) -> "RedisReplayGuard":
        client = Redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
        guard = cls(client)
        if not await guard.ready():
            await client.aclose()
            raise RuntimeError("Redis is not reachable")
        return guard

    def _key(self, tenant_id: str, event_id: str) -> str:
        material = json.dumps(
            [tenant_id, event_id],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(material).hexdigest()
        return f"middleware:inbox-lock:{digest}"

    async def acquire(self, tenant_id: str, event_id: str) -> str:
        token = secrets.token_urlsafe(24)
        ok = await self.client.set(
            self._key(tenant_id, event_id),
            token,
            ex=self.lock_seconds,
            nx=True,
        )
        if not ok:
            raise ReplayBusy("event is already being processed")
        return token

    async def release(self, tenant_id: str, event_id: str, token: str) -> None:
        result = self.client.eval(
            self._RELEASE_SCRIPT,
            1,
            self._key(tenant_id, event_id),
            token,
        )
        if not inspect.isawaitable(result):
            raise TypeError("replay guard requires an asynchronous Redis client")
        await result

    async def ready(self) -> bool:
        try:
            return bool(await self.client.ping())
        except Exception:
            return False

    async def close(self) -> None:
        if self.owns_client:
            await self.client.aclose()
