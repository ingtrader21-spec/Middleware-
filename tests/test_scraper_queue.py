from uuid import uuid4
from unittest.mock import Mock
from redis.asyncio import Redis

import pytest

from app.core.config import settings
from app.sales.queue import ScraperRedisQueue


class _Redis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.items: list[str] = []

    async def set(self, key, value, *, ex, nx):
        assert ex == 300 and nx is True
        if key in self.values:
            return False
        self.values[key] = value
        return True

    async def rpush(self, _key, value):
        self.items.append(value)
        return len(self.items)

    async def blpop(self, _keys, *, timeout):
        assert timeout == 1
        return ["queue", self.items.pop(0)] if self.items else None

    async def delete(self, key):
        self.values.pop(key, None)
        return 1


@pytest.mark.asyncio
async def test_scraper_signal_is_namespaced_deduplicated_and_recoverable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "environment", "staging")
    redis = _Redis()
    queue = ScraperRedisQueue(Mock(spec=Redis, wraps=redis))
    item_id = uuid4()
    assert await queue.enqueue(item_id, "correlation") is True
    assert await queue.enqueue(item_id, "correlation") is False
    signal = await queue.claim()
    assert signal == {"outbox_id": str(item_id), "correlation_id": "correlation"}
    assert await queue.enqueue(item_id, "correlation") is True
    assert queue.queue_key == "codestra:staging:middleware:scraper:ready"
