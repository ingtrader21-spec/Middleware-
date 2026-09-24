import asyncio

import httpx
import pytest

from app.integrations.postiz.client import PostizClient
from app.integrations.postiz.exceptions import PostizError
from app.social.adapters import map_postiz_error
from app.social.queue import RedisSocialQueue
from app.core.config import settings


def test_read_timeout_is_unknown_after_send_and_not_blindly_retryable(monkeypatch):
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic ambiguous result", request=request)

    client = PostizClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(client, "base_url", "https://staging.invalid")
    monkeypatch.setattr(
        client,
        "_headers",
        lambda correlation_id=None: {"Authorization": "redacted-test-value"},
    )
    with pytest.raises(PostizError) as error:
        asyncio.run(client.create_post({"content": "test"}, "correlation"))
    normalized = map_postiz_error(error.value)
    assert normalized.code == "SOCIAL_PROVIDER_UNKNOWN_RESULT"
    assert normalized.unknown_result is True
    assert normalized.retryable is False


@pytest.mark.parametrize(
    ("status", "expected_code", "retryable"),
    [
        (401, "SOCIAL_PROVIDER_AUTH_FAILED", False),
        (403, "SOCIAL_PROVIDER_AUTH_FAILED", False),
        (404, "SOCIAL_PUBLISH_FAILED", False),
        (429, "SOCIAL_PROVIDER_RATE_LIMITED", True),
        (500, "SOCIAL_PROVIDER_UNAVAILABLE", True),
        (502, "SOCIAL_PROVIDER_UNAVAILABLE", True),
        (503, "SOCIAL_PROVIDER_UNAVAILABLE", True),
        (504, "SOCIAL_PROVIDER_UNAVAILABLE", True),
    ],
)
def test_postiz_http_failure_matrix(monkeypatch, status, expected_code, retryable):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, request=request)

    client = PostizClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(client, "base_url", "https://staging.invalid")
    monkeypatch.setattr(client, "_headers", lambda correlation_id=None: {})
    with pytest.raises(PostizError) as error:
        asyncio.run(client.create_post({"content": "test"}, "correlation"))
    normalized = map_postiz_error(error.value)
    assert normalized.code == expected_code
    assert normalized.retryable is retryable


@pytest.mark.parametrize("exception", [httpx.ConnectTimeout, httpx.ConnectError])
def test_postiz_pre_send_connection_failure_is_retryable(monkeypatch, exception):
    async def handler(request: httpx.Request) -> httpx.Response:
        raise exception("synthetic pre-send failure", request=request)

    client = PostizClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(client, "base_url", "https://staging.invalid")
    monkeypatch.setattr(client, "_headers", lambda correlation_id=None: {})
    with pytest.raises(PostizError) as error:
        asyncio.run(client.create_post({"content": "test"}, "correlation"))
    normalized = map_postiz_error(error.value)
    assert normalized.code == "SOCIAL_PROVIDER_UNAVAILABLE"
    assert normalized.retryable is True


def test_redis_queue_contains_only_minimal_references():
    class FakeRedis:
        def __init__(self):
            self.values = []

        async def rpush(self, key, value):
            self.values.append((key, value))
            return len(self.values)

    from uuid import uuid4

    redis = FakeRedis()
    job_id = uuid4()
    asyncio.run(RedisSocialQueue(redis).enqueue(job_id, "correlation"))  # type: ignore[arg-type]
    assert str(job_id) in redis.values[0][1]
    assert "content" not in redis.values[0][1]
    assert "account" not in redis.values[0][1]
    assert "token" not in redis.values[0][1]


def test_phase2_runtime_defaults_remain_fail_closed():
    assert settings.social_integration_enabled is False
    assert settings.social_publish_enabled is False
    assert settings.social_provider == "disabled"
    assert settings.social_provider_mode == "single"
    assert settings.social_provider_migration_mode == "disabled"
    assert settings.social_sql_repository_enabled is False
    assert settings.social_worker_enabled is False
    assert settings.social_worker_concurrency == 1
    assert settings.postiz_delivery_enabled is False
    assert settings.hootsuite_enabled is False
    assert settings.social_n8n_events_enabled is False
    assert settings.social_odoo_sync_enabled is False
    assert settings.social_odoo_write_enabled is False
