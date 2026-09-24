from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from app.core.config import Settings
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


SECRET = b"test-secret-value-that-is-at-least-thirty-two-bytes"


class FakeTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        if authorization != f"Bearer valid-{expected_client_id}-{required_scope}":
            from app.security import AuthenticationError

            raise AuthenticationError("invalid test token")
        return {
            "azp": expected_client_id,
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "tenant-1",
        }

    async def ready(self) -> bool:
        return True


@pytest.fixture
def test_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ALLOW_IN_MEMORY_STORAGE", "true")
    for producer in (
        "odoo-integration",
        "n8n-automation",
        "vicidial-adapter",
        "telnexa-gateway",
        "klyrow-gateway",
        "kyqra-gateway",
        "postly-adapter",
    ):
        monkeypatch.setenv(
            "WEBHOOK_SECRET_" + producer.upper().replace("-", "_"),
            SECRET.decode(),
        )
    return Settings.from_env()


@pytest.fixture
def runtime(test_settings: Settings) -> Runtime:
    return Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=FakeTokenVerifier(),
    )


def make_event(
    *,
    producer: str,
    event_type: str,
    event_id: str = "evt-00000001",
    tenant_id: str = "tenant-1",
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "event_version": "1.0",
        "occurred_at": "2026-08-26T21:59:59Z",
        "received_at": "2026-08-26T22:00:00Z",
        "source": producer,
        "tenant_id": tenant_id,
        "correlation_id": "corr-00000001",
        "causation_id": "cause-00000001",
        "idempotency_key": event_id,
        "payload": data or {"ok": True},
        "metadata": {},
    }


def signed_headers(
    *,
    path: str,
    producer: str,
    scope: str,
    event: dict[str, Any],
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    timestamp = str(int(time.time()))
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "v1",
            "POST",
            path,
            timestamp,
            event["event_id"],
            producer,
            body_sha,
        )
    ).encode()
    signature = hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
    return body, {
        "Authorization": f"Bearer valid-{producer}-{scope}",
        "Content-Type": "application/json",
        "Idempotency-Key": event["event_id"],
        "X-Codestra-Event-Id": event["event_id"],
        "X-Codestra-Event-Type": event["event_type"],
        "X-Codestra-Source": producer,
        "X-Codestra-Tenant-Id": event["tenant_id"],
        "X-Codestra-Timestamp": timestamp,
        "X-Codestra-Signature": f"sha256={signature}",
        "X-Correlation-Id": event["correlation_id"],
    }
