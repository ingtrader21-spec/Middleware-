from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import httpx
import pytest

from app.runtime_safety import runtime_safety_readback
from scripts.staging_synthetic_acceptance import (
    AcceptanceError,
    REQUIRED_EFFECT_CONTROLS,
    REQUIRED_UMBRELLA_CONTROLS,
    WEBHOOK_PATH,
    build_signed_event,
    run,
    validate_base_url,
    validate_runtime_safety,
)


SOURCE_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + ("b" * 64)


def staging_readback(test_settings) -> dict:
    staging = test_settings.replace(
        app_env="staging",
        runtime_profile_id="codestra-middleware-staging-v1",
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        build_time="2026-08-28T12:00:00Z",
        allow_in_memory_storage=False,
    )
    return runtime_safety_readback(staging)


def test_staging_safety_validator_accepts_exact_fail_closed_release(
    test_settings,
) -> None:
    value = staging_readback(test_settings)
    accepted = validate_runtime_safety(
        value,
        expected_source_sha=SOURCE_SHA,
        expected_image_digest=IMAGE_DIGEST,
    )
    assert set(accepted["external_effects"]) == REQUIRED_EFFECT_CONTROLS
    assert set(accepted["umbrella_controls"]) == REQUIRED_UMBRELLA_CONTROLS


@pytest.mark.parametrize(
    ("path", "unsafe_value"),
    [
        (("environment",), "production"),
        (("persistence", "in_memory"), True),
        (("dispatch", "outbox_enabled"), True),
        (("external_effects", "ODOO_WRITE"), True),
        (("umbrella_controls", "EXTERNAL_DELIVERY_ENABLED"), True),
        (("production_activation_configured",), True),
        (("staging_safe",), False),
    ],
)
def test_staging_safety_validator_rejects_unsafe_runtime_state(
    test_settings,
    path: tuple[str, ...],
    unsafe_value: object,
) -> None:
    value = staging_readback(test_settings)
    target = value
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = unsafe_value
    with pytest.raises(AcceptanceError):
        validate_runtime_safety(
            value,
            expected_source_sha=SOURCE_SHA,
            expected_image_digest=IMAGE_DIGEST,
        )


def test_signed_synthetic_event_uses_canonical_hmac() -> None:
    secret = b"synthetic-test-secret-at-least-thirty-two-bytes"
    fixed_uuid = uuid.UUID("00000000-0000-4000-8000-000000000009")
    event, body, headers = build_signed_event(
        tenant_id="tenant-synthetic",
        secret=secret,
        now=1_788_000_000,
        event_uuid=fixed_uuid,
    )
    assert json.loads(body) == event
    assert event["payload"]["external_effects_expected"] is False
    body_sha = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(
        (
            "v1",
            "POST",
            WEBHOOK_PATH,
            headers["X-Codestra-Timestamp"],
            event["event_id"],
            "odoo-integration",
            body_sha,
        )
    ).encode()
    expected = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    assert headers["X-Codestra-Signature"] == f"sha256={expected}"


def test_staging_base_url_must_be_https_and_cannot_embed_credentials() -> None:
    assert validate_base_url("https://staging.example.test/") == (
        "https://staging.example.test"
    )
    for unsafe in (
        "http://staging.example.test",
        "https://user:secret@staging.example.test",
        "https://staging.example.test/middleware",
        "https://staging.example.test?token=secret",
    ):
        with pytest.raises(AcceptanceError):
            validate_base_url(unsafe)


def test_deployed_acceptance_runner_checks_safety_before_synthetic_event(
    test_settings,
) -> None:
    safety = staging_readback(test_settings)
    calls: list[str] = []
    accepted_event: dict | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal accepted_event
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == "/v1/runtime/safety":
            assert request.headers["Authorization"] == "Bearer monitoring-token"
            return httpx.Response(200, json=safety)
        if request.url.path == "/ready":
            return httpx.Response(
                200,
                json={
                    "status": "ready",
                    "release_sha": SOURCE_SHA,
                    "image_digest": IMAGE_DIGEST,
                    "components": {
                        "inbox_store": "ready",
                        "replay_guard": "ready",
                        "identity_jwks": "ready",
                        "command_store": "ready",
                    },
                },
            )
        assert request.url.path == "/api/v1/odoo/events"
        assert request.headers["Authorization"] == "Bearer producer-token"
        current = json.loads(request.content)
        if accepted_event is None:
            accepted_event = current
            return httpx.Response(
                202,
                json={
                    "event_id": current["event_id"],
                    "tenant_id": current["tenant_id"],
                    "status": "accepted",
                    "duplicate": False,
                    "correlation_id": current["correlation_id"],
                },
            )
        assert current == accepted_event
        return httpx.Response(
            200,
            json={
                "event_id": current["event_id"],
                "tenant_id": current["tenant_id"],
                "status": "duplicate",
                "duplicate": True,
                "correlation_id": current["correlation_id"],
            },
        )

    result = run(
        {
            "STAGING_BASE_URL": "https://middleware-staging.example.test",
            "STAGING_MONITORING_TOKEN": "monitoring-token",
            "STAGING_ODOO_PRODUCER_TOKEN": "producer-token",
            "STAGING_ODOO_WEBHOOK_SECRET": (
                "staging-webhook-secret-at-least-thirty-two-bytes"
            ),
            "STAGING_SYNTHETIC_TENANT_ID": "tenant-synthetic",
            "EXPECTED_SOURCE_SHA": SOURCE_SHA,
            "EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
        },
        transport=httpx.MockTransport(handler),
    )

    assert result["status"] == "passed"
    assert result["source_sha"] == SOURCE_SHA
    assert calls == [
        "GET /v1/runtime/safety",
        "GET /ready",
        "POST /api/v1/odoo/events",
        "POST /api/v1/odoo/events",
    ]
