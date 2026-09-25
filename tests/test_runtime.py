from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from app.contracts import ROUTE_BY_PATH, WEBHOOK_ROUTES
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime, _asyncpg_dsn
from app.runtime_safety import runtime_safety_readback
from app.storage import MemoryInboxStore

from .conftest import FakeTokenVerifier, make_event, signed_headers


def test_all_contract_routes_are_registered(test_settings, runtime) -> None:
    app = create_app(settings=test_settings, runtime=runtime)
    registered = {
        path
        for path, operations in app.openapi()["paths"].items()
        if "post" in operations
        and path.startswith("/api/v1/")
        and operations["post"]["operationId"].startswith("ingress_")
    }
    assert registered == {item.path for item in WEBHOOK_ROUTES}


def test_accept_and_idempotent_duplicate(test_settings, runtime) -> None:
    path = "/api/v1/odoo/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        first = client.post(path, content=body, headers=headers)
        assert first.status_code == 202, first.text
        assert first.json()["duplicate"] is False

        second = client.post(path, content=body, headers=headers)
        assert second.status_code == 200, second.text
        assert second.json()["duplicate"] is True


def test_accepts_sdk_call_disposition_event_on_vicidial_route(
    test_settings, runtime
) -> None:
    path = "/api/v1/vicidial/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type="codestra.events.call_disposition_updated",
        data={
            "event_type": "call_disposition_updated",
            "correlation_id": "11111111-1111-4111-8111-111111111111",
            "causation_id": "1745850000.42",
            "odoo_contact_id": 4301,
            "odoo_lead_id": None,
            "disposition": "sale_completed",
            "phone_number": "+15551234567",
            "duration_seconds": 180,
            "campaign_id": "campaign-alpha",
            "provider_call_id": "1745850000.42",
            "dry_run": False,
        },
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)

    assert response.status_code == 202, response.text


def test_accepts_sdk_sms_received_event_on_telnexa_route(
    test_settings, runtime
) -> None:
    path = "/api/v1/telnexa/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type="codestra.events.sms_received",
        data={
            "event_type": "sms_received",
            "correlation_id": "22222222-2222-4222-8222-222222222222",
            "causation_id": "telnexa-message-123",
            "odoo_contact_id": 4301,
            "odoo_message_id": None,
            "from_number": "+15557654321",
            "body_preview": "Reply received",
            "provider_event_id": "telnexa-message-123",
            "dry_run": False,
        },
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)

    assert response.status_code == 202, response.text


def test_semantically_identical_reformatted_retry_is_duplicate(
    test_settings, runtime
) -> None:
    path = "/api/v1/odoo/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        assert client.post(path, content=body, headers=headers).status_code == 202
        # A producer retry may serialize equivalent JSON differently. Re-sign the new raw body.
        import hashlib
        import hmac
        import json
        import time
        from .conftest import SECRET

        pretty = json.dumps(event, indent=2, sort_keys=False).encode()
        timestamp = str(int(time.time()))
        body_sha = hashlib.sha256(pretty).hexdigest()
        canonical = "\n".join(
            (
                "v1",
                "POST",
                path,
                timestamp,
                event["event_id"],
                route.producer_client_id,
                body_sha,
            )
        ).encode()
        signature = hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
        retry_headers = dict(headers)
        retry_headers["X-Codestra-Timestamp"] = timestamp
        retry_headers["X-Codestra-Signature"] = f"sha256={signature}"
        response = client.post(path, content=pretty, headers=retry_headers)
        assert response.status_code == 200, response.text
        assert response.json()["duplicate"] is True


def test_same_event_id_with_changed_payload_conflicts(test_settings, runtime) -> None:
    path = "/api/v1/n8n/results"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        assert client.post(path, content=body, headers=headers).status_code == 202

        changed = {**event, "payload": {"ok": False}}
        changed_body, changed_headers = signed_headers(
            path=path,
            producer=route.producer_client_id,
            scope=route.required_scope,
            event=changed,
        )
        response = client.post(path, content=changed_body, headers=changed_headers)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "idempotency_conflict"


def test_invalid_signature_is_rejected_with_canonical_error(
    test_settings, runtime
) -> None:
    path = "/api/v1/vicidial/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    headers["X-Codestra-Signature"] = "sha256=" + ("0" * 64)
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 401
        error = response.json()["error"]
        assert error["code"] == "webhook_signature_invalid"
        assert error["correlation_id"] == event["correlation_id"]
        assert error["retryable"] is False
        assert error["details"] == {}


def test_body_and_header_tenant_must_match(test_settings, runtime) -> None:
    path = "/api/v1/telnexa/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    headers["X-Codestra-Tenant-Id"] = "other-tenant"
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 400


def test_cross_tenant_token_is_rejected(test_settings) -> None:
    class WrongTenantVerifier(FakeTokenVerifier):
        async def verify(self, authorization, *, expected_client_id, required_scope):
            claims = await super().verify(
                authorization,
                expected_client_id=expected_client_id,
                required_scope=required_scope,
            )
            claims["tenant_id"] = "different-tenant"
            return claims

    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=WrongTenantVerifier(),
    )
    path = "/api/v1/klyrow/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "authorization_denied"


def test_actor_schema_fails_closed(test_settings, runtime) -> None:
    path = "/api/v1/kyqra/results"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
    )
    event["actor"] = {"type": "root", "id": "x", "unexpected": True}
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_request"


def test_oversized_body_is_rejected_before_buffering(test_settings, runtime) -> None:
    limited = test_settings.replace(max_request_body_bytes=1024)
    runtime.settings = limited
    path = "/api/v1/postly/events"
    route = ROUTE_BY_PATH[path]
    event = make_event(
        producer=route.producer_client_id,
        event_type=sorted(route.event_types)[0],
        data={"padding": "x" * 2000},
    )
    body, headers = signed_headers(
        path=path,
        producer=route.producer_client_id,
        scope=route.required_scope,
        event=event,
    )
    app = create_app(settings=limited, runtime=runtime)
    with TestClient(app) as client:
        response = client.post(path, content=body, headers=headers)
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "payload_too_large"


def test_health_ready_version(test_settings, runtime) -> None:
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "service": "middleware-api",
            "component": "api",
        }
        readiness = client.get("/ready")
        assert readiness.status_code == 200
        assert readiness.json()["status"] == "ready"
        assert readiness.json()["components"] == {
            "inbox_store": "ready",
            "replay_guard": "ready",
            "identity_jwks": "ready",
            "command_store": "not_configured",
            "communications_store": "not_configured",
            "incident_store": "not_configured",
            "automation_store": "not_configured",
        }
        assert "checked_at" in readiness.json()
        assert (
            client.get("/readiness").json()["components"]
            == readiness.json()["components"]
        )
        dependencies = client.get("/dependencies")
        assert dependencies.status_code == 200
        assert dependencies.json()["dependencies"] == readiness.json()["components"]
        version = client.get("/version").json()
        assert version["service"] == "middleware-api"
        assert version["environment"] == "test"
        assert version["runtime_profile_id"] == "local-unlocked"
        assert version["schema_head"] == "0069_campaign_recycling_delivery_events"
        assert version["git_sha"] == version["source_sha"]
        assert version["schema_version"] == version["schema_head"]
        assert {
            "release_id",
            "image_digest",
            "build_timestamp",
            "configuration_checksum",
        } <= set(version)
        capabilities = client.get("/capabilities")
        assert capabilities.status_code == 200
        assert capabilities.json()["capabilities"]["PRODUCTION_DIALING"] is False
        assert capabilities.json()["capabilities"]["LIVE_ADVERTISING_ENABLED"] is False


def test_runtime_safety_readback_is_authenticated_and_schema_valid(
    test_settings,
    runtime,
) -> None:
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        denied = client.get("/v1/runtime/safety")
        accepted = client.get(
            "/v1/runtime/safety",
            headers={"Authorization": ("Bearer valid-monitoring-readonly-health.read")},
        )

    assert denied.status_code == 401
    assert accepted.status_code == 200
    value = accepted.json()
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "contracts"
            / "runtime-safety-readback.v1.1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(value)
    assert value["environment"] == "test"
    assert value["provider_effects_disabled"] is True
    assert value["all_external_effects_disabled"] is True
    assert value["umbrella_controls"] == {
        "EXTERNAL_DELIVERY_ENABLED": False,
        "EXTERNAL_MODEL_CALLS_ENABLED": False,
        "LIVE_ADVERTISING_ENABLED": False,
        "N8N_EXTERNAL_PROVIDER_WRITES": False,
        "SOCIAL_PUBLISHING_ENABLED": False,
    }
    assert value["staging_safe"] is False
    assert "test-secret-value" not in accepted.text


def test_runtime_safety_readback_proves_fail_closed_staging(
    test_settings,
    runtime,
) -> None:
    staging = test_settings.replace(
        app_env="staging",
        runtime_profile_id="codestra-middleware-staging-v1",
        source_sha="a" * 40,
        image_digest="sha256:" + ("b" * 64),
        build_time="2026-08-28T12:00:00Z",
        allow_in_memory_storage=False,
    )
    runtime.settings = staging
    app = create_app(settings=staging, runtime=runtime)
    with TestClient(app) as client:
        response = client.get(
            "/v1/runtime/safety",
            headers={"Authorization": ("Bearer valid-monitoring-readonly-health.read")},
        )

    assert response.status_code == 200
    value = response.json()
    assert value["staging_safe"] is True
    assert value["dispatch"] == {
        "outbox_enabled": False,
        "nats_mode": "disabled",
        "temporal_worker_mode": "disabled",
    }
    assert value["production_activation_configured"] is False
    assert not any(value["external_effects"].values())
    assert not any(value["umbrella_controls"].values())


def test_runtime_safety_aggregate_summaries_include_umbrella_controls(
    test_settings,
) -> None:
    enabled = test_settings.replace(umbrella_external_delivery_enabled=True)

    value = runtime_safety_readback(enabled)

    assert value["umbrella_controls"]["EXTERNAL_DELIVERY_ENABLED"] is True
    assert value["provider_effects_disabled"] is False
    assert value["all_external_effects_disabled"] is False


def test_runtime_discovery_allowlists_every_umbrella_control() -> None:
    discovery = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "discover_middleware_runtime.sh"
    ).read_text(encoding="utf-8")
    allowlist = discovery.partition("safe_controls=")[2].partition(
        "printf '\\nCOMPOSE_PROJECTS\\n'"
    )[0]
    assert allowlist
    for name in (
        "LIVE_ADVERTISING_ENABLED",
        "EXTERNAL_DELIVERY_ENABLED",
        "SOCIAL_PUBLISHING_ENABLED",
        "EXTERNAL_MODEL_CALLS_ENABLED",
        "N8N_EXTERNAL_PROVIDER_WRITES",
    ):
        assert name in allowlist


def test_readiness_reports_named_failure_without_dependency_details(
    test_settings,
    runtime,
) -> None:
    class UnavailableReplayGuard(MemoryReplayGuard):
        async def ready(self) -> bool:
            return False

    runtime.replay = UnavailableReplayGuard()
    app = create_app(settings=test_settings, runtime=runtime)
    with TestClient(app) as client:
        response = client.get("/ready")

    assert response.status_code == 503
    value = response.json()
    assert value["status"] == "not-ready"
    assert value["components"]["replay_guard"] == "not_ready"
    assert value["dependencies"]["redis"] == "unavailable"
    assert value["reason"] == "components_not_ready:replay_guard"
    # Dependency *states* are named; addresses and credentials never are.
    assert "localhost" not in response.text.lower()
    assert "://" not in response.text


def test_asyncpg_dsn_normalizes_sqlalchemy_asyncpg_scheme() -> None:
    assert (
        _asyncpg_dsn("postgresql+asyncpg://user:secret@db:5432/middleware")
        == "postgresql://user:secret@db:5432/middleware"
    )
    assert (
        _asyncpg_dsn("postgresql://user:secret@db:5432/middleware")
        == "postgresql://user:secret@db:5432/middleware"
    )
