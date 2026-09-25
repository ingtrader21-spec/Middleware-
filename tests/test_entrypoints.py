import subprocess
import sys
from uuid import UUID

from fastapi.testclient import TestClient

from app.core.config import settings
from app.entrypoints import (
    event_gateway,
    extension_allocator,
    integration_api,
    notification_worker,
    pjsip_adapter,
    policy_engine,
    scheduler,
    sync_worker,
    telephony_provisioning,
    vicidial_adapter,
    webphone_session_issuer,
)
from app.entrypoints.runtime import worker_app
from app.core.config import CANONICAL_SCHEMA_HEAD


def route_paths(app):
    return set(app.openapi()["paths"])


def test_api_surfaces_are_narrow_and_cover_existing_routes():
    event_paths = route_paths(event_gateway.app)
    integration_paths = route_paths(integration_api.app)
    assert "/api/v1/events/vicidial" in event_paths
    assert "/api/v2/telephony/canary" in event_paths
    assert "/api/v1/automation/events" in integration_paths
    # AUTH-01: tenantless legacy telephony journal routes are retired from the
    # deployed integration API. The canonical tenant-bound command kernel is
    # the only command authority exposed by this profile.
    for retired in (
        "/api/v1/commands",
        "/api/v1/commands/{command_public_id}",
        "/api/v1/telephony/commands",
        "/api/v1/telephony/commands/{command_public_id}",
        "/api/v1/telephony/commands/{command_public_id}/cancel",
        "/api/v1/telephony/operations",
        "/api/v1/telephony/operations/{operation_public_id}",
        "/api/v1/telephony/operations/{operation_public_id}/transitions",
        "/api/v1/telephony/results",
        "/api/v1/telephony/results/{result_public_id}",
        "/api/v1/telephony/reconciliation/runs",
        "/api/v1/telephony/reconciliation/runs/{run_public_id}",
    ):
        assert retired not in integration_paths

    assert "/platform/v1/commands" in integration_paths
    assert "/platform/v1/operations/{operation_id}" in integration_paths
    assert "/platform/v1/operations/{operation_id}/timeline" in integration_paths
    assert "/platform/v1/operations/{operation_id}/cancel" in integration_paths
    assert "/platform/v1/operations/{operation_id}/replay" in integration_paths
    assert "/api/v1/lead-automation/results" in integration_paths
    assert "/api/v1/lead-automation/events/{automation_event_id}" in integration_paths
    assert "/api/v1/integrations/n8n/results" in integration_paths
    assert "/webphone-api/v1/session" in integration_paths
    assert route_paths(policy_engine.app) >= {
        "/health",
        "/api/v1/policy/decisions",
        "/healthz",
        "/ready",
        "/readyz",
        "/version",
        "/capabilities",
        "/dependencies",
    }
    assert "/api/v1/events/vicidial" not in route_paths(policy_engine.app)
    assert "/v1/telephony/extensions/reserve" in route_paths(extension_allocator.app)
    assert "/v1/telephony/provisioning" not in route_paths(extension_allocator.app)
    assert "/v1/telephony/provisioning" in route_paths(telephony_provisioning.app)
    assert "/v1/telephony/extensions/reserve" not in route_paths(
        telephony_provisioning.app
    )
    assert "/webphone-api/v1/session" in route_paths(webphone_session_issuer.app)


def test_integration_api_registers_the_exact_telnexa_callback_in_fresh_runtime():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from app.entrypoints.integration_api import app;"
                "paths=app.openapi()['paths'];"
                "assert '/api/v1/events/telnexa' in paths;"
                "assert '/api/v1/events/vicidial' not in paths"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_api_runtime_health_and_correlation(monkeypatch):
    monkeypatch.setattr(settings, "middleware_secret", "unit-test-secret")
    client = TestClient(event_gateway.app)
    # A well-formed client correlation id is echoed for end-to-end tracing;
    # anything else is replaced by a fresh UUID so log injection is impossible.
    echoed = client.get("/healthz", headers={"X-Correlation-ID": "synthetic-correlation"})
    assert echoed.status_code == 200
    assert echoed.headers["X-Correlation-ID"] == "synthetic-correlation"
    assert echoed.headers["Traceparent"].startswith("00-")
    replaced = client.get("/healthz", headers={"X-Correlation-ID": "bad value with spaces"})
    assert replaced.status_code == 200
    assert replaced.headers["X-Correlation-ID"] != "bad value with spaces"
    UUID(replaced.headers["X-Correlation-ID"])
    generated = client.get("/healthz")
    UUID(generated.headers["X-Correlation-ID"])


def test_api_runtime_logs_trusted_kong_request_id(monkeypatch, caplog):
    monkeypatch.setattr(settings, "middleware_secret", "unit-test-secret")
    gateway_request_id = "8a9bb119-78b5-4d97-b221-cf86e77ac115"
    with caplog.at_level("INFO", logger="codestra.runtime"):
        response = TestClient(event_gateway.app).get(
            "/healthz", headers={"X-Kong-Request-Id": gateway_request_id}
        )
    assert response.status_code == 200
    assert any(
        getattr(record, "gateway_request_id", None) == gateway_request_id
        for record in caplog.records
    )


def test_api_runtime_readiness_fails_when_required_database_is_unavailable(
    monkeypatch,
):
    from app.core import health

    async def probe(_settings, *, engine=None):
        return {"postgres": "unavailable", "redis": "online", "keycloak": "online"}

    monkeypatch.setattr(health, "dependency_states", probe)
    response = TestClient(integration_api.app).get("/readyz")
    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"


def test_narrow_service_readiness_requires_database_when_declared(monkeypatch):
    from app.core import health

    async def probe(_settings, *, engine=None):
        return {"postgres": "unavailable", "redis": "not_probed", "keycloak": "not_probed"}

    monkeypatch.setattr(settings, "health_require_database", True)
    monkeypatch.setattr(health, "dependency_states", probe)
    response = TestClient(policy_engine.app).get("/readyz")
    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"


def test_api_runtime_readiness_documents_optional_database(monkeypatch):
    monkeypatch.setattr(settings, "health_require_database", False)
    response = TestClient(policy_engine.app).get("/readyz")
    assert response.status_code == 200
    assert response.json()["database"] == "not-required"


def test_api_runtime_version_is_safe_and_immutable():
    from app.application import create_app
    from app.core.config import Settings

    # Release labels come from the canonical settings (APP_SOURCE_SHA, with
    # SOURCE_SHA accepted as the former entrypoint name), never from ad-hoc
    # environment reads at request time.
    app = create_app(
        settings=Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "SOURCE_SHA": "a" * 40,
                "RELEASE_ID": "release-20260823",
                "IMAGE_DIGEST": "sha256:" + "b" * 64,
            }
        ),
        service="middleware-integration-api",
    )
    response = TestClient(app).get("/version")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "middleware-integration-api"
    assert body["source_sha"] == "a" * 40
    assert body["git_sha"] == "a" * 40
    assert body["release_id"] == "release-20260823"
    assert body["image_digest"] == "sha256:" + "b" * 64
    assert body["schema_head"] == CANONICAL_SCHEMA_HEAD
    assert "://" not in response.text and "secret" not in response.text.lower()


def test_api_runtime_capabilities_read_back_fail_closed_settings(monkeypatch):
    monkeypatch.setattr(settings, "live_writes_enabled", False)
    monkeypatch.setattr(settings, "enable_external_delivery", False)
    monkeypatch.setattr(settings, "allow_live_email", False)
    monkeypatch.setattr(settings, "allow_live_sms", False)
    monkeypatch.setattr(settings, "external_dial_enabled", False)
    monkeypatch.setattr(settings, "social_publish_enabled", False)
    response = TestClient(integration_api.app).get("/capabilities")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Correlation-ID"]
    assert response.json()["business_writes_enabled"] is False
    assert response.json()["external_delivery_enabled"] is False
    assert response.json()["live_email_enabled"] is False
    assert response.json()["live_sms_enabled"] is False
    assert response.json()["live_pstn_enabled"] is False
    assert response.json()["live_social_publish_enabled"] is False


def test_disabled_delivery_workers_do_not_claim_or_contact_adapters(monkeypatch):
    monkeypatch.setattr(settings, "odoo_delivery_enabled", False)
    monkeypatch.setattr(settings, "n8n_delivery_enabled", False)
    monkeypatch.setattr(settings, "messaging_enabled", False)
    assert __import__("asyncio").run(sync_worker.cycle()) == {"status": "disabled"}
    assert __import__("asyncio").run(notification_worker.cycle()) == {
        "status": "disabled"
    }


def test_canonical_broad_event_flags_default_closed_and_require_conjunction(
    monkeypatch,
):
    canonical = (
        "broad_event_send_enabled",
        "broad_event_delivery_enabled",
        "production_n8n_enabled",
        "n8n_production_workflows_enabled",
    )
    for name in canonical:
        monkeypatch.setattr(settings, name, False)
    assert settings.broad_event_pipeline_enabled is False

    for name in canonical:
        monkeypatch.setattr(settings, name, True)
    assert settings.broad_event_pipeline_enabled is True
    assert settings.enable_external_delivery is False


def test_broad_event_activation_fails_closed_without_exact_bounded_scope(
    monkeypatch,
):
    canonical = (
        "broad_event_send_enabled",
        "broad_event_delivery_enabled",
        "production_n8n_enabled",
        "n8n_production_workflows_enabled",
    )
    for name in canonical:
        monkeypatch.setattr(settings, name, True)
    monkeypatch.setattr(settings, "controlled_broad_event_activation", False)
    try:
        settings.validate_safety()
    except ValueError as exc:
        assert "bounded explicit scope" in str(exc)
    else:
        raise AssertionError("unscoped broad-event activation must be rejected")


def test_broad_event_activation_accepts_only_bounded_internal_scope(monkeypatch):
    canonical = (
        "broad_event_send_enabled",
        "broad_event_delivery_enabled",
        "production_n8n_enabled",
        "n8n_production_workflows_enabled",
    )
    for name in canonical:
        monkeypatch.setattr(settings, name, True)
    monkeypatch.setattr(settings, "controlled_broad_event_activation", True)
    monkeypatch.setattr(settings, "broad_event_business_unit_allowlist", "BU-400-COD")
    monkeypatch.setattr(settings, "broad_event_campaign_allowlist", "CMP-400-COD")
    monkeypatch.setattr(settings, "broad_event_workflow_allowlist", "existing-id")
    monkeypatch.setattr(settings, "broad_event_type_allowlist", "existing.event")
    monkeypatch.setattr(
        settings, "broad_event_activation_high_water_mark", "2026-07-29T00:00:00Z"
    )
    monkeypatch.setattr(settings, "broad_event_submission_limit", 3)
    monkeypatch.setattr(settings, "enable_external_delivery", False)
    settings.validate_safety()


def test_disabled_scheduler_is_safe(monkeypatch):
    monkeypatch.setattr(settings, "outbox_worker_enabled", False)
    assert __import__("asyncio").run(scheduler.cycle()) == {"status": "disabled"}


def test_telephony_adapters_are_independently_kill_switched(monkeypatch):
    monkeypatch.setattr(settings, "vicidial_provisioning_enabled", False)
    monkeypatch.setattr(settings, "pjsip_provisioning_enabled", False)
    assert __import__("asyncio").run(vicidial_adapter.cycle()) == {
        "result": "kill_switch_closed"
    }
    assert __import__("asyncio").run(pjsip_adapter.cycle()) == {
        "result": "kill_switch_closed"
    }


def test_worker_has_internal_operational_endpoints():
    app = worker_app("test-worker", "test.queue.v1", sync_worker.cycle)
    paths = route_paths(app)
    assert {
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/version",
        "/capabilities",
        "/dependencies",
    } <= paths
    with TestClient(app) as client:
        health = client.get("/healthz")
        readiness = client.get("/readyz")
        assert health.json()["stopping"] is False
        assert readiness.json()["status"] == "ready"
        assert readiness.json()["queue"] == "test.queue.v1"
        assert health.headers["Cache-Control"] == "no-store"
        assert health.headers["X-Correlation-ID"]
