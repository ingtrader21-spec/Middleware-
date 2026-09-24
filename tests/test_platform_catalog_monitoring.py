"""Service catalog monitoring state: desired identity, runtime evidence, certification, secret references."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db import session as database_session
from app.entrypoints.integration_api import app
from app.platform_catalog_monitoring import (
    CertificationEvidence,
    certification_blockers,
    compare,
    derive_state,
    freshness,
)

ISSUER = "https://identity.example.invalid/realms/platform-test"
AUDIENCE = "platform-test-api"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
GIT = "a" * 40
IMAGE = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64
REFERENCE = {
    "provider": "openbao", "environment": "staging", "service_id": "sample-api",
    "secret_ref": "codestra/staging/sample/api/database", "secret_class": "database_credentials",
    "version": None, "workload_identity": "sample-api",
}
SERVICE = {
    "service_id": "sample-api", "owner": "platform", "tenant_mode": "multi-tenant",
    "type": "api", "repository": "ingtrader21-spec/sample-api", "environments": ["staging"],
    "dependencies": [], "data_classification": "confidential", "slo_profile": "customer-api",
    "alert_profile": "business-critical",
    "deployment_id": "sample-api-staging-1", "host_id": "core-01", "private_origin": "http://sample-api:8080",
    "liveness_path": "/health/live", "readiness_path": "/health/ready",
    "metrics_profile": "prometheus", "logs_profile": "alloy", "traces_profile": "otel",
    "prometheus_target_id": "sample-api-staging", "grafana_dashboard_ids": ["sample-api-overview"],
    "expected_git_sha": GIT, "expected_image_digest": IMAGE, "expected_config_digest": CONFIG,
    "secret_references": [REFERENCE],
}


def row(**overrides):
    base = {
        "id": "00000000-0000-0000-0000-000000000001", "service_id": "sample-api", "owner": "platform", "state": "registered",
        "environments": ["staging"], "dependencies": [], "slo_profile": "customer-api", "alert_profile": "business-critical",
        "monitoring_state": "registered", "monitoring_state_reason": "", "metrics_profile": "prometheus",
        "logs_profile": "alloy", "traces_profile": "otel", "prometheus_target_id": "sample-api-staging",
        "grafana_dashboard_ids": ["sample-api-overview"], "secret_references": [REFERENCE],
        "expected_git_sha": GIT, "expected_image_digest": IMAGE, "expected_config_digest": CONFIG, "expected_migration_head": None,
        "observed_git_sha": None, "observed_image_digest": None, "observed_config_digest": None, "observed_migration_head": None,
        "last_observed_at": None, "last_certified_at": None,
    }
    base.update(overrides)
    return base


# --- pure state machine -----------------------------------------------------------


def test_registered_descriptor_alone_never_becomes_synced():
    state, reason = derive_state(row(), NOW)
    assert state == "pending"
    state, _ = derive_state(row(expected_git_sha=None, expected_image_digest=None, expected_config_digest=None), NOW)
    assert state == "registered"
    assert derive_state(row(monitoring_state="unregistered"), NOW)[0] == "unregistered"


def test_fresh_matching_evidence_is_synced_and_drift_is_named():
    observed = row(observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=NOW - timedelta(minutes=1))
    assert derive_state(observed, NOW) == ("synced", "every expected field matches fresh runtime evidence: config_digest, git_sha, image_digest")
    drifted = row(**{**observed, "observed_image_digest": "sha256:" + "d" * 64})
    state, reason = derive_state(drifted, NOW)
    assert state == "drifted" and "image_digest" in reason
    assert compare(drifted) == (["git_sha", "config_digest"], ["image_digest"], [])


def test_stale_partial_failed_and_applying_evidence_are_never_synced():
    stale = row(observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=NOW - timedelta(hours=1))
    assert derive_state(stale, NOW)[0] == "unknown"
    assert freshness(stale, NOW) == "stale"
    partial = row(observed_git_sha=GIT, last_observed_at=NOW)
    state, reason = derive_state(partial, NOW)
    assert state == "unknown" and "config_digest" in reason
    assert derive_state(row(last_observed_at=NOW), NOW, reporter_status="failed")[0] == "failed"
    assert derive_state(row(last_observed_at=NOW), NOW, reporter_status="applying")[0] == "applying"


def test_certification_survives_only_while_synced_and_fresh():
    certified = row(monitoring_state="certified", observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=NOW)
    assert derive_state(certified, NOW)[0] == "certified"
    assert derive_state({**certified, "observed_git_sha": "e" * 40}, NOW)[0] == "drifted"
    assert derive_state(certified, NOW + timedelta(hours=2))[0] == "unknown"


def test_certification_blockers_require_runtime_proof_not_git():
    evidence = CertificationEvidence(reason="TEST_SYN synthetic request produced metric, log, trace, alert and incident",
                                     health_endpoints=True, metrics_scraped=True, logs_received=True, traces_received=True,
                                     alert_route_test=True, dashboards_bound=True, secret_references_reconciled=True)
    blockers = certification_blockers(row(), evidence, NOW)
    assert any("pending" in item for item in blockers)
    synced = row(observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=NOW)
    assert certification_blockers(synced, evidence, NOW) == []
    weak = evidence.model_copy(update={"traces_received": False, "alert_route_test": False})
    assert certification_blockers(synced, weak, NOW) == ["evidence missing: traces_received, alert_route_test"]
    no_traces = {**synced, "traces_profile": "not-applicable"}
    assert certification_blockers(no_traces, evidence.model_copy(update={"traces_received": False}), NOW) == []
    assert "no Grafana dashboard is bound" in certification_blockers({**synced, "grafana_dashboard_ids": []}, evidence, NOW)


# --- HTTP surface ----------------------------------------------------------------------


@pytest.fixture
def authority(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Keys:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=private.public_key())

    monkeypatch.setattr(jwt, "PyJWKClient", Keys)
    for key, value in {
        "keycloak_issuer": ISSUER, "keycloak_audience": AUDIENCE,
        "keycloak_jwks_url": ISSUER + "/certs", "keycloak_authorized_parties": "platform-test-client",
        "middleware_secret": "shared-integration-test-token",
    }.items():
        monkeypatch.setattr(settings, key, value)

    def token(scope="platform.services.write", role="platform_admin", subject="reviewer-subject"):
        current = int(time.time())
        return jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "azp": "platform-test-client", "sub": subject,
                           "iat": current, "exp": current + 300, "realm_access": {"roles": [role]}, "scope": scope}, private, algorithm="RS256")
    return token


class Result:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def all(self):
        return self.rows


@pytest.fixture
def client_and_db(monkeypatch):
    db = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = db
    monkeypatch.setattr(database_session, "SessionFactory", lambda: context)
    return TestClient(app), db


def executed_sql(db):
    return [str(call.args[0]) for call in db.execute.await_args_list]


def test_registration_persists_the_descriptor_and_secret_references_as_pointers(authority, client_and_db):
    client, db = client_and_db
    response = client.post("/platform/v1/services", json=SERVICE, headers={"Authorization": "Bearer " + authority()})
    assert response.status_code == 201, response.text
    assert response.json()["monitoring_state"] == "registered"
    params = db.execute.await_args_list[0].args[1]
    assert params["expected_git_sha"] == GIT and params["monitoring_reason"].startswith("registered from an approved descriptor")
    assert '"reference_uri": "openbao://codestra/staging/sample/api/database"' in params["secret_references"]
    assert "value" not in params["secret_references"]


@pytest.mark.parametrize("poison", [
    {"secret_references": [{**REFERENCE, "value": "hunter2"}]},
    {"secret_references": [{**REFERENCE, "client_secret": "x"}]},
    {"secret_references": [{**REFERENCE, "lease_metadata": {"ttl_seconds": 60, "db_password": "x"}}]},
    {"secret_references": [{**REFERENCE, "environment": "production", "secret_ref": "codestra/production/sample/api/database"}]},
    {"secret_references": [{**REFERENCE, "secret_ref": "codestra/staging/sample/api/*"}]},
    {"secret_references": [{**REFERENCE, "reference_uri": "openbao://codestra/staging/other/path"}]},
    {"secret_references": [REFERENCE, REFERENCE]},
])
def test_value_bearing_or_foreign_secret_references_are_rejected_before_any_write(authority, client_and_db, poison):
    client, db = client_and_db
    response = client.post("/platform/v1/services", json={**SERVICE, **poison}, headers={"Authorization": "Bearer " + authority()})
    assert response.status_code == 422, response.text
    db.execute.assert_not_awaited()


def test_observation_moves_pending_to_synced_and_records_the_transition(authority, client_and_db):
    client, db = client_and_db
    db.execute.side_effect = [Result(row()), Result("catalog-id"), Result(None)]
    response = client.post("/platform/v1/services/sample-api/monitoring-state/observations", json={
        "observed_git_sha": GIT, "observed_image_digest": IMAGE, "observed_config_digest": CONFIG,
        "observed_at": datetime.now(timezone.utc).isoformat(), "source": "alloy-core-01",
    }, headers={"Authorization": "Bearer " + authority(scope="platform.runtime.observe", role="platform_operator"), "X-Correlation-ID": "corr-1"})
    assert response.status_code == 202, response.text
    assert response.json()["monitoring_state"] == "synced" and response.json()["runtime_mutated"] is False
    sql = executed_sql(db)
    assert "UPDATE platform_services" in sql[1] and "INSERT INTO platform_service_monitoring_audit" in sql[2]
    db.commit.assert_awaited_once()


def test_observation_requires_correlation_and_never_rewinds_time(authority, client_and_db):
    client, db = client_and_db
    payload = {"observed_git_sha": GIT, "observed_at": datetime.now(timezone.utc).isoformat(), "source": "alloy-core-01"}
    headers = {"Authorization": "Bearer " + authority(scope="platform.runtime.observe", role="platform_operator")}
    assert client.post("/platform/v1/services/sample-api/monitoring-state/observations", json=payload, headers=headers).status_code == 422
    db.execute.assert_not_awaited()
    db.execute.side_effect = [Result(row(last_observed_at=datetime.now(timezone.utc) + timedelta(seconds=30)))]
    response = client.post("/platform/v1/services/sample-api/monitoring-state/observations", json=payload, headers={**headers, "X-Correlation-ID": "corr-2"})
    assert response.status_code == 409
    db.commit.assert_not_awaited()


def test_observation_scope_and_write_role_are_enforced(authority, client_and_db):
    client, db = client_and_db
    payload = {"observed_git_sha": GIT, "observed_at": datetime.now(timezone.utc).isoformat(), "source": "x"}
    response = client.post("/platform/v1/services/sample-api/monitoring-state/observations", json=payload,
                           headers={"Authorization": "Bearer " + authority(scope="platform.services.read"), "X-Correlation-ID": "c"})
    assert response.status_code == 403
    response = client.post("/platform/v1/services/sample-api/monitoring-state/certification", json={"reason": "x" * 30},
                           headers={"Authorization": "Bearer " + authority(scope="platform.services.write", role="platform_operator"), "X-Correlation-ID": "c"})
    assert response.status_code == 403
    db.execute.assert_not_awaited()


def test_certification_refuses_git_only_state_and_accepts_fresh_synced_evidence(authority, client_and_db):
    client, db = client_and_db
    evidence = {"reason": "TEST_SYN produced metric, sanitized log, trace, controlled alert and incident",
                "health_endpoints": True, "metrics_scraped": True, "logs_received": True, "traces_received": True,
                "alert_route_test": True, "dashboards_bound": True, "secret_references_reconciled": True}
    headers = {"Authorization": "Bearer " + authority(role="platform_reviewer"), "X-Correlation-ID": "cert-1"}
    db.execute.side_effect = [Result(row())]
    response = client.post("/platform/v1/services/sample-api/monitoring-state/certification", json=evidence, headers=headers)
    assert response.status_code == 409 and any("pending" in b for b in response.json()["detail"]["blockers"])
    db.commit.assert_not_awaited()
    db.reset_mock()
    synced = row(monitoring_state="synced", observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=datetime.now(timezone.utc))
    db.execute.side_effect = [Result(synced), Result("catalog-id"), Result(None)]
    response = client.post("/platform/v1/services/sample-api/monitoring-state/certification", json=evidence, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["monitoring_state"] == "certified" and response.json()["certified_by"] == "reviewer-subject"
    db.commit.assert_awaited_once()


def test_monitoring_state_read_exposes_references_without_values(authority, client_and_db):
    client, db = client_and_db
    synced = row(monitoring_state="synced", observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=datetime.now(timezone.utc))
    db.execute.side_effect = [Result(synced), Result(rows=[{"from_state": "pending", "to_state": "synced", "reason": "r", "actor": "a", "correlation_id": "c", "evidence_hash": "0" * 64, "created_at": NOW}])]
    response = client.get("/platform/v1/services/sample-api/monitoring-state", headers={"Authorization": "Bearer " + authority(scope="platform.services.read")})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["derived_state"] == "synced" and body["freshness"] == "fresh" and body["matching"] == ["git_sha", "image_digest", "config_digest"]
    assert body["secret_references"][0]["secret_ref"] == "codestra/staging/sample/api/database"
    assert "value" not in response.text and "password" not in response.text
    assert body["audit"][0]["to_state"] == "synced" and body["runtime_mutated"] is False


def test_new_expected_release_invalidates_certification(authority, client_and_db):
    client, db = client_and_db
    certified = row(monitoring_state="certified", observed_git_sha=GIT, observed_image_digest=IMAGE, observed_config_digest=CONFIG, last_observed_at=datetime.now(timezone.utc))
    db.execute.side_effect = [Result(certified), Result("catalog-id"), Result(None)]
    response = client.patch("/platform/v1/services/sample-api", json={"expected_git_sha": "f" * 40},
                            headers={"Authorization": "Bearer " + authority(), "X-Correlation-ID": "rel-2"})
    assert response.status_code == 200, response.text
    assert response.json()["monitoring_state"] == "drifted"
    assert "INSERT INTO platform_service_monitoring_audit" in executed_sql(db)[2]
