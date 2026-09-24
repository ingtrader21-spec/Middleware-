"""HTTP regressions against the actual integration entrypoint, with real JWT signatures."""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.api.v1.platform import CertificationSubmission
from app.core.config import settings
from app.db import session as database_session
from app.entrypoints.integration_api import app
from app.main import app as aggregate_app

ISSUER = "https://identity.example.invalid/realms/platform-test"
AUDIENCE = "platform-test-api"
REQUEST = "d335d985-287e-4e13-a76a-19d651fb566e"
SERVICE = {
    "service_id": "sample-api", "owner": "platform", "tenant_mode": "multi-tenant",
    "type": "api", "repository": "appolon1908-hue/sample-api", "environments": ["staging"],
    "dependencies": [], "data_classification": "confidential", "slo_profile": "customer-api",
    "alert_profile": "business-critical",
}
PROVISIONING = {
    "service_id": "sample-api", "environment": "staging",
    "manifest_sha256": "sha256:" + "1" * 64, "git_sha": "2" * 40,
    "requested_components": ["kong"],
}


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

    def token(scope="platform.services.write", subject="requester-subject", role="platform_admin", **changes):
        current = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "azp": "platform-test-client",
            "sub": subject, "iat": current, "exp": current + 300,
            "realm_access": {"roles": [role]}, "scope": scope,
            **changes,
        }
        return jwt.encode(claims, private, algorithm="RS256")
    return token


@pytest.fixture(params=[app, aggregate_app], ids=["integration-api", "aggregate-api"])
def client_and_db(monkeypatch, request):
    db = AsyncMock()
    context = AsyncMock()
    context.__aenter__.return_value = db
    monkeypatch.setattr(database_session, "SessionFactory", lambda: context)
    yield TestClient(request.param), db


class Result:
    def __init__(self, value=None):
        self.value = value
    def mappings(self):
        return self
    def one_or_none(self):
        return self.value
    def scalar_one_or_none(self):
        return self.value
    def all(self):
        return []


@pytest.mark.parametrize("method,path", [
    ("GET", "/services"), ("GET", "/services/sample-api"), ("POST", "/services"),
    ("PATCH", "/services/sample-api"), ("POST", "/services/sample-api/environments"),
    ("POST", "/services/sample-api/activate"), ("POST", "/services/sample-api/decommission"),
    ("POST", "/provisioning/requests"), ("GET", f"/provisioning/requests/{REQUEST}"),
    *[("POST", f"/provisioning/requests/{REQUEST}/{action}") for action in ("validate", "approve", "apply", "rollback")],
])
def test_every_platform_operation_rejects_shared_secret_and_forged_identity(authority, client_and_db, method, path):
    client, db = client_and_db
    response = client.request(method, "/platform/v1" + path, json={}, headers={
        "Authorization": "Bearer shared-integration-test-token", "X-Codestra-Role": "platform_admin",
        "X-Codestra-Principal": "spoofed-independent-reviewer",
    })
    assert response.status_code == 403
    db.execute.assert_not_awaited()


@pytest.mark.parametrize("changes", [
    {"iss": "https://wrong.invalid"}, {"aud": "wrong-api"}, {"azp": "wrong-client"},
    {"exp": 1}, {"nbf": 9999999999}, {"sub": ""}, {"sub": None},
    {"realm_access": {"roles": ["ordinary-client"]}}, {"realm_access": None},
    {"realm_access": {"roles": "platform_admin"}}, {"scope": "platform.services.read"},
])
def test_wrong_claims_never_mutate_catalog(authority, client_and_db, changes):
    client, db = client_and_db
    response = client.post("/platform/v1/services", json=SERVICE, headers={"Authorization": "Bearer " + authority(**changes)})
    assert response.status_code == 403
    db.execute.assert_not_awaited()


def test_signature_cannot_be_forged(authority, client_and_db):
    client, db = client_and_db
    claims = jwt.decode(authority(), options={"verify_signature": False})
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, rogue_key, algorithm="RS256")
    assert client.post("/platform/v1/services", json=SERVICE, headers={"Authorization": "Bearer " + token}).status_code == 403
    db.execute.assert_not_awaited()


def test_missing_identity_configuration_and_anonymous_fail_closed(authority, client_and_db, monkeypatch):
    client, db = client_and_db
    assert client.get("/platform/v1/services").status_code == 401
    monkeypatch.setattr(settings, "keycloak_audience", "")
    assert client.get("/platform/v1/services", headers={"Authorization": "Bearer " + authority()}).status_code == 503
    db.execute.assert_not_awaited()


def test_verified_catalog_write_and_read_only_denial(authority, client_and_db):
    client, db = client_and_db
    response = client.post("/platform/v1/services", json=SERVICE, headers={"Authorization": "Bearer " + authority()})
    assert response.status_code == 201
    db.commit.assert_awaited_once()
    db.reset_mock()
    response = client.patch("/platform/v1/services/sample-api", json={"owner": "attacker"}, headers={"Authorization": "Bearer " + authority(scope="platform.services.read")})
    assert response.status_code == 403
    db.execute.assert_not_awaited()


def test_request_persists_verified_subject_not_header(authority, client_and_db):
    client, db = client_and_db
    db.execute.return_value = Result({"environments": ["staging"]})
    response = client.post("/platform/v1/provisioning/requests", json=PROVISIONING, headers={
        "Authorization": "Bearer " + authority(scope="platform.provisioning.request", subject="stable-subject"),
        "X-Codestra-Principal": "fake-subject", "X-Codestra-Role": "platform_admin",
    })
    assert response.status_code == 202
    assert response.json()["apply_authorized"] is False
    assert db.execute.await_args_list[1].args[1]["principal"] == "stable-subject"


@pytest.mark.parametrize("subject,expected", [("requester", 403), ("independent-reviewer", 200)])
def test_approval_independence_uses_verified_sub(authority, client_and_db, subject, expected):
    client, db = client_and_db
    db.execute.side_effect = [Result({"state": "validated", "requested_by": "requester", "validation_json": {}}), Result(UUID(REQUEST)), Result()]
    response = client.post(f"/platform/v1/provisioning/requests/{REQUEST}/approve", json={"reason": "Reviewed immutable no-effect evidence"}, headers={
        "Authorization": "Bearer " + authority(scope="platform.provisioning.approve", subject=subject, role="platform_reviewer"),
        "X-Codestra-Principal": "different-spoofed-subject", "X-Codestra-Role": "platform_admin",
    })
    assert response.status_code == expected
    if expected == 403:
        assert db.execute.await_count == 1
        db.commit.assert_not_awaited()
    else:
        assert response.json()["apply_authorized"] is False
        assert db.execute.await_args_list[1].args[1]["principal"] == subject
        assert db.execute.await_args_list[2].args[1]["actor"] == f"platform_reviewer:{subject}"


def test_concurrent_state_change_cannot_write_audit_or_commit(authority, client_and_db):
    client, db = client_and_db
    db.execute.side_effect = [Result({"state": "validated", "requested_by": "other"}), Result(None)]
    response = client.post(f"/platform/v1/provisioning/requests/{REQUEST}/approve", json={"reason": "Reviewed immutable no-effect evidence"}, headers={"Authorization": "Bearer " + authority(scope="platform.provisioning.approve")})
    assert response.status_code == 409
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()
    assert db.execute.await_count == 2


def test_review_scope_does_not_authorize_apply(authority, client_and_db):
    client, db = client_and_db
    response = client.post(f"/platform/v1/provisioning/requests/{REQUEST}/apply", json={"reason": "Request a separately authorized operation"}, headers={"Authorization": "Bearer " + authority(scope="platform.provisioning.approve")})
    assert response.status_code == 403
    db.execute.assert_not_awaited()


def test_validation_evidence_failure_never_updates_state(authority, client_and_db):
    client, db = client_and_db
    body = {key: True for key in CertificationSubmission.model_fields if key != "reason"}
    body.update(reason="Reviewed immutable no-effect evidence", tenant_isolation=False)
    response = client.post(f"/platform/v1/provisioning/requests/{REQUEST}/validate", json=body, headers={"Authorization": "Bearer " + authority(scope="platform.provisioning.validate")})
    assert response.status_code == 422
    db.execute.assert_not_awaited()
