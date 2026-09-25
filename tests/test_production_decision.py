"""Production GO/NO_GO decision engine and private decision API."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import production_decision as engine
from app.api.internal import production_decision as decision_api
from app.router_registry import install_domain_error_handler

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
SOURCE_SHA = "a" * 40
IMAGE = "sha256:" + "b" * 64
PREVIOUS_IMAGE = "sha256:" + "c" * 64
SCHEMA_HEAD = "0067_service_catalog_monitoring_state"
RELEASE = {"source_sha": SOURCE_SHA, "image_digest": IMAGE, "schema_head": SCHEMA_HEAD}


def _common(kind: str, age: timedelta = timedelta(hours=1)) -> dict:
    return {
        "evidence_id": f"{kind}-1",
        "status": "PASS",
        "source_sha": SOURCE_SHA,
        "image_digest": IMAGE,
        "observed_at": (NOW - age).isoformat(),
        "artifact_sha256": "d" * 64,
    }


def _evidence(capabilities=("EMAIL_DELIVERY_ENABLED", "SMS_DELIVERY_ENABLED")) -> dict:
    return {
        "staging": {
            **_common("staging"),
            "environment": "staging",
            "schema_head": SCHEMA_HEAD,
            "smoke_passed": True,
        },
        "release_seal": {
            **_common("release_seal"),
            "seal_sha256": "e" * 64,
            "signer": "release-controller",
            "signature_verified": True,
        },
        "canary": {
            **_common("canary"),
            "capabilities": list(capabilities),
            "duration_seconds": 3600,
            "error_rate": 0.001,
        },
        "monitoring": {
            **_common("monitoring"),
            "open_critical_alerts": 0,
            "alert_routes_verified": True,
            "slo_burn_rate_ok": True,
        },
        "rollback": {
            **_common("rollback"),
            "rehearsed": True,
            "rollback_verified": True,
            "rollback_image_digest": PREVIOUS_IMAGE,
        },
        "reconciliation": {
            **_common("reconciliation"),
            "unreconciled_count": 0,
            "drift_count": 0,
        },
        "approval": {
            **_common("approval"),
            "approved_by": "release-approver",
            "expires_at": (NOW + timedelta(hours=12)).isoformat(),
            "capabilities": list(capabilities),
        },
    }


def _request(evidence=None, capabilities=("EMAIL_DELIVERY_ENABLED",)) -> engine.DecisionRequest:
    return engine.DecisionRequest.model_validate(
        {
            "release": RELEASE,
            "requested_capabilities": list(capabilities),
            "evidence": _evidence() if evidence is None else evidence,
        }
    )


def _evaluate(request: engine.DecisionRequest, requested_by: str = "release-requester") -> dict:
    result = engine.evaluate(request, requested_by=requested_by, now=NOW, source="request")
    engine.DecisionReadback.model_validate(result)
    return result


def _assert_inert(result: dict) -> None:
    assert result["activation"] == {
        "performed": False,
        "capabilities_activated": [],
        "provider_effects_enabled": False,
        "note": "decision only; activation is owned by the release controller",
    }


def test_complete_evidence_authorizes_requested_capability_without_activation():
    result = _evaluate(_request())
    assert result["decision"] == "GO"
    assert result["reasons"] == []
    assert result["authorized_capabilities"] == ["EMAIL_DELIVERY_ENABLED"]
    assert result["denied_capabilities"] == []
    assert result["partial"] is False
    assert result["authoritative"] is False
    assert result["capabilities"][0]["required_umbrella_control"] == "EXTERNAL_DELIVERY_ENABLED"
    assert {item["status"] for item in result["evidence"]} == {"ACCEPTED"}
    _assert_inert(result)


def test_decision_id_is_deterministic_and_bound_to_evidence():
    first = _evaluate(_request())
    assert first["decision_id"] == _evaluate(_request())["decision_id"]
    changed = _evidence()
    changed["canary"]["evidence_id"] = "canary-2"
    assert _evaluate(_request(changed))["decision_id"] != first["decision_id"]


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_missing_evidence_of_any_kind_denies_go(kind):
    evidence = _evidence()
    del evidence[kind]
    result = _evaluate(_request(evidence))
    assert result["decision"] == "NO_GO"
    assert f"{kind}_evidence_missing" in result["reasons"]
    assert result["authorized_capabilities"] == []
    assert result["denied_capabilities"] == ["EMAIL_DELIVERY_ENABLED"]
    assessment = next(item for item in result["evidence"] if item["kind"] == kind)
    assert assessment["status"] == "MISSING"
    _assert_inert(result)


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_null_evidence_denies_go(kind):
    evidence = _evidence()
    evidence[kind] = None
    assert _evaluate(_request(evidence))["decision"] == "NO_GO"


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_failed_evidence_denies_go(kind):
    evidence = _evidence()
    evidence[kind]["status"] = "FAIL"
    result = _evaluate(_request(evidence))
    assert result["decision"] == "NO_GO"
    assert f"{kind}_status_not_pass" in result["reasons"]


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_evidence_for_another_release_denies_go(kind):
    evidence = _evidence()
    evidence[kind]["source_sha"] = "f" * 40
    evidence[kind]["image_digest"] = PREVIOUS_IMAGE
    result = _evaluate(_request(evidence))
    assert result["decision"] == "NO_GO"
    assert f"{kind}_source_sha_mismatch" in result["reasons"]
    assert f"{kind}_image_digest_mismatch" in result["reasons"]


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_stale_and_future_evidence_denies_go(kind):
    stale = _evidence()
    stale[kind]["observed_at"] = (NOW - engine.MAX_EVIDENCE_AGE[kind] - timedelta(seconds=1)).isoformat()
    assert f"{kind}_evidence_stale" in _evaluate(_request(stale))["reasons"]

    future = _evidence()
    future[kind]["observed_at"] = (NOW + timedelta(hours=1)).isoformat()
    result = _evaluate(_request(future))
    assert result["decision"] == "NO_GO"
    assert f"{kind}_observed_in_future" in result["reasons"]


@pytest.mark.parametrize(
    ("kind", "field", "value", "reason"),
    [
        ("staging", "schema_head", "0066_other", "staging_schema_head_mismatch"),
        ("staging", "smoke_passed", False, "staging_smoke_failed"),
        ("release_seal", "signature_verified", False, "release_seal_signature_unverified"),
        ("canary", "duration_seconds", 60, "canary_duration_insufficient"),
        ("canary", "error_rate", 0.2, "canary_error_rate_exceeded"),
        ("monitoring", "open_critical_alerts", 1, "monitoring_critical_alerts_open"),
        ("monitoring", "alert_routes_verified", False, "monitoring_alert_routes_unverified"),
        ("monitoring", "slo_burn_rate_ok", False, "monitoring_slo_burn_rate_exceeded"),
        ("rollback", "rehearsed", False, "rollback_not_rehearsed"),
        ("rollback", "rollback_verified", False, "rollback_not_verified"),
        ("rollback", "rollback_image_digest", IMAGE, "rollback_target_is_candidate"),
        ("reconciliation", "unreconciled_count", 3, "reconciliation_unreconciled_records"),
        ("reconciliation", "drift_count", 1, "reconciliation_drift_detected"),
        ("approval", "expires_at", (NOW - timedelta(seconds=1)).isoformat(), "approval_expired"),
        ("approval", "expires_at", (NOW + timedelta(days=30)).isoformat(), "approval_validity_too_long"),
    ],
)
def test_kind_specific_invariants_deny_go(kind, field, value, reason):
    evidence = _evidence()
    evidence[kind][field] = value
    result = _evaluate(_request(evidence))
    assert result["decision"] == "NO_GO"
    assert reason in result["reasons"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda doc: doc.pop("artifact_sha256"),
        lambda doc: doc.update(observed_at="2026-09-25T11:00:00"),  # naive timestamp
        lambda doc: doc.update(status="pass"),
        lambda doc: doc.update(unexpected="field"),
    ],
)
def test_malformed_evidence_is_rejected_not_trusted(mutation):
    evidence = _evidence()
    mutation(evidence["monitoring"])
    result = _evaluate(_request(evidence))
    assert result["decision"] == "NO_GO"
    assessment = next(item for item in result["evidence"] if item["kind"] == "monitoring")
    assert assessment["status"] == "REJECTED"
    assert assessment["reasons"] == ["monitoring_evidence_invalid"]
    assert assessment["invalid_fields"]


def test_selective_authorization_grants_only_canaried_and_approved_capabilities():
    evidence = _evidence(capabilities=("EMAIL_DELIVERY_ENABLED", "SMS_DELIVERY_ENABLED"))
    evidence["approval"]["capabilities"] = ["EMAIL_DELIVERY_ENABLED", "ODOO_WRITE"]
    result = _evaluate(
        _request(
            evidence,
            capabilities=(
                "EMAIL_DELIVERY_ENABLED",
                "SMS_DELIVERY_ENABLED",
                "ODOO_WRITE",
                "EXTERNAL_DELIVERY_ENABLED",
                "NOT_A_CAPABILITY",
            ),
        )
    )
    assert result["decision"] == "GO"
    assert result["partial"] is True
    assert result["authorized_capabilities"] == ["EMAIL_DELIVERY_ENABLED"]
    by_name = {item["capability"]: item for item in result["capabilities"]}
    assert by_name["SMS_DELIVERY_ENABLED"]["reasons"] == ["capability_not_approved"]
    assert by_name["ODOO_WRITE"]["reasons"] == ["capability_not_canaried"]
    assert "umbrella_control_not_grantable" in by_name["EXTERNAL_DELIVERY_ENABLED"]["reasons"]
    assert "capability_unknown" in by_name["NOT_A_CAPABILITY"]["reasons"]
    assert sorted(result["denied_capabilities"]) == sorted(
        ["SMS_DELIVERY_ENABLED", "ODOO_WRITE", "EXTERNAL_DELIVERY_ENABLED", "NOT_A_CAPABILITY"]
    )
    _assert_inert(result)


def test_no_authorized_capability_is_no_go():
    result = _evaluate(_request(capabilities=("ODOO_WRITE",)))
    assert result["decision"] == "NO_GO"
    assert result["reasons"] == ["no_capability_authorized"]


def test_self_approval_is_denied():
    result = _evaluate(_request(), requested_by="release-approver")
    assert result["decision"] == "NO_GO"
    assert result["capabilities"][0]["reasons"] == ["approval_not_independent"]


def test_evidence_failure_denies_every_capability_even_if_approved():
    evidence = _evidence()
    evidence["monitoring"]["open_critical_alerts"] = 2
    result = _evaluate(_request(evidence, capabilities=("EMAIL_DELIVERY_ENABLED", "SMS_DELIVERY_ENABLED")))
    assert result["decision"] == "NO_GO"
    assert result["authorized_capabilities"] == []
    assert all(item["decision"] == "NO_GO" for item in result["capabilities"])
    assert all("release_evidence_incomplete" in item["reasons"] for item in result["capabilities"])


@pytest.mark.parametrize(
    "body",
    [
        {"release": RELEASE, "requested_capabilities": [], "evidence": {}},
        {"release": RELEASE, "requested_capabilities": ["a lower"], "evidence": {}},
        {"release": RELEASE, "requested_capabilities": ["ODOO_WRITE", "ODOO_WRITE"], "evidence": {}},
        {"release": RELEASE, "requested_capabilities": ["ODOO_WRITE"], "evidence": {"extra": {}}},
        {"release": {**RELEASE, "source_sha": "short"}, "requested_capabilities": ["ODOO_WRITE"]},
    ],
)
def test_malformed_decision_request_is_refused(body):
    with pytest.raises(ValueError):
        engine.DecisionRequest.model_validate(body)


def test_default_no_go_and_policy_document():
    result = engine.default_no_go(now=NOW, reason="evidence_store_unconfigured")
    engine.DecisionReadback.model_validate(result)
    assert result["decision"] == "NO_GO"
    assert result["authoritative"] is False
    assert [item["status"] for item in result["evidence"]] == ["MISSING"] * len(engine.EVIDENCE_KINDS)
    _assert_inert(result)

    policy = engine.DecisionPolicy.model_validate(engine.policy_document())
    assert policy.default_decision == "NO_GO"
    assert policy.required_evidence == list(engine.EVIDENCE_KINDS)
    assert not set(policy.grantable_capabilities) & set(policy.non_grantable_umbrella_controls)


# --- HTTP surface -----------------------------------------------------------


class FakeTokens:
    def __init__(self):
        self.scopes: list[str] = []

    async def verify(self, authorization, *, expected_client_id, required_scope):
        assert authorization == "Bearer test"
        assert expected_client_id == "release-requester"
        self.scopes.append(required_scope)
        return {"azp": expected_client_id, "scope": required_scope, "sub": "test"}


def _client(monkeypatch, evidence_dir: str = ""):
    tokens = FakeTokens()
    app = FastAPI()
    install_domain_error_handler(app)
    app.state.runtime = SimpleNamespace(
        tokens=tokens,
        settings=SimpleNamespace(production_decision_evidence_dir=evidence_dir),
    )
    app.include_router(decision_api.router)
    monkeypatch.setattr(
        decision_api,
        "caller_for_authorization",
        lambda _authorization: SimpleNamespace(client_id="release-requester"),
    )
    monkeypatch.setattr(decision_api, "_now", lambda: NOW)
    return TestClient(app), tokens


HEADERS = {"Authorization": "Bearer test"}


def _write_store(root, *, skip=(), requested_by="release-requester"):
    (root / decision_api.REQUEST_FILENAME).write_text(
        json.dumps(
            {
                "release": RELEASE,
                "requested_capabilities": ["EMAIL_DELIVERY_ENABLED"],
                "requested_by": requested_by,
            }
        )
    )
    for kind, document in _evidence().items():
        if kind not in skip:
            (root / f"{kind}.json").write_text(json.dumps(document))


def test_readback_defaults_to_no_go_when_store_is_unconfigured(monkeypatch):
    client, tokens = _client(monkeypatch)
    response = client.get("/internal/v1/production/decision", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "NO_GO"
    assert body["reasons"] == ["evidence_store_unconfigured"]
    assert body["activation"]["performed"] is False
    assert tokens.scopes == [decision_api.READ_SCOPE]


def test_readback_is_authoritative_go_from_complete_store(monkeypatch, tmp_path):
    _write_store(tmp_path)
    client, _tokens = _client(monkeypatch, str(tmp_path))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["decision"] == "GO"
    assert body["authoritative"] is True
    assert body["source"] == "evidence_store"
    assert body["requested_by"] == "release-requester"
    assert body["authorized_capabilities"] == ["EMAIL_DELIVERY_ENABLED"]
    assert body["activation"]["capabilities_activated"] == []


@pytest.mark.parametrize("kind", engine.EVIDENCE_KINDS)
def test_readback_store_missing_evidence_is_no_go(monkeypatch, tmp_path, kind):
    _write_store(tmp_path, skip=(kind,))
    client, _tokens = _client(monkeypatch, str(tmp_path))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["decision"] == "NO_GO"
    assert f"{kind}_evidence_missing" in body["reasons"]


def test_readback_store_rejects_unreadable_documents(monkeypatch, tmp_path):
    _write_store(tmp_path)
    (tmp_path / "canary.json").write_text("{not json")
    (tmp_path / "approval.json").write_text("[]")
    client, _tokens = _client(monkeypatch, str(tmp_path))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["decision"] == "NO_GO"
    statuses = {item["kind"]: item["status"] for item in body["evidence"]}
    assert statuses["canary"] == "REJECTED"
    assert statuses["approval"] == "REJECTED"


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda root: None, "decision_request_missing"),
        (lambda root: (root / decision_api.REQUEST_FILENAME).write_text("nope"), "decision_request_invalid"),
        (
            lambda root: (root / decision_api.REQUEST_FILENAME).write_text(
                json.dumps({"release": RELEASE, "requested_capabilities": ["ODOO_WRITE"]})
            ),
            "decision_requester_invalid",
        ),
        (
            lambda root: (root / decision_api.REQUEST_FILENAME).write_text(
                json.dumps({"release": {}, "requested_capabilities": [], "requested_by": "x"})
            ),
            "decision_request_invalid",
        ),
    ],
)
def test_readback_store_request_failures_are_no_go(monkeypatch, tmp_path, setup, reason):
    setup(tmp_path)
    client, _tokens = _client(monkeypatch, str(tmp_path))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["decision"] == "NO_GO"
    assert body["reasons"] == [reason]


def test_readback_store_nonexistent_directory_is_no_go(monkeypatch, tmp_path):
    client, _tokens = _client(monkeypatch, str(tmp_path / "absent"))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["reasons"] == ["evidence_store_unavailable"]


def test_readback_store_self_approval_is_no_go(monkeypatch, tmp_path):
    _write_store(tmp_path, requested_by="release-approver")
    client, _tokens = _client(monkeypatch, str(tmp_path))
    body = client.get("/internal/v1/production/decision", headers=HEADERS).json()
    assert body["decision"] == "NO_GO"


def test_evaluate_is_non_authoritative_and_uses_caller_identity(monkeypatch):
    client, tokens = _client(monkeypatch)
    response = client.post(
        "/internal/v1/production/decision/evaluate",
        headers=HEADERS,
        json={
            "release": RELEASE,
            "requested_capabilities": ["EMAIL_DELIVERY_ENABLED"],
            "evidence": _evidence(),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "GO"
    assert body["authoritative"] is False
    assert body["source"] == "request"
    assert body["requested_by"] == "release-requester"
    assert body["activation"]["provider_effects_enabled"] is False
    assert tokens.scopes == [decision_api.EVALUATE_SCOPE]


def test_evaluate_without_evidence_is_no_go(monkeypatch):
    client, _tokens = _client(monkeypatch)
    body = client.post(
        "/internal/v1/production/decision/evaluate",
        headers=HEADERS,
        json={"release": RELEASE, "requested_capabilities": ["EMAIL_DELIVERY_ENABLED"]},
    ).json()
    assert body["decision"] == "NO_GO"
    assert {f"{kind}_evidence_missing" for kind in engine.EVIDENCE_KINDS} <= set(body["reasons"])


def test_evaluate_rejects_malformed_body(monkeypatch):
    client, _tokens = _client(monkeypatch)
    response = client.post(
        "/internal/v1/production/decision/evaluate",
        headers=HEADERS,
        json={"release": RELEASE, "requested_capabilities": []},
    )
    assert response.status_code == 422


def test_policy_endpoint(monkeypatch):
    client, tokens = _client(monkeypatch)
    body = client.get("/internal/v1/production/decision/policy", headers=HEADERS).json()
    assert body["default_decision"] == "NO_GO"
    assert body["activation_performed_by_this_service"] is False
    assert tokens.scopes == [decision_api.READ_SCOPE]


def test_unauthenticated_requests_are_refused(monkeypatch):
    client, _tokens = _client(monkeypatch)
    monkeypatch.undo()
    for method, path in (
        ("GET", "/internal/v1/production/decision"),
        ("GET", "/internal/v1/production/decision/policy"),
        ("POST", "/internal/v1/production/decision/evaluate"),
    ):
        assert client.request(method, path).status_code == 401


def test_no_activation_or_mutation_routes_exist(monkeypatch):
    client, _tokens = _client(monkeypatch)
    for path in (
        "/internal/v1/production/decision/activate",
        "/internal/v1/production/capabilities/enable",
        "/internal/v1/production/decision/apply",
    ):
        assert client.post(path, headers=HEADERS).status_code in {404, 405}
    methods = {
        (method, route.path)
        for route in decision_api.router.routes
        for method in route.methods
    }
    assert methods == {
        ("GET", "/internal/v1/production/decision"),
        ("GET", "/internal/v1/production/decision/policy"),
        ("POST", "/internal/v1/production/decision/evaluate"),
    }


def test_canonical_registry_owns_production_decision_router():
    from app.router_registry import CANONICAL_ROUTERS

    assert decision_api.router in CANONICAL_ROUTERS
