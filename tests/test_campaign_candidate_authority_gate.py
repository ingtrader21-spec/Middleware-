from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import campaign_recycling as api

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "config/campaign-recycling-candidate-authority.v1.json"


def _gate() -> dict:
    return json.loads(GATE.read_text(encoding="utf-8"))


def test_candidate_authority_gate_is_fail_closed_and_non_effectful() -> None:
    gate = _gate()
    assert gate["schema_version"] == "1.0"
    assert gate["gate"] == "MCR-C6-candidate-authority"
    assert gate["status"] == "synthetic_certified_production_blocked"
    assert gate["production_authorized"] is False
    assert gate["provider_effects_enabled"] is False
    assert gate["rules"] == {
        "middleware_must_not_invent_campaigns": True,
        "raw_provider_or_vicidial_campaign_ids_allowed": False,
        "candidate_source_must_be_tenant_bound": True,
        "campaign_version_must_be_immutable": True,
        "audience_membership_must_be_authoritative": True,
        "sender_identity_must_be_authoritative": True,
    }


def test_klyrow_existing_surface_is_explicitly_insufficient() -> None:
    email = _gate()["channels"]["email"]
    observed = email["observed_existing_surface"]
    assert email["campaign_authority"] == "klyrow"
    assert email["sender_identity_authority"] == "klyrow"
    assert email["status"] == "blocked"
    assert observed["campaign_list"] == "GET /v1/campaign-definitions"
    assert observed["preflight"].endswith("/preflight")
    assert "no immutable campaign-version" in observed["deficiency"]
    assert "recipient audience-membership" in observed["deficiency"]


def test_required_klyrow_read_contract_contains_no_provider_effect_fields() -> None:
    required = _gate()["channels"]["email"]["required_read_contract"]
    assert set(required) == {
        "tenant_binding",
        "campaign_id",
        "campaign_version",
        "channel",
        "active",
        "version_approved",
        "priority",
        "sender_identity_id",
        "sender_authorized",
        "audience_snapshot_ref",
        "lead_membership",
        "effective_window",
        "readback_version",
    }
    assert required["campaign_id"] == "klyrow:<raw_id>"
    serialized = json.dumps(required).lower()
    for forbidden in ("smtp_password", "api_key", "send_message", "provider_submit"):
        assert forbidden not in serialized


def test_cross_channel_authorities_match_frozen_split() -> None:
    channels = _gate()["channels"]
    assert channels["email"]["campaign_authority"] == "klyrow"
    assert channels["sms"]["campaign_authority"] == "klyrow"
    assert channels["sms"]["sender_identity_authority"] == "telnexa"
    assert channels["whatsapp"]["campaign_authority"] == "whatsapp"
    assert channels["whatsapp"]["transport_authority"] == "evolution"
    assert channels["voice"]["status"] == "not_supported_in_v1"


def test_activation_requirements_require_tenant_and_restart_safe_authority() -> None:
    requirements = _gate()["activation_requirements"]
    assert "service authentication and tenant isolation negative tests pass" in requirements
    assert "audience membership is authoritative and restart-safe" in requirements
    assert "no provider effect is introduced by candidate reads" in requirements


def test_runtime_plan_still_fails_closed_without_candidate_authority(monkeypatch) -> None:
    monkeypatch.setattr(
        api,
        "validate_token",
        lambda _token: {
            "aud": "middleware-api",
            "tenant_id": "TEST_SYN_TENANT",
            "azp": "mcr-test",
            "scope": "campaign.engine.plan",
        },
    )
    app = FastAPI()
    app.include_router(api.router)
    response = TestClient(app).post(
        "/platform/v1/campaign-engine/plan",
        headers={
            "Authorization": "Bearer test",
            "X-Tenant-ID": "TEST_SYN_TENANT",
            "X-Correlation-ID": "corr-c6-gate",
        },
        json={"schema_version": "1.0", "lead_ids": ["100-L-00000001"]},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] in {
        "policy_not_configured",
        "dependency_unavailable",
    }
