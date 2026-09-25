from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.internal import provider_canaries as canary_api
from app.core.config import Settings
from app.provider_canary import canonical_fingerprint, validate_provider_canary_evidence
from app.provider_canary_controller import (
    REQUIRED_EVIDENCE_KINDS,
    ProviderCanaryPlan,
    evaluate_plan,
    execute_synthetic,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
DEST = canonical_fingerprint({"destination": "synthetic-inbox"})
PAYLOAD = canonical_fingerprint({"payload": "synthetic"})
BASE_ENV = {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}


def _settings(**changes):
    values = {
        "app_env": "staging",
        "provider_canary_controller_enabled": True,
        "provider_canary_kill_switch_engaged": False,
        "provider_canary_allowed_tenant_ids": "tenant-canary",
        "provider_canary_allowed_targets": "klyrow-email,vicidial-restricted",
        "provider_canary_max_attempts": 1,
        "provider_canary_max_rate_per_minute": 1,
        "provider_canary_max_destinations": 1,
        "provider_canary_max_duration_seconds": 900,
        "provider_canary_max_spend_minor_units": 0,
        "provider_canary_kill_switch_readback_max_age_seconds": 900,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _plan(**changes) -> dict:
    plan = {
        "schema_version": "1.0",
        "canary_id": "pas57-email-001",
        "tenant_id": "tenant-canary",
        "campaign_id": "TEST_SYN",
        "target": "klyrow-email",
        "provider": "postal",
        "capability": "email.send",
        "mode": "synthetic",
        "destination_fingerprints": [DEST],
        "payload_fingerprint": PAYLOAD,
        "budget": {
            "max_attempts": 1,
            "max_rate_per_minute": 1,
            "max_spend_minor_units": 0,
            "max_destinations": 1,
            "max_duration_seconds": 900,
        },
        "not_before": (NOW - timedelta(minutes=1)).isoformat(),
        "not_after": (NOW + timedelta(minutes=10)).isoformat(),
        "evidence": [
            {
                "kind": kind,
                "reference": f"evidence/{kind}",
                "digest": canonical_fingerprint(kind),
            }
            for kind in REQUIRED_EVIDENCE_KINDS
        ],
        "kill_switch": {
            "reference": "ops/kill-switch/postal",
            "state": "armed",
            "observed_at": (NOW - timedelta(minutes=2)).isoformat(),
        },
        "readback": {"required": True, "source": "provider_api", "timeout_seconds": 300},
    }
    plan.update(changes)
    return plan


def _evaluate(plan: dict, settings=None, **kwargs):
    return evaluate_plan(
        ProviderCanaryPlan.model_validate(plan),
        settings or _settings(),
        now=NOW,
        **kwargs,
    )


def test_complete_bounded_plan_is_allowed_synthetic_only():
    decision = _evaluate(_plan())
    assert decision.allowed
    body = decision.as_dict()
    assert body["decision"] == "ALLOW_SYNTHETIC"
    assert body["execution_mode"] == "synthetic"
    assert body["live_execution_available"] is False
    assert body["provider_effects"] == 0


def test_controller_is_disabled_by_default_in_settings():
    settings = Settings.from_env({**BASE_ENV})
    assert settings.provider_canary_controller_enabled is False
    assert settings.provider_canary_max_spend_minor_units == 0
    decision = _evaluate(_plan(), settings)
    assert "CONTROLLER_DISABLED" in decision.reasons
    assert "TENANT_NOT_ALLOWED" in decision.reasons
    assert "TARGET_NOT_ALLOWED" in decision.reasons


@pytest.mark.parametrize(
    ("changes", "settings_changes", "reason"),
    [
        ({"mode": "live"}, {}, "LIVE_EXECUTION_NOT_AUTHORIZED"),
        ({"campaign_id": "REAL_CAMPAIGN"}, {}, "CAMPAIGN_NOT_TEST_SYN"),
        ({"tenant_id": "tenant-other"}, {}, "TENANT_NOT_ALLOWED"),
        ({"target": "unknown-target"}, {}, "TARGET_UNKNOWN"),
        (
            {"target": "telnexa-sms", "provider": "jasmin", "capability": "sms.send"},
            {},
            "TARGET_NOT_ALLOWED",
        ),
        ({"provider": "sendgrid"}, {}, "PROVIDER_MISMATCH"),
        ({"capability": "email.bulk"}, {}, "CAPABILITY_MISMATCH"),
        ({}, {"app_env": "production"}, "PRODUCTION_ENVIRONMENT_FORBIDDEN"),
        ({}, {"provider_canary_kill_switch_engaged": True}, "KILL_SWITCH_ENGAGED"),
        ({}, {"provider_canary_controller_enabled": False}, "CONTROLLER_DISABLED"),
        ({"evidence": []}, {}, "EVIDENCE_MISSING:owner_approval"),
        ({"kill_switch": None}, {}, "KILL_SWITCH_READBACK_MISSING"),
        ({"readback": None}, {}, "READBACK_REQUIREMENT_MISSING"),
        (
            {"readback": {"required": False, "source": "provider_api", "timeout_seconds": 60}},
            {},
            "READBACK_NOT_REQUIRED",
        ),
        (
            {"readback": {"required": True, "source": "provider_cdr", "timeout_seconds": 60}},
            {},
            "READBACK_SOURCE_INVALID_FOR_CHANNEL",
        ),
        (
            {"not_after": (NOW - timedelta(seconds=1)).isoformat(),
             "not_before": (NOW - timedelta(minutes=5)).isoformat()},
            {},
            "WINDOW_EXPIRED",
        ),
        (
            {"not_before": (NOW + timedelta(minutes=1)).isoformat()},
            {},
            "WINDOW_NOT_OPEN",
        ),
        (
            {"not_after": (NOW + timedelta(hours=2)).isoformat()},
            {},
            "WINDOW_EXCEEDS_DURATION_BUDGET",
        ),
    ],
)
def test_missing_or_out_of_bounds_prerequisites_are_denied(
    changes, settings_changes, reason
):
    decision = _evaluate(_plan(**changes), _settings(**settings_changes))
    assert not decision.allowed
    assert reason in decision.reasons
    assert decision.as_dict()["decision"] == "DENY"


def test_budgets_are_bounded_by_operator_caps_and_plan():
    over = _plan(
        budget={
            "max_attempts": 5,
            "max_rate_per_minute": 5,
            "max_spend_minor_units": 100,
            "max_destinations": 5,
            "max_duration_seconds": 3600,
        }
    )
    reasons = set(_evaluate(over).reasons)
    assert {
        "BUDGET_ATTEMPTS_EXCEEDS_CAP",
        "BUDGET_RATE_EXCEEDS_CAP",
        "BUDGET_SPEND_EXCEEDS_CAP",
        "BUDGET_DESTINATIONS_EXCEEDS_CAP",
        "BUDGET_DURATION_EXCEEDS_CAP",
    } <= reasons

    two = _plan(destination_fingerprints=[DEST, canonical_fingerprint("second")])
    reasons = set(_evaluate(two).reasons)
    assert {"DESTINATIONS_EXCEED_BUDGET", "ATTEMPTS_EXCEED_BUDGET"} <= reasons

    assert "RATE_BUDGET_EXHAUSTED" in _evaluate(_plan(), recent_runs=1).reasons
    assert "KILL_SWITCH_ENGAGED" in _evaluate(
        _plan(), runtime_kill_switch_engaged=True
    ).reasons


def test_evidence_and_kill_switch_readback_are_strict():
    duplicated = _plan()
    duplicated["evidence"] = duplicated["evidence"] + duplicated["evidence"][:1]
    assert "EVIDENCE_DUPLICATE:owner_approval" in _evaluate(duplicated).reasons

    stale = _plan(
        kill_switch={
            "reference": "ops/kill",
            "state": "armed",
            "observed_at": (NOW - timedelta(hours=1)).isoformat(),
        }
    )
    assert "KILL_SWITCH_READBACK_STALE" in _evaluate(stale).reasons
    future = _plan(
        kill_switch={
            "reference": "ops/kill",
            "state": "armed",
            "observed_at": (NOW + timedelta(minutes=1)).isoformat(),
        }
    )
    assert "KILL_SWITCH_READBACK_FROM_FUTURE" in _evaluate(future).reasons
    tripped = _plan(
        kill_switch={
            "reference": "ops/kill",
            "state": "tripped",
            "observed_at": NOW.isoformat(),
        }
    )
    assert "KILL_SWITCH_NOT_ARMED" in _evaluate(tripped).reasons


@pytest.mark.parametrize(
    "changes",
    [
        {"destination_fingerprints": ["user@example.com"]},
        {"destination_fingerprints": [DEST, DEST]},
        {"payload_fingerprint": "plain text"},
        {"not_before": "2026-09-25T12:00:00"},
        {"not_after": (NOW - timedelta(hours=1)).isoformat()},
        {"unexpected": True},
        {"evidence": [{"kind": "owner_approval", "reference": "a b", "digest": PAYLOAD}]},
    ],
)
def test_structurally_invalid_plans_are_rejected(changes):
    with pytest.raises(ValidationError):
        ProviderCanaryPlan.model_validate(_plan(**changes))


def test_synthetic_execution_has_no_effect_and_cannot_pass_as_provider_proof():
    plan = ProviderCanaryPlan.model_validate(_plan())
    decision = evaluate_plan(plan, _settings(), now=NOW)
    run = execute_synthetic(plan, decision, now=NOW).as_dict()
    assert run["status"] == "completed"
    assert run["readback_verified"] is True
    assert run["provider_calls"] == run["provider_effects"] == 0
    assert run["spend_minor_units"] == 0
    attempt = run["attempts"][0]
    assert attempt["readback"]["synthetic"] is True
    assert attempt["readback"]["source"] == "synthetic_simulator"

    forged = {
        "schema_version": "1.0",
        "channel": "email",
        "provider": "postal",
        "provider_reference": attempt["synthetic_reference"],
        "terminal_status": attempt["terminal_status"],
        "observed_at": NOW.isoformat(),
        "source": attempt["readback"]["source"],
        "destination_fingerprint": DEST,
        "payload_fingerprint": PAYLOAD,
        "facts": {
            "delivery_event_id": "evt",
            "delivery_status": attempt["terminal_status"],
            "provider_message_id": attempt["synthetic_reference"],
            "recipient_fingerprint": DEST,
            "occurred_at": NOW.isoformat(),
        },
    }
    with pytest.raises(ValidationError):
        validate_provider_canary_evidence(
            forged,
            target="klyrow-email",
            destination_fingerprint=DEST,
            payload_fingerprint=PAYLOAD,
        )


def test_execution_refuses_denied_or_mismatched_decisions_and_honours_kill_switch():
    plan = ProviderCanaryPlan.model_validate(_plan())
    denied = evaluate_plan(plan, _settings(provider_canary_controller_enabled=False), now=NOW)
    with pytest.raises(PermissionError):
        execute_synthetic(plan, denied, now=NOW)
    other = ProviderCanaryPlan.model_validate(_plan(canary_id="pas57-other"))
    allowed_other = evaluate_plan(other, _settings(), now=NOW)
    with pytest.raises(PermissionError):
        execute_synthetic(plan, allowed_other, now=NOW)

    decision = evaluate_plan(plan, _settings(), now=NOW)
    halted = execute_synthetic(
        plan, decision, now=NOW, kill_switch_engaged=lambda: True
    ).as_dict()
    assert halted["status"] == "halted"
    assert halted["halt_reason"] == "KILL_SWITCH_ENGAGED"
    assert halted["attempts"] == []
    assert halted["readback_verified"] is False


def test_controller_module_has_no_provider_transport():
    for relative in (
        "app/provider_canary_controller.py",
        "app/api/internal/provider_canaries.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        assert not imported & {
            "httpx",
            "requests",
            "aiohttp",
            "smtplib",
            "aiosmtplib",
            "urllib",
            "socket",
        }, relative


# --- Settings -----------------------------------------------------------


def test_settings_reject_unsafe_controller_configuration():
    with pytest.raises(ValueError, match="explicit tenant and target allowlists"):
        Settings.from_env(
            {**BASE_ENV, "PROVIDER_CANARY_CONTROLLER_ENABLED": "true"}
        )
    with pytest.raises(ValueError, match="unknown target"):
        Settings.from_env(
            {
                **BASE_ENV,
                "PROVIDER_CANARY_CONTROLLER_ENABLED": "true",
                "PROVIDER_CANARY_ALLOWED_TENANT_IDS": "tenant-canary",
                "PROVIDER_CANARY_ALLOWED_TARGETS": "twilio-sms",
            }
        )
    with pytest.raises(ValueError, match="PROVIDER_CANARY_MAX_SPEND_MINOR_UNITS"):
        Settings.from_env(
            {**BASE_ENV, "PROVIDER_CANARY_MAX_SPEND_MINOR_UNITS": "1"}
        )
    with pytest.raises(ValueError, match="PROVIDER_CANARY_MAX_ATTEMPTS"):
        Settings.from_env({**BASE_ENV, "PROVIDER_CANARY_MAX_ATTEMPTS": "50"})
    enabled = Settings.from_env(
        {
            **BASE_ENV,
            "PROVIDER_CANARY_CONTROLLER_ENABLED": "true",
            "PROVIDER_CANARY_ALLOWED_TENANT_IDS": "tenant-canary",
            "PROVIDER_CANARY_ALLOWED_TARGETS": "klyrow-email",
        }
    )
    assert enabled.provider_canary_controller_enabled is True


# --- API ----------------------------------------------------------------


class FakeTokens:
    def __init__(self):
        self.scopes: list[str] = []

    async def verify(self, authorization, *, expected_client_id, required_scope):
        assert authorization == "Bearer test"
        assert expected_client_id == "canary-operator"
        self.scopes.append(required_scope)
        return {"azp": expected_client_id, "scope": required_scope}


def _client(monkeypatch, **settings_changes):
    tokens = FakeTokens()
    app = FastAPI()
    app.state.runtime = SimpleNamespace(
        tokens=tokens, settings=_settings(**settings_changes)
    )
    app.include_router(canary_api.router)
    monkeypatch.setattr(
        canary_api,
        "caller_for_authorization",
        lambda _authorization: SimpleNamespace(client_id="canary-operator"),
    )
    monkeypatch.setattr(canary_api, "_now", lambda: NOW)
    return TestClient(app), tokens


HEADERS = {"Authorization": "Bearer test"}
BASE = "/internal/v1/provider-canaries"


def test_api_status_reports_disabled_live_path_and_caps(monkeypatch):
    client, tokens = _client(monkeypatch, provider_canary_controller_enabled=False)
    body = client.get(f"{BASE}/status", headers=HEADERS).json()
    assert body["controller_enabled"] is False
    assert body["execution_modes"] == ["synthetic"]
    assert body["live_execution_available"] is False
    assert body["caps"]["max_spend_minor_units"] == 0
    assert body["target_bindings"]["klyrow-email"] == {
        "provider": "postal",
        "capability": "email.send",
    }
    assert tokens.scopes == [canary_api.READ_SCOPE]


def test_api_policy_check_is_side_effect_free(monkeypatch):
    client, tokens = _client(monkeypatch)
    response = client.post(f"{BASE}/policy-check", headers=HEADERS, json=_plan())
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW_SYNTHETIC"
    denied = client.post(
        f"{BASE}/policy-check", headers=HEADERS, json=_plan(mode="live")
    )
    assert denied.status_code == 200
    assert "LIVE_EXECUTION_NOT_AUTHORIZED" in denied.json()["reasons"]
    status = client.get(f"{BASE}/status", headers=HEADERS).json()
    assert status["ledger"] == {"runs": 0, "denials": 0}
    assert canary_api.EXECUTE_SCOPE not in tokens.scopes


def test_api_synthetic_run_lifecycle(monkeypatch):
    client, tokens = _client(monkeypatch)
    created = client.post(f"{BASE}/synthetic-runs", headers=HEADERS, json=_plan())
    assert created.status_code == 201
    run = created.json()
    assert run["synthetic"] is True
    assert run["provider_effects"] == 0
    assert run["readback_verified"] is True
    assert run["decision"]["decision"] == "ALLOW_SYNTHETIC"
    assert canary_api.EXECUTE_SCOPE in tokens.scopes

    readback = client.get(f"{BASE}/synthetic-runs/{run['run_id']}", headers=HEADERS)
    assert readback.status_code == 200
    assert readback.json()["evidence_digest"] == run["evidence_digest"]

    replay = client.post(f"{BASE}/synthetic-runs", headers=HEADERS, json=_plan())
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["run_id"] == run["run_id"]

    conflict = client.post(
        f"{BASE}/synthetic-runs",
        headers=HEADERS,
        json=_plan(payload_fingerprint=canonical_fingerprint("changed")),
    )
    assert conflict.status_code == 409

    # The per-minute rate budget (1) is consumed by the first run.
    limited = client.post(
        f"{BASE}/synthetic-runs",
        headers=HEADERS,
        json=_plan(canary_id="pas57-email-002"),
    )
    assert limited.status_code == 403
    assert "RATE_BUDGET_EXHAUSTED" in limited.json()["reasons"]
    assert client.get(f"{BASE}/synthetic-runs/unknown", headers=HEADERS).status_code == 404


def test_api_denies_missing_prerequisites_and_records_denial(monkeypatch):
    client, _tokens = _client(monkeypatch)
    response = client.post(
        f"{BASE}/synthetic-runs",
        headers=HEADERS,
        json=_plan(evidence=[], kill_switch=None, readback=None),
    )
    assert response.status_code == 403
    reasons = response.json()["reasons"]
    for kind in REQUIRED_EVIDENCE_KINDS:
        assert f"EVIDENCE_MISSING:{kind}" in reasons
    assert "KILL_SWITCH_READBACK_MISSING" in reasons
    assert "READBACK_REQUIREMENT_MISSING" in reasons
    status = client.get(f"{BASE}/status", headers=HEADERS).json()
    assert status["ledger"] == {"runs": 0, "denials": 1}
    assert client.post(
        f"{BASE}/synthetic-runs", headers=HEADERS, json={"schema_version": "1.0"}
    ).status_code == 422


def test_api_kill_switch_blocks_runs_and_cannot_be_released(monkeypatch):
    client, tokens = _client(monkeypatch)
    engaged = client.post(
        f"{BASE}/kill-switch/engage", headers=HEADERS, json={"reason": "drill"}
    )
    assert engaged.status_code == 200
    assert engaged.json()["engaged"] is True
    assert engaged.json()["engaged_by"] == "canary-operator"
    assert canary_api.KILL_SCOPE in tokens.scopes
    again = client.post(
        f"{BASE}/kill-switch/engage", headers=HEADERS, json={"reason": "second"}
    )
    assert again.json()["reason"] == "drill"

    blocked = client.post(f"{BASE}/synthetic-runs", headers=HEADERS, json=_plan())
    assert blocked.status_code == 403
    assert "KILL_SWITCH_ENGAGED" in blocked.json()["reasons"]
    for path in ("/kill-switch/release", "/kill-switch/disengage", "/live-runs"):
        assert client.post(f"{BASE}{path}", headers=HEADERS, json={}).status_code == 404


def test_integration_registry_owns_provider_canary_router():
    from app.router_registry import INTEGRATION_ROUTERS

    assert canary_api.router in INTEGRATION_ROUTERS
