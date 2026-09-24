from datetime import datetime, time, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.policy_engine import PolicyRequest, evaluate
from app.db.session import get_session
from app.entrypoints.policy_engine import app


NOW = datetime(2026, 7, 26, 15, 0, tzinfo=timezone.utc)


def request(**overrides):
    values = {
        "correlation_id": "policy-test",
        "action": "voice",
        "subject": "synthetic-subject",
        "resource": "synthetic-resource",
        "environment": "staging",
        "evaluated_at": NOW,
        "consent_allowed": True,
        "consent_observed_at": NOW - timedelta(minutes=5),
        "dnc_suppressed": False,
        "dnc_observed_at": NOW - timedelta(minutes=5),
        "customer_timezone": "America/Santo_Domingo",
        "jurisdiction": "DO",
        "calling_window_start": time(8),
        "calling_window_end": time(20),
        "attempts": 0,
        "max_attempts": 3,
        "minimum_spacing_seconds": 300,
        "channel_eligible": True,
        "business_unit": "MOY",
        "allowed_business_units": ["MOY"],
        "campaign": "TEST_SYN",
        "allowed_campaigns": ["TEST_SYN"],
        "agent": "SYNTHETIC",
        "allowed_agents": ["SYNTHETIC"],
        "callback_allowed": True,
        "transfer_allowed": True,
        "recording_required": False,
        "disclosure_present": True,
        "emergency_kill_switch": False,
    }
    values.update(overrides)
    return PolicyRequest(**values)


def test_complete_fresh_policy_allows_in_shadow_and_enforcement():
    shadow = evaluate(request())
    assert shadow.allow and not shadow.enforced
    enforced = evaluate(request(shadow_mode=False))
    assert enforced.allow and enforced.enforced
    assert enforced.policy_version and enforced.decision_id
    assert enforced.expiration > enforced.evaluated_at


def test_missing_and_stale_data_deny():
    missing = evaluate(request(consent_allowed=None))
    assert not missing.allow and "missing_consent_data" in missing.reason_codes
    missing_observation = evaluate(request(consent_observed_at=None))
    assert not missing_observation.allow
    assert missing_observation.data_freshness["consent"] == "missing"
    stale = evaluate(request(consent_observed_at=NOW - timedelta(hours=25)))
    assert not stale.allow and "stale_consent_data" in stale.reason_codes


def test_dnc_kill_switch_access_and_attempt_controls_deny():
    assert "dnc_suppressed" in evaluate(request(dnc_suppressed=True)).reason_codes
    assert (
        "emergency_kill_switch"
        in evaluate(request(emergency_kill_switch=True)).reason_codes
    )
    assert "campaign_denied" in evaluate(request(campaign="OTHER")).reason_codes
    assert "attempt_limit_reached" in evaluate(request(attempts=3)).reason_codes
    assert (
        "minimum_attempt_spacing"
        in evaluate(request(last_attempt_at=NOW - timedelta(seconds=30))).reason_codes
    )


def test_timezone_midnight_dst_and_jurisdiction_boundaries():
    dst_now = datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc)
    overnight = evaluate(
        request(
            customer_timezone="America/New_York",
            evaluated_at=dst_now,
            consent_observed_at=dst_now - timedelta(minutes=5),
            dnc_observed_at=dst_now - timedelta(minutes=5),
            calling_window_start=time(22),
            calling_window_end=time(7),
        )
    )
    assert overnight.allow
    midnight_denied = evaluate(
        request(
            evaluated_at=datetime(2026, 7, 26, 4, 0, tzinfo=timezone.utc),
        )
    )
    assert "outside_calling_hours" in midnight_denied.reason_codes
    invalid_zone = evaluate(request(customer_timezone="Invalid/Zone"))
    assert "invalid_customer_timezone" in invalid_zone.reason_codes
    missing_jurisdiction = evaluate(request(jurisdiction=None))
    assert "missing_jurisdiction_data" in missing_jurisdiction.reason_codes


def test_callback_transfer_and_recording_disclosure_are_explicit():
    assert (
        "callback_denied"
        in evaluate(request(action="callback", callback_allowed=False)).reason_codes
    )


def test_policy_api_requires_auth_and_audits_decision(monkeypatch):
    session = MagicMock()
    session.commit = AsyncMock()

    async def session_override():
        yield session

    monkeypatch.setattr(settings, "middleware_secret", "policy-test-secret")
    app.dependency_overrides[get_session] = session_override
    try:
        client = TestClient(app)
        body = request().model_dump(mode="json")
        assert client.post("/api/v1/policy/decisions", json=body).status_code == 401
        response = client.post(
            "/api/v1/policy/decisions",
            json=body,
            headers={"Authorization": "Bearer policy-test-secret"},
        )
        assert response.status_code == 200
        assert response.json()["allow"] is True
        assert len(response.json()["decision_hash"]) == 64
        assert response.json()["authorization_scope"] == {
            "action": "voice",
            "subject": "synthetic-subject",
            "resource": "synthetic-resource",
            "environment": "staging",
            "business_unit": "MOY",
            "campaign": "TEST_SYN",
            "agent": "SYNTHETIC",
        }
        assert session.add.call_count == 2
        session.commit.assert_awaited_once()
    finally:
        app.dependency_overrides.clear()
    assert (
        "transfer_denied"
        in evaluate(request(action="transfer", transfer_allowed=False)).reason_codes
    )
    assert (
        "recording_disclosure_missing"
        in evaluate(
            request(
                action="recording",
                recording_required=True,
                disclosure_present=False,
            )
        ).reason_codes
    )
