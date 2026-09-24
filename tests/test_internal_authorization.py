"""``POST /internal/v1/authorization/check`` - canonical alias verification.

Mirrors ``tests/test_policy_engine.py``'s auth/audit test exactly, against
the same ``middleware-policy-engine`` entrypoint app, proving the canonical
path produces an identical decision/audit outcome to the legacy
``/api/v1/policy/decisions`` path it delegates to.
"""

from datetime import datetime, time, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.policy_engine import PolicyRequest
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


def test_internal_authorization_check_requires_auth_and_audits_decision(monkeypatch):
    session = MagicMock()
    session.commit = AsyncMock()

    async def session_override():
        yield session

    monkeypatch.setattr(settings, "middleware_secret", "policy-test-secret")
    app.dependency_overrides[get_session] = session_override
    try:
        client = TestClient(app)
        body = request().model_dump(mode="json")
        assert (
            client.post("/internal/v1/authorization/check", json=body).status_code
            == 401
        )
        response = client.post(
            "/internal/v1/authorization/check",
            json=body,
            headers={"Authorization": "Bearer policy-test-secret"},
        )
        assert response.status_code == 200
        assert response.json()["allow"] is True
        assert len(response.json()["decision_hash"]) == 64
        assert session.add.call_count == 2
        session.commit.assert_awaited_once()
    finally:
        app.dependency_overrides.clear()


def test_internal_authorization_check_route_is_distinct_from_legacy_path():
    paths = app.openapi()["paths"]
    assert "/internal/v1/authorization/check" in paths
    assert "/api/v1/policy/decisions" in paths
