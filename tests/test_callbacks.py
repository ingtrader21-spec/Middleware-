from datetime import datetime
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from pydantic import ValidationError

from app.api.v1.callbacks import CreateCallback, _view
from app.api.v1.callbacks import principal
from app.core.callbacks import (
    CallbackConflict,
    canonical_time,
    compliance_state,
    normalized_phone,
    reminders,
    transition,
)
from app.core.config import settings
from app.entrypoints.integration_api import app as integration_app
from app.db.models import CallbackRecord


def request(**overrides):
    value = {
        "tenant_id": "COD",
        "campaign_id": "TEST_SYN",
        "lead_id": "TEST-SYN-LEAD-1",
        "assigned_agent_id": "synthetic.agent.test.syn.6101",
        "phone_number": "+1 555 000 6101",
        "scheduled_at": "2026-08-25T10:00:00-04:00",
        "customer_timezone": "America/New_York",
        "reason": "Synthetic callback contract test",
        "compliance": {
            "consent": True,
            "dnc": False,
            "suppressed": False,
            "within_calling_hours": True,
            "campaign_allowed": True,
        },
    }
    value.update(overrides)
    return value


def test_contract_forbids_unknown_fields_and_orphans():
    with pytest.raises(ValidationError):
        CreateCallback.model_validate(request(extra_secret="no"))
    with pytest.raises(ValidationError):
        CreateCallback.model_validate(request(assigned_agent_id=None))


def test_timezone_requires_named_zone_matching_offset():
    body = CreateCallback.model_validate(request())
    assert (
        canonical_time(body.scheduled_at, body.customer_timezone).isoformat()
        == "2026-08-25T14:00:00+00:00"
    )
    with pytest.raises(ValueError):
        canonical_time(
            datetime.fromisoformat("2026-08-25T10:00:00-05:00"), "America/New_York"
        )
    with pytest.raises(ValueError):
        canonical_time(datetime(2026, 8, 25, 10), "America/New_York")


def test_state_machine_is_fail_closed():
    transition("DUE", "IN_PROGRESS")
    transition("IN_PROGRESS", "COMPLETED")
    with pytest.raises(CallbackConflict):
        transition("COMPLETED", "DUE")
    with pytest.raises(CallbackConflict):
        transition("CANCELLED", "SCHEDULED")


def test_compliance_denies_actionability():
    state, evidence = compliance_state(
        consent=True,
        dnc=True,
        suppressed=False,
        within_calling_hours=True,
        campaign_allowed=True,
    )
    assert state == "BLOCKED_COMPLIANCE" and evidence["dnc_clear"] is False


def test_phone_and_reminder_policy():
    assert normalized_phone("+1 (555) 000-6101") == "+15550006101"
    at = datetime.fromisoformat("2026-08-25T14:00:00+00:00")
    r1, r2, popup = reminders(at)
    assert (
        (at - r1).total_seconds() == 86400
        and (at - r2).total_seconds() == 3600
        and (at - popup).total_seconds() == 900
    )


def _mounted_paths(routes, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            paths |= _mounted_paths(
                original.routes, prefix + (getattr(context, "prefix", "") or "")
            )
            continue
        path = getattr(route, "path", None)
        if path is not None:
            paths.add(prefix + path)
    return paths


def test_production_runtime_exposes_callback_contract_fail_closed():
    paths = _mounted_paths(integration_app.router.routes)
    assert "/api/v1/control/callbacks" in paths
    assert settings.callback_scheduler_enabled is False
    assert settings.callback_delivery_enabled is False
    assert settings.callback_test_syn_enabled is False


def test_callback_principal_is_derived_from_verified_claims(monkeypatch):
    claims = {
        "sub": "agent-6101",
        "tenant_id": "COD",
        "campaigns": ["TEST_SYN"],
        "teams": ["SYN_TEAM"],
        "realm_access": {"roles": ["agent"]},
    }
    monkeypatch.setattr(
        "app.api.v1.callbacks.KeycloakValidator.validate", lambda self, token: claims
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/control/callbacks",
            "headers": [],
        }
    )
    value = principal(request, "Bearer synthetic.jwt.value")
    assert (
        value.tenant == "COD"
        and value.campaigns == frozenset({"TEST_SYN"})
        and value.role == "agent"
    )


def test_callback_principal_rejects_missing_bearer():
    request = Request(
        {"type": "http", "method": "GET", "path": "/api/v1/callbacks", "headers": []}
    )
    with pytest.raises(HTTPException) as denied:
        principal(request, "")
    assert denied.value.status_code == 401


def test_reconciliation_view_preserves_completion_details():
    row = CallbackRecord(
        id="018f0000-0000-7000-8000-000000000001",
        tenant_id="COD",
        campaign_id="TEST_SYN",
        assigned_agent_id="synthetic.agent.test.syn.6101",
        scheduled_at=datetime.fromisoformat("2026-08-25T14:00:00+00:00"),
        customer_timezone="UTC",
        priority="NORMAL",
        reason="Synthetic reconciliation",
        notes="",
        state="COMPLETED",
        version=4,
        correlation_id="TEST-SYN-CORRELATION",
        completion_disposition="SYNTHETIC_COMPLETE",
        completion_notes="Synthetic callback completed without PSTN",
        context_json={},
    )
    payload = _view(row)
    assert payload["completion_disposition"] == "SYNTHETIC_COMPLETE"
    assert payload["completion_notes"] == "Synthetic callback completed without PSTN"
