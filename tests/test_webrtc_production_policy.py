from datetime import datetime, time, timedelta, timezone

import pytest

from app.core.webrtc_production_policy import (
    CallRequest,
    Capacity,
    Consent,
    Decision,
    Policy,
    RecordingPolicy,
    authorize,
)


NOW = datetime(2026, 8, 20, 15, 0, tzinfo=timezone.utc)


def policy(**changes):
    value = Policy(
        version="v1",
        enabled=True,
        kill_switch=False,
        allowed_campaign="COD400",
        allowed_business_unit="COD",
        allowed_agent="sub-1",
        allowed_extension="7410",
        allowed_caller_id="+18095550100",
        allowed_destination="+18095550101",
        allowed_destination_classes=frozenset({"CONSENTED_PILOT"}),
        allowed_countries=frozenset({"DO"}),
        timezone="America/Santo_Domingo",
        calling_start=time(8),
        calling_end=time(18),
        allowed_weekdays=frozenset(range(5)),
        pilot_start=NOW - timedelta(hours=1),
        pilot_end=NOW + timedelta(hours=1),
        max_concurrent_calls=1,
        max_call_attempts=1,
        recording=RecordingPolicy(),
        emergency_blocking=True,
        premium_blocking=True,
        consent_required=True,
    )
    return Policy(**{**value.__dict__, **changes})


def request(**changes):
    value = CallRequest(
        correlation_id="corr",
        agent_subject="sub-1",
        tenant="tenant",
        business_unit="COD",
        campaign="COD400",
        extension="7410",
        caller_id="+18095550100",
        destination="+18095550101",
        destination_class="CONSENTED_PILOT",
        destination_country="DO",
        destination_timezone="America/Santo_Domingo",
        recording_requested=False,
        consent=Consent(
            "granted",
            "production-webrtc-pilot",
            NOW - timedelta(days=1),
            NOW + timedelta(days=1),
            "written",
            "ref-1",
        ),
        requested_at=NOW,
    )
    return CallRequest(**{**value.__dict__, **changes})


def test_default_policy_is_deny_and_invalid_for_activation(tmp_path):
    value = Policy.from_file(
        __import__("pathlib").Path("config/webrtc-production-policy.default-deny.json")
    )
    assert authorize(value, request()) == Decision.DENY
    assert value.validate_for_activation()


@pytest.mark.parametrize(
    ("change", "decision"),
    [
        ({"kill_switch": True}, Decision.DENY),
        ({"allowed_campaign": "OTHER"}, Decision.DENY_UNAUTHORIZED_CAMPAIGN),
        ({"allowed_agent": "other"}, Decision.DENY_UNAUTHORIZED_AGENT),
        ({"allowed_caller_id": "+18095550999"}, Decision.DENY_UNAUTHORIZED_CALLER_ID),
        ({"allowed_destination": "+18095550999"}, Decision.DENY_PROHIBITED),
        ({"allowed_countries": frozenset({"US"})}, Decision.DENY_UNSUPPORTED_COUNTRY),
        ({"pilot_end": NOW}, Decision.DENY_OUTSIDE_PILOT_WINDOW),
        ({"calling_start": time(12)}, Decision.DENY_OUTSIDE_CALLING_HOURS),
    ],
)
def test_fail_closed_policy_decisions(change, decision):
    assert authorize(policy(**change), request()) == decision


def test_consent_missing_expired_and_wrong_scope_denied():
    assert authorize(policy(), request(consent=None)) == Decision.DENY_NO_CONSENT
    assert (
        authorize(
            policy(),
            request(
                consent=Consent(
                    "granted", "wrong", NOW, NOW + timedelta(1), "written", "ref"
                )
            ),
        )
        == Decision.DENY_NO_CONSENT
    )


def test_destination_class_and_recording_policy_fail_closed():
    assert (
        authorize(policy(), request(destination_class="UNKNOWN"))
        == Decision.DENY_PROHIBITED
    )
    assert authorize(policy(), request(recording_requested=True)) == Decision.DENY
    assert (
        authorize(
            policy(recording=RecordingPolicy(mode="required")),
            request(recording_requested=False),
        )
        == Decision.DENY
    )
    assert (
        authorize(
            policy(),
            request(
                consent=Consent(
                    "granted",
                    "production-webrtc-pilot",
                    NOW - timedelta(2),
                    NOW - timedelta(1),
                    "written",
                    "ref",
                )
            ),
        )
        == Decision.DENY_NO_CONSENT
    )


def test_country_aware_emergency_premium_and_prohibited_denied():
    assert (
        authorize(policy(allowed_destination="+1911"), request(destination="+1911"))
        == Decision.DENY_EMERGENCY
    )
    assert (
        authorize(
            policy(allowed_destination="+19005550100"),
            request(destination="+19005550100", destination_country="US"),
        )
        == Decision.DENY_PREMIUM
    )
    assert (
        authorize(
            policy(prohibited_destinations=frozenset({"+18095550101"})), request()
        )
        == Decision.DENY_PROHIBITED
    )


def test_capacity_is_one_attempt_and_kill_switch_precedes_inconsistent_state():
    capacity = Capacity()
    assert authorize(policy(), request(), capacity) == Decision.ALLOW
    capacity.release()
    assert authorize(policy(), request(), capacity) == Decision.DENY_CAPACITY
    assert (
        authorize(policy(kill_switch=True, allowed_campaign="WRONG"), request())
        == Decision.DENY
    )


def test_timezone_is_destination_local_and_dst_aware():
    ny_now = datetime(2026, 3, 9, 14, 0, tzinfo=timezone.utc)
    p = policy(
        timezone="America/New_York",
        allowed_countries=frozenset({"US"}),
        pilot_start=ny_now - timedelta(1),
        pilot_end=ny_now + timedelta(1),
    )
    r = request(
        destination_country="US",
        destination_timezone="America/New_York",
        requested_at=ny_now,
    )
    assert authorize(p, r) == Decision.ALLOW


def test_audit_redacts_phone_values(caplog):
    with caplog.at_level("INFO", logger="codestra.telephony_policy"):
        assert authorize(policy(), request()) == Decision.ALLOW
    assert "+18095550100" not in caplog.text and "+18095550101" not in caplog.text
    assert "destination_reference" in caplog.text and "policy_result" in caplog.text
