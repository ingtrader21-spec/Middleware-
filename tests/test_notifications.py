from datetime import datetime, time, timedelta, timezone

import pytest

from app.core.notifications import (
    Channel,
    CommandType,
    CommandState,
    Decision,
    InvalidNotificationCommand,
    InvalidNotificationTransition,
    NotificationCommand,
    PolicyInput,
    can_dispatch,
    evaluate_policy,
    payload_digest,
    validate_transition,
)


def policy(**overrides):
    now = datetime(2026, 7, 28, 15, tzinfo=timezone.utc)
    values = {
        "channel": Channel.EMAIL,
        "organization_id": "ORG-1",
        "business_unit_id": "BU-1",
        "campaign_id": "CMP-1",
        "sender_profile_id": "SENDER-1",
        "destination_classification": "APPROVED_EMPLOYEE_TEST",
        "purpose": "INTERNAL_CANARY",
        "policy_hash": "a" * 64,
        "current_policy_hash": "a" * 64,
        "consent_granted": True,
        "suppression_active": False,
        "feature_enabled": True,
        "scope_allowed": True,
        "sender_approved": True,
        "destination_allowed": True,
        "approval_present": True,
        "rate_remaining": 1,
        "estimated_cost_minor": 1,
        "cost_remaining_minor": 10,
        "requested_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    values.update(overrides)
    return PolicyInput(**values)


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"feature_enabled": False}, Decision.FEATURE_DISABLED),
        ({"scope_allowed": False}, Decision.SCOPE_MISMATCH),
        ({"current_policy_hash": "b" * 64}, Decision.POLICY_STALE),
        ({"approval_present": False}, Decision.APPROVAL_REQUIRED),
        ({"consent_granted": False}, Decision.CONSENT_MISSING),
        ({"suppression_active": True}, Decision.SUPPRESSED),
        ({"sender_approved": False}, Decision.DESTINATION_PROHIBITED),
        ({"destination_allowed": False}, Decision.DESTINATION_PROHIBITED),
        ({"rate_remaining": 0}, Decision.RATE_LIMITED),
        ({"estimated_cost_minor": 11}, Decision.COST_LIMITED),
    ],
)
def test_policy_fails_closed(override, expected):
    assert evaluate_policy(policy(**override)) is expected


def test_policy_allows_only_complete_scope():
    assert evaluate_policy(policy()) is Decision.ALLOW


def test_quiet_hours_cross_midnight():
    assert (
        evaluate_policy(
            policy(
                requested_at=datetime(2026, 7, 28, 23, tzinfo=timezone.utc),
                expires_at=datetime(2026, 7, 29, 0, tzinfo=timezone.utc),
                quiet_hours_start=time(22),
                quiet_hours_end=time(8),
            )
        )
        is Decision.QUIET_HOURS
    )


def test_dispatch_requires_both_switches():
    assert not can_dispatch(
        channel=Channel.EMAIL, allow_live=False, dispatcher_enabled=True
    )
    assert not can_dispatch(
        channel=Channel.EMAIL, allow_live=True, dispatcher_enabled=False
    )
    assert can_dispatch(channel=Channel.EMAIL, allow_live=True, dispatcher_enabled=True)


def test_no_requested_to_completed_jump():
    with pytest.raises(InvalidNotificationTransition):
        validate_transition(CommandState.REQUESTED, CommandState.DELIVERED)


def test_terminal_state_cannot_transition():
    with pytest.raises(InvalidNotificationTransition):
        validate_transition(CommandState.SUPPRESSED, CommandState.QUEUED)


def test_reviewed_path_reaches_reservation():
    validate_transition(CommandState.REQUESTED, CommandState.VALIDATING)
    validate_transition(CommandState.VALIDATING, CommandState.VALIDATED)
    validate_transition(CommandState.VALIDATED, CommandState.AUTHORIZING)
    validate_transition(CommandState.AUTHORIZING, CommandState.AUTHORIZED)
    validate_transition(CommandState.AUTHORIZED, CommandState.RESERVED)


def test_payload_hash_is_exact_bytes():
    assert (
        payload_digest(b"{}")
        == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )


def command(**overrides):
    now = datetime(2026, 7, 29, 12, tzinfo=timezone.utc)
    values = {
        "schema_version": "notification-command.v1",
        "command_id": "CMD-1",
        "command_type": CommandType.EMAIL_SEND,
        "idempotency_key": "IDEMPOTENCY-1",
        "correlation_id": "CORRELATION-1",
        "causation_id": "CAUSATION-1",
        "organization_id": "ORG-1",
        "business_unit_id": "BU-1",
        "campaign_id": "CMP-1",
        "lead_id": "LEAD-1",
        "customer_id": "CUSTOMER-1",
        "channel": Channel.EMAIL,
        "template_id": "TEMPLATE-1",
        "template_version": 1,
        "sender_profile_id": "SENDER-1",
        "destination_token": "opaque-destination-token",
        "destination_classification": "APPROVED_EMPLOYEE_TEST",
        "consent_evidence_id": "CONSENT-1",
        "suppression_version": "SUPPRESSION-1",
        "policy_version": "POLICY-1",
        "policy_hash": "a" * 64,
        "requested_by": "USER-1",
        "approved_by": "APPROVER-1",
        "requested_at": now,
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "timezone": "UTC",
        "quiet_hours_policy": "INTERNAL-TEST",
        "rate_limit_bucket": "BU-1:EMAIL",
        "cost_limit_bucket": "BU-1:EMAIL",
        "pii_classification": "TOKENIZED",
        "payload_hash": "b" * 64,
        "template_variables": {"first_name": "synthetic"},
    }
    values.update(overrides)
    return NotificationCommand(**values)


def test_common_command_contract_accepts_complete_tokenized_metadata():
    command().validate()


@pytest.mark.parametrize(
    "override",
    [
        {"destination_token": ""},
        {"template_version": 0},
        {"policy_hash": "short"},
        {
            "not_before": datetime(2026, 7, 29, 11, tzinfo=timezone.utc),
        },
    ],
)
def test_common_command_contract_fails_closed(override):
    with pytest.raises(InvalidNotificationCommand):
        command(**override).validate()


@pytest.mark.parametrize(
    "target",
    [
        CommandState.DELIVERED,
        CommandState.DEFERRED,
        CommandState.BOUNCED,
        CommandState.COMPLAINED,
        CommandState.UNSUBSCRIBED,
        CommandState.UNDELIVERED,
    ],
)
def test_provider_receipt_states_are_explicit(target):
    validate_transition(CommandState.PROVIDER_ACCEPTED, target)
