"""Fail-closed notification policy and lifecycle primitives.

This module is provider neutral and performs no network or database I/O.
"""

from dataclasses import dataclass
from datetime import datetime, time, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Any, Mapping


class Channel(StrEnum):
    EMAIL = "EMAIL"
    SMS = "SMS"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    CONSENT_MISSING = "CONSENT_MISSING"
    SUPPRESSED = "SUPPRESSED"
    QUIET_HOURS = "QUIET_HOURS"
    RATE_LIMITED = "RATE_LIMITED"
    COST_LIMITED = "COST_LIMITED"
    POLICY_STALE = "POLICY_STALE"
    FEATURE_DISABLED = "FEATURE_DISABLED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DESTINATION_PROHIBITED = "DESTINATION_PROHIBITED"


class CommandState(StrEnum):
    REQUESTED = "REQUESTED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    AUTHORIZING = "AUTHORIZING"
    AUTHORIZED = "AUTHORIZED"
    SUPPRESSED = "SUPPRESSED"
    RATE_LIMITED = "RATE_LIMITED"
    COST_LIMITED = "COST_LIMITED"
    RESERVED = "RESERVED"
    QUEUED = "QUEUED"
    DISPATCHING = "DISPATCHING"
    PROVIDER_ACCEPTED = "PROVIDER_ACCEPTED"
    DELIVERED = "DELIVERED"
    DEFERRED = "DEFERRED"
    BOUNCED = "BOUNCED"
    COMPLAINED = "COMPLAINED"
    UNSUBSCRIBED = "UNSUBSCRIBED"
    UNDELIVERED = "UNDELIVERED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"
    REPLAY_APPROVAL_REQUIRED = "REPLAY_APPROVAL_REQUIRED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


TERMINAL_STATES = frozenset(
    {
        CommandState.SUPPRESSED,
        CommandState.RATE_LIMITED,
        CommandState.COST_LIMITED,
        CommandState.DELIVERED,
        CommandState.BOUNCED,
        CommandState.COMPLAINED,
        CommandState.UNSUBSCRIBED,
        CommandState.UNDELIVERED,
        CommandState.DEAD_LETTER,
        CommandState.CANCELLED,
        CommandState.EXPIRED,
    }
)

ALLOWED_TRANSITIONS: Mapping[CommandState, frozenset[CommandState]] = {
    CommandState.REQUESTED: frozenset(
        {CommandState.VALIDATING, CommandState.CANCELLED}
    ),
    CommandState.VALIDATING: frozenset(
        {CommandState.VALIDATED, CommandState.FAILED, CommandState.EXPIRED}
    ),
    CommandState.VALIDATED: frozenset({CommandState.AUTHORIZING}),
    CommandState.AUTHORIZING: frozenset(
        {
            CommandState.AUTHORIZED,
            CommandState.SUPPRESSED,
            CommandState.RATE_LIMITED,
            CommandState.COST_LIMITED,
            CommandState.FAILED,
        }
    ),
    CommandState.AUTHORIZED: frozenset({CommandState.RESERVED, CommandState.CANCELLED}),
    CommandState.RESERVED: frozenset({CommandState.QUEUED, CommandState.FAILED}),
    CommandState.QUEUED: frozenset({CommandState.DISPATCHING, CommandState.CANCELLED}),
    CommandState.DISPATCHING: frozenset(
        {
            CommandState.PROVIDER_ACCEPTED,
            CommandState.RETRY_SCHEDULED,
            CommandState.DEAD_LETTER,
            CommandState.FAILED,
        }
    ),
    CommandState.PROVIDER_ACCEPTED: frozenset(
        {
            CommandState.DELIVERED,
            CommandState.DEFERRED,
            CommandState.BOUNCED,
            CommandState.COMPLAINED,
            CommandState.UNSUBSCRIBED,
            CommandState.UNDELIVERED,
            CommandState.RECONCILIATION_REQUIRED,
            CommandState.FAILED,
        }
    ),
    CommandState.DEFERRED: frozenset(
        {
            CommandState.RETRY_SCHEDULED,
            CommandState.DEAD_LETTER,
            CommandState.FAILED,
        }
    ),
    CommandState.RETRY_SCHEDULED: frozenset(
        {CommandState.QUEUED, CommandState.DEAD_LETTER}
    ),
    CommandState.FAILED: frozenset(
        {CommandState.DEAD_LETTER, CommandState.REPLAY_APPROVAL_REQUIRED}
    ),
    CommandState.REPLAY_APPROVAL_REQUIRED: frozenset(
        {CommandState.QUEUED, CommandState.CANCELLED}
    ),
    CommandState.RECONCILIATION_REQUIRED: frozenset(
        {CommandState.DELIVERED, CommandState.FAILED}
    ),
}


class InvalidNotificationTransition(ValueError):
    pass


class CommandType(StrEnum):
    EMAIL_SEND = "email.send"
    EMAIL_CANCEL = "email.cancel"
    EMAIL_SUPPRESS = "email.suppress"
    SMS_SEND = "sms.send"
    SMS_CANCEL = "sms.cancel"
    SMS_SUPPRESS = "sms.suppress"
    NOTIFICATION_AUTHORIZE = "notification.authorize"
    NOTIFICATION_REJECT = "notification.reject"
    WORKFLOW_PUBLISH = "workflow.publish"
    WORKFLOW_ACTIVATE = "workflow.activate"
    WORKFLOW_DEACTIVATE = "workflow.deactivate"
    EXTERNAL_EVENT_DELIVER = "external_event.deliver"
    DEAD_LETTER_REPLAY = "dead_letter.replay"
    RECONCILIATION_RUN = "reconciliation.run"


class InvalidNotificationCommand(ValueError):
    pass


@dataclass(frozen=True)
class NotificationCommand:
    schema_version: str
    command_id: str
    command_type: CommandType
    idempotency_key: str
    correlation_id: str
    causation_id: str
    organization_id: str
    business_unit_id: str
    campaign_id: str
    lead_id: str
    customer_id: str
    channel: Channel
    template_id: str
    template_version: int
    sender_profile_id: str
    destination_token: str
    destination_classification: str
    consent_evidence_id: str
    suppression_version: str
    policy_version: str
    policy_hash: str
    requested_by: str
    approved_by: str
    requested_at: datetime
    not_before: datetime
    expires_at: datetime
    timezone: str
    quiet_hours_policy: str
    rate_limit_bucket: str
    cost_limit_bucket: str
    pii_classification: str
    payload_hash: str
    template_variables: Mapping[str, Any]

    def validate(self) -> None:
        """Validate provider-neutral metadata without inspecting destinations."""
        required_text = {
            name: value for name, value in vars(self).items() if isinstance(value, str)
        }
        missing = sorted(name for name, value in required_text.items() if not value)
        if missing:
            raise InvalidNotificationCommand(
                "missing required fields: " + ",".join(missing)
            )
        if self.template_version < 1:
            raise InvalidNotificationCommand("template_version must be positive")
        if len(self.policy_hash) != 64 or len(self.payload_hash) != 64:
            raise InvalidNotificationCommand(
                "policy and payload hashes must be SHA-256"
            )
        if self.not_before < self.requested_at:
            raise InvalidNotificationCommand("not_before precedes requested_at")
        if self.expires_at <= self.not_before:
            raise InvalidNotificationCommand("command expiration is not future")


def validate_transition(current: CommandState, target: CommandState) -> None:
    if current in TERMINAL_STATES or target not in ALLOWED_TRANSITIONS.get(
        current, frozenset()
    ):
        raise InvalidNotificationTransition(f"{current.value}->{target.value}")


@dataclass(frozen=True)
class PolicyInput:
    channel: Channel
    organization_id: str
    business_unit_id: str
    campaign_id: str
    sender_profile_id: str
    destination_classification: str
    purpose: str
    policy_hash: str
    current_policy_hash: str
    consent_granted: bool
    suppression_active: bool
    feature_enabled: bool
    scope_allowed: bool
    sender_approved: bool
    destination_allowed: bool
    approval_present: bool
    rate_remaining: int
    estimated_cost_minor: int
    cost_remaining_minor: int
    requested_at: datetime
    expires_at: datetime
    quiet_hours_start: time | None = None
    quiet_hours_end: time | None = None


def evaluate_policy(value: PolicyInput) -> Decision:
    """Return the first stable fail-closed policy outcome."""
    now = value.requested_at.astimezone(timezone.utc)
    if value.expires_at.astimezone(timezone.utc) <= now:
        return Decision.DENY
    if not value.feature_enabled:
        return Decision.FEATURE_DISABLED
    if not value.scope_allowed:
        return Decision.SCOPE_MISMATCH
    if value.policy_hash != value.current_policy_hash:
        return Decision.POLICY_STALE
    if not value.approval_present:
        return Decision.APPROVAL_REQUIRED
    if not value.consent_granted:
        return Decision.CONSENT_MISSING
    if value.suppression_active:
        return Decision.SUPPRESSED
    if not value.sender_approved or not value.destination_allowed:
        return Decision.DESTINATION_PROHIBITED
    if value.rate_remaining < 1:
        return Decision.RATE_LIMITED
    if (
        value.estimated_cost_minor < 0
        or value.estimated_cost_minor > value.cost_remaining_minor
    ):
        return Decision.COST_LIMITED
    if _inside_quiet_hours(
        now.timetz().replace(tzinfo=None),
        value.quiet_hours_start,
        value.quiet_hours_end,
    ):
        return Decision.QUIET_HOURS
    return Decision.ALLOW


def _inside_quiet_hours(current: time, start: time | None, end: time | None) -> bool:
    if start is None or end is None:
        return False
    if start == end:
        return True
    if start < end:
        return start <= current < end
    return current >= start or current < end


def payload_digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def can_dispatch(
    *, channel: Channel, allow_live: bool, dispatcher_enabled: bool
) -> bool:
    """Both channel switches are mandatory; absence/false remains fail-closed."""
    return channel in {Channel.EMAIL, Channel.SMS} and allow_live and dispatcher_enabled
