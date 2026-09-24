"""Provider-neutral delivery contracts and fail-closed adapters.

These are value objects over the authoritative notification command journal.
They perform no database I/O and introduce no second command or audit store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
import json
from typing import Mapping, Protocol, Sequence


class ProviderContractError(ValueError):
    """A provider-neutral contract failed validation."""


class ProviderDeliveryDisabled(PermissionError):
    """External delivery is disabled or outside the synthetic test scope."""


class DeliveryState(StrEnum):
    REQUESTED = "REQUESTED"
    POLICY_CHECKED = "POLICY_CHECKED"
    SUPPRESSED = "SUPPRESSED"
    APPROVED = "APPROVED"
    DISPATCH_RESERVED = "DISPATCH_RESERVED"
    DISPATCHED = "DISPATCHED"
    PROVIDER_ACCEPTED = "PROVIDER_ACCEPTED"
    DELIVERED = "DELIVERED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_TERMINAL = "FAILED_TERMINAL"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    RECONCILED = "RECONCILED"
    QUARANTINED = "QUARANTINED"


TERMINAL_DELIVERY_STATES = frozenset(
    {
        DeliveryState.SUPPRESSED,
        DeliveryState.DELIVERED,
        DeliveryState.FAILED_TERMINAL,
        DeliveryState.EXPIRED,
        DeliveryState.CANCELLED,
        DeliveryState.RECONCILED,
        DeliveryState.QUARANTINED,
    }
)

DELIVERY_TRANSITIONS: Mapping[DeliveryState, frozenset[DeliveryState]] = {
    DeliveryState.REQUESTED: frozenset(
        {
            DeliveryState.POLICY_CHECKED,
            DeliveryState.EXPIRED,
            DeliveryState.CANCELLED,
            DeliveryState.QUARANTINED,
        }
    ),
    DeliveryState.POLICY_CHECKED: frozenset(
        {
            DeliveryState.SUPPRESSED,
            DeliveryState.APPROVED,
            DeliveryState.QUARANTINED,
        }
    ),
    DeliveryState.APPROVED: frozenset(
        {DeliveryState.DISPATCH_RESERVED, DeliveryState.CANCELLED}
    ),
    DeliveryState.DISPATCH_RESERVED: frozenset(
        {
            DeliveryState.DISPATCHED,
            DeliveryState.FAILED_RETRYABLE,
            DeliveryState.FAILED_TERMINAL,
            DeliveryState.CANCELLED,
        }
    ),
    DeliveryState.DISPATCHED: frozenset(
        {
            DeliveryState.PROVIDER_ACCEPTED,
            DeliveryState.FAILED_RETRYABLE,
            DeliveryState.FAILED_TERMINAL,
            DeliveryState.QUARANTINED,
        }
    ),
    DeliveryState.PROVIDER_ACCEPTED: frozenset(
        {
            DeliveryState.DELIVERED,
            DeliveryState.FAILED_RETRYABLE,
            DeliveryState.FAILED_TERMINAL,
            DeliveryState.QUARANTINED,
        }
    ),
    DeliveryState.FAILED_RETRYABLE: frozenset(
        {
            DeliveryState.DISPATCH_RESERVED,
            DeliveryState.FAILED_TERMINAL,
            DeliveryState.CANCELLED,
        }
    ),
}


def validate_delivery_transition(current: DeliveryState, target: DeliveryState) -> None:
    if current in TERMINAL_DELIVERY_STATES or target not in DELIVERY_TRANSITIONS.get(
        current, frozenset()
    ):
        raise ProviderContractError(f"invalid delivery transition {current}->{target}")


def _require_text(values: Mapping[str, str]) -> None:
    missing = sorted(key for key, value in values.items() if not value.strip())
    if missing:
        raise ProviderContractError("missing required fields: " + ",".join(missing))


def _require_sha256(name: str, value: str) -> None:
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ProviderContractError(f"{name} must be a lowercase SHA-256")


@dataclass(frozen=True)
class CommunicationRecipient:
    destination_token: str
    destination_classification: str
    channel: str

    def validate(self) -> None:
        _require_text(
            {
                "destination_token": self.destination_token,
                "destination_classification": self.destination_classification,
                "channel": self.channel,
            }
        )


@dataclass(frozen=True)
class CommunicationContentReference:
    reference: str
    version: int
    content_hash: str

    def validate(self) -> None:
        _require_text({"reference": self.reference})
        if self.version < 1:
            raise ProviderContractError("content version must be positive")
        _require_sha256("content_hash", self.content_hash)


@dataclass(frozen=True)
class CommunicationCommand:
    command_id: str
    idempotency_key: str
    correlation_id: str
    causation_id: str
    test_run_id: str
    record_environment: str
    organization_id: str
    business_unit_id: str
    campaign_id: str
    lead_public_id: str
    agent_public_id: str
    channel: str
    message_purpose: str
    consent_reference: str
    suppression_check_version: str
    provider_adapter: str
    recipient: CommunicationRecipient
    content: CommunicationContentReference
    requested_at: datetime
    expires_at: datetime
    policy_hash: str

    def validate(self) -> None:
        _require_text(
            {
                "command_id": self.command_id,
                "idempotency_key": self.idempotency_key,
                "correlation_id": self.correlation_id,
                "causation_id": self.causation_id,
                "test_run_id": self.test_run_id,
                "record_environment": self.record_environment,
                "organization_id": self.organization_id,
                "business_unit_id": self.business_unit_id,
                "campaign_id": self.campaign_id,
                "lead_public_id": self.lead_public_id,
                "agent_public_id": self.agent_public_id,
                "channel": self.channel,
                "message_purpose": self.message_purpose,
                "consent_reference": self.consent_reference,
                "suppression_check_version": self.suppression_check_version,
                "provider_adapter": self.provider_adapter,
            }
        )
        self.recipient.validate()
        self.content.validate()
        _require_sha256("policy_hash", self.policy_hash)
        if self.expires_at <= self.requested_at:
            raise ProviderContractError("command is already expired")


@dataclass(frozen=True)
class ProviderDispatchRequest:
    command: CommunicationCommand
    attempt_number: int

    def validate(self) -> None:
        self.command.validate()
        if self.attempt_number < 1:
            raise ProviderContractError("attempt_number must be positive")


@dataclass(frozen=True)
class ProviderDispatchResponse:
    provider_id: str
    state: DeliveryState
    response_code: str
    response_summary: str
    response_hash: str
    received_at: datetime


@dataclass(frozen=True)
class ProviderWebhookEnvelope:
    provider: str
    provider_account: str
    provider_event_id: str
    received_at: datetime
    occurred_at: datetime
    payload_hash: str
    raw_body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)


@dataclass(frozen=True)
class NormalizedDeliveryEvent:
    provider_event_id: str
    provider_id: str
    command_id: str
    correlation_id: str
    state: DeliveryState
    occurred_at: datetime
    payload_hash: str


@dataclass(frozen=True)
class SuppressionEvent:
    event_id: str
    scope: str
    reason: str
    destination_token: str
    occurred_at: datetime
    correlation_id: str


@dataclass(frozen=True)
class ReconciliationResult:
    command_id: str
    desired_state: DeliveryState
    observed_state: DeliveryState
    drift_classification: str
    checked_at: datetime


class ProviderAdapter(Protocol):
    name: str

    def validate_configuration(self) -> None: ...

    def validate_destination(self, recipient: CommunicationRecipient) -> None: ...

    def dispatch(
        self, request: ProviderDispatchRequest
    ) -> ProviderDispatchResponse: ...

    def query_status(self, provider_id: str) -> ProviderDispatchResponse: ...

    def normalize_webhook(
        self, envelope: ProviderWebhookEnvelope
    ) -> Sequence[NormalizedDeliveryEvent]: ...

    def classify_error(self, error: Exception) -> str: ...

    def reconcile(
        self, *, command_id: str, desired_state: DeliveryState, provider_id: str
    ) -> ReconciliationResult: ...

    def health(self) -> Mapping[str, str]: ...

    def readiness(self) -> Mapping[str, str]: ...


class NullProviderAdapter:
    """Fail-closed adapter used whenever an external provider is not approved."""

    name = "null"

    def validate_configuration(self) -> None:
        return None

    def validate_destination(self, recipient: CommunicationRecipient) -> None:
        recipient.validate()
        raise ProviderDeliveryDisabled("external provider delivery is disabled")

    def dispatch(self, request: ProviderDispatchRequest) -> ProviderDispatchResponse:
        request.validate()
        raise ProviderDeliveryDisabled("external provider delivery is disabled")

    def query_status(self, provider_id: str) -> ProviderDispatchResponse:
        raise ProviderDeliveryDisabled("external provider status is unavailable")

    def normalize_webhook(
        self, envelope: ProviderWebhookEnvelope
    ) -> Sequence[NormalizedDeliveryEvent]:
        raise ProviderDeliveryDisabled("external provider webhook is disabled")

    def classify_error(self, error: Exception) -> str:
        return "FAILED_TERMINAL"

    def reconcile(
        self, *, command_id: str, desired_state: DeliveryState, provider_id: str
    ) -> ReconciliationResult:
        raise ProviderDeliveryDisabled("external provider reconciliation is disabled")

    def health(self) -> Mapping[str, str]:
        return {"status": "disabled", "network": "not_used"}

    def readiness(self) -> Mapping[str, str]:
        return {"status": "not_ready", "reason": "external_delivery_disabled"}


class SyntheticSinkAdapter:
    """Deterministic in-memory test sink that never opens a network connection."""

    name = "synthetic-sink"

    def __init__(self) -> None:
        self._responses: dict[str, ProviderDispatchResponse] = {}

    def validate_configuration(self) -> None:
        return None

    def validate_destination(self, recipient: CommunicationRecipient) -> None:
        recipient.validate()
        if recipient.destination_classification != "APPROVED_SYNTHETIC":
            raise ProviderDeliveryDisabled("synthetic destination is not approved")

    def dispatch(self, request: ProviderDispatchRequest) -> ProviderDispatchResponse:
        request.validate()
        self.validate_destination(request.command.recipient)
        if request.command.record_environment != "TEST":
            raise ProviderDeliveryDisabled("synthetic sink accepts TEST records only")
        existing = self._responses.get(request.command.idempotency_key)
        if existing is not None:
            return existing
        identity = sha256(
            (
                request.command.command_id
                + "\0"
                + request.command.idempotency_key
                + "\0"
                + request.command.content.content_hash
            ).encode()
        ).hexdigest()
        response_summary = "synthetic provider accepted"
        response_hash = sha256(response_summary.encode()).hexdigest()
        response = ProviderDispatchResponse(
            provider_id=f"synthetic:{identity}",
            state=DeliveryState.PROVIDER_ACCEPTED,
            response_code="SYNTHETIC_ACCEPTED",
            response_summary=response_summary,
            response_hash=response_hash,
            received_at=request.command.requested_at,
        )
        self._responses[request.command.idempotency_key] = response
        return response

    def query_status(self, provider_id: str) -> ProviderDispatchResponse:
        for response in self._responses.values():
            if response.provider_id == provider_id:
                return response
        raise ProviderContractError("unknown synthetic provider object")

    def normalize_webhook(
        self, envelope: ProviderWebhookEnvelope
    ) -> Sequence[NormalizedDeliveryEvent]:
        _require_sha256("payload_hash", envelope.payload_hash)
        try:
            value = json.loads(envelope.raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderContractError("invalid synthetic webhook JSON") from exc
        required = {"provider_id", "command_id", "correlation_id", "state"}
        if not isinstance(value, dict) or not required.issubset(value):
            raise ProviderContractError("invalid synthetic webhook schema")
        try:
            state = DeliveryState(value["state"])
        except (TypeError, ValueError) as exc:
            raise ProviderContractError("invalid synthetic delivery state") from exc
        return (
            NormalizedDeliveryEvent(
                provider_event_id=envelope.provider_event_id,
                provider_id=str(value["provider_id"]),
                command_id=str(value["command_id"]),
                correlation_id=str(value["correlation_id"]),
                state=state,
                occurred_at=envelope.occurred_at,
                payload_hash=envelope.payload_hash,
            ),
        )

    def classify_error(self, error: Exception) -> str:
        if isinstance(error, ProviderDeliveryDisabled):
            return "FAILED_TERMINAL"
        return "FAILED_RETRYABLE"

    def reconcile(
        self, *, command_id: str, desired_state: DeliveryState, provider_id: str
    ) -> ReconciliationResult:
        response = self.query_status(provider_id)
        observed = response.state
        return ReconciliationResult(
            command_id=command_id,
            desired_state=desired_state,
            observed_state=observed,
            drift_classification=(
                "NO_DRIFT" if desired_state is observed else "STATUS_MISMATCH"
            ),
            checked_at=response.received_at,
        )

    def health(self) -> Mapping[str, str]:
        return {"status": "ok", "network": "not_used"}

    def readiness(self) -> Mapping[str, str]:
        return {"status": "ready", "scope": "TEST:APPROVED_SYNTHETIC"}


class DisabledProviderStub(NullProviderAdapter):
    """Credential-free provider-specific placeholder with no live endpoint."""

    def __init__(self, provider_name: str) -> None:
        if not provider_name.strip():
            raise ProviderContractError("provider name is required")
        self.name = provider_name

    def validate_configuration(self) -> None:
        raise ProviderDeliveryDisabled(
            f"{self.name} has no approved account, credentials, or endpoint"
        )
