"""Strict telephony command and result contracts.

Commands reference public identities and committed allocation reservations.  They
never carry a selected extension, host, URL, database address, dialplan context,
or trunk name.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PUBLIC_ID = re.compile(r"^[A-Z][A-Z0-9_]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


class TelephonyCommandType(StrEnum):
    USER_APPLY = "telephony.vicidial.user.apply"
    USER_DISABLE = "telephony.vicidial.user.disable"
    PHONE_APPLY = "telephony.vicidial.phone.apply"
    PHONE_DISABLE = "telephony.vicidial.phone.disable"
    ENDPOINT_APPLY = "telephony.asterisk.endpoint.apply"
    ENDPOINT_DISABLE = "telephony.asterisk.endpoint.disable"
    CONTACT_REVOKE = "telephony.asterisk.contact.revoke"
    CONTACTS_REVOKE_ALL = "telephony.asterisk.contacts.revoke_all"
    TARGET_RECONCILE = "telephony.target.reconcile"
    AGENT_RECONCILE = "telephony.agent.reconcile"
    CAMPAIGN_RECONCILE = "telephony.campaign.reconcile"


class TelephonyCommandState(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    POLICY_PENDING = "POLICY_PENDING"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_APPROVED = "POLICY_APPROVED"
    JOURNALED = "JOURNALED"
    ROUTE_RESOLVED = "ROUTE_RESOLVED"
    TARGET_ATTESTED = "TARGET_ATTESTED"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHING = "DISPATCHING"
    DISPATCHED = "DISPATCHED"
    OPERATION_REGISTERED = "OPERATION_REGISTERED"
    APPLYING = "APPLYING"
    APPLIED = "APPLIED"
    SUBMITTING = "SUBMITTING"
    SUBMITTED = "SUBMITTED"
    READBACK_PENDING = "READBACK_PENDING"
    READBACK_VERIFIED = "READBACK_VERIFIED"
    ODOO_RESULT_PENDING = "ODOO_RESULT_PENDING"
    ODOO_RESULT_DELIVERED = "ODOO_RESULT_DELIVERED"
    RECONCILED = "RECONCILED"
    SUCCEEDED = "SUCCEEDED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    FAILED_TRANSIENT = "FAILED_TRANSIENT"
    FAILED_PERMANENT = "FAILED_PERMANENT"


TELEPHONY_OPERATION_LIFECYCLE = (
    "RECEIVED",
    "VALIDATING",
    "VALIDATED",
    "POLICY_APPROVED",
    "JOURNALED",
    "ROUTE_RESOLVED",
    "TARGET_ATTESTED",
    "DISPATCHING",
    "DISPATCHED",
    "OPERATION_REGISTERED",
    "APPLYING",
    "APPLIED",
    "READBACK_PENDING",
    "READBACK_VERIFIED",
    "ODOO_RESULT_PENDING",
    "ODOO_RESULT_DELIVERED",
    "RECONCILED",
)


MUTATION_ENDPOINTS: dict[TelephonyCommandType, str] = {
    TelephonyCommandType.USER_APPLY: "telephony.vicidial.users.apply",
    TelephonyCommandType.USER_DISABLE: "telephony.vicidial.users.disable",
    TelephonyCommandType.PHONE_APPLY: "telephony.vicidial.phones.apply",
    TelephonyCommandType.PHONE_DISABLE: "telephony.vicidial.phones.disable",
    TelephonyCommandType.ENDPOINT_APPLY: "telephony.asterisk.endpoints.apply",
    TelephonyCommandType.ENDPOINT_DISABLE: "telephony.asterisk.endpoints.disable",
    TelephonyCommandType.CONTACT_REVOKE: "telephony.asterisk.contacts.revoke",
    TelephonyCommandType.CONTACTS_REVOKE_ALL: "telephony.asterisk.contacts.revoke_all",
    TelephonyCommandType.TARGET_RECONCILE: "telephony.reconciliation.create",
    TelephonyCommandType.AGENT_RECONCILE: "telephony.reconciliation.create",
    TelephonyCommandType.CAMPAIGN_RECONCILE: "telephony.reconciliation.create",
}

READBACK_ENDPOINTS: dict[TelephonyCommandType, str] = {
    TelephonyCommandType.USER_APPLY: "telephony.vicidial.users.read",
    TelephonyCommandType.USER_DISABLE: "telephony.vicidial.users.read",
    TelephonyCommandType.PHONE_APPLY: "telephony.vicidial.phones.read",
    TelephonyCommandType.PHONE_DISABLE: "telephony.vicidial.phones.read",
    TelephonyCommandType.ENDPOINT_APPLY: "telephony.asterisk.endpoints.read",
    TelephonyCommandType.ENDPOINT_DISABLE: "telephony.asterisk.endpoints.read",
    TelephonyCommandType.CONTACT_REVOKE: "telephony.asterisk.contacts.list",
    TelephonyCommandType.CONTACTS_REVOKE_ALL: "telephony.asterisk.contacts.list",
    TelephonyCommandType.TARGET_RECONCILE: "telephony.reconciliation.read",
    TelephonyCommandType.AGENT_RECONCILE: "telephony.reconciliation.read",
    TelephonyCommandType.CAMPAIGN_RECONCILE: "telephony.reconciliation.read",
}

LOGICAL_ENDPOINT_KEYS = frozenset(
    {
        "telephony.vicidial.users.read",
        "telephony.vicidial.users.apply",
        "telephony.vicidial.users.disable",
        "telephony.vicidial.phones.read",
        "telephony.vicidial.phones.apply",
        "telephony.vicidial.phones.disable",
        "telephony.vicidial.campaigns.read",
        "telephony.vicidial.runtime.read",
        "telephony.asterisk.endpoints.read",
        "telephony.asterisk.endpoints.apply",
        "telephony.asterisk.endpoints.disable",
        "telephony.asterisk.contacts.list",
        "telephony.asterisk.contacts.revoke",
        "telephony.asterisk.contacts.revoke_all",
        "telephony.asterisk.dialplan.read",
        "telephony.asterisk.runtime.read",
        "telephony.reconciliation.create",
        "telephony.reconciliation.read",
        "telephony.service.attest",
    }
)

DISABLED_ADAPTER_ENDPOINT_DEFAULTS = {
    key: {
        "enabled": False,
        "kill_switch": True,
        "redirects_allowed": False,
        "target_attestation_required": True,
    }
    for key in LOGICAL_ENDPOINT_KEYS
    if key.startswith("telephony.")
}

FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "extension",
        "server_b_ip",
        "adapter_base_url",
        "ami_address",
        "vicidial_database_host",
        "pjsip_context",
        "context_name",
        "trunk",
        "trunk_name",
        "telephone_number",
        "customer_number",
        "destination_number",
    }
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def payload_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def stable_result_idempotency_key(
    command_public_id: str,
    operation_public_id: str,
    target_public_id: str,
    observed_state_version: int,
    result_hash: str,
) -> str:
    material = "\x1f".join(
        (
            command_public_id,
            operation_public_id,
            target_public_id,
            str(observed_state_version),
            result_hash.removeprefix("sha256:"),
        )
    )
    return hashlib.sha256(material.encode()).hexdigest()


class TelephonyCommandPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    endpoint_public_id: str | None = Field(default=None, max_length=144)
    source_endpoint_public_id: str | None = Field(default=None, max_length=144)
    destination_endpoint_public_id: str | None = Field(default=None, max_length=144)
    agent_public_id: str | None = Field(default=None, max_length=144)
    phone_public_id: str | None = Field(default=None, max_length=144)
    call_public_id: str | None = Field(default=None, max_length=144)
    contact_id: str | None = Field(default=None, max_length=128)
    allocation_reservation_id: str = Field(min_length=4, max_length=144)
    desired_state_version: int = Field(ge=1)
    state: Literal["DISABLED", "ENABLED"] = "DISABLED"
    maximum_duration_seconds: int | None = Field(default=None, ge=1, le=300)
    purpose: str | None = Field(default=None, max_length=128)
    reservation_generation: int | None = Field(default=None, ge=1)
    reservation_hash: str | None = Field(
        default=None, pattern=r"^(?:sha256:)?[0-9a-f]{64}$"
    )
    desired_state_hash: str | None = Field(
        default=None, pattern=r"^(?:sha256:)?[0-9a-f]{64}$"
    )
    context_key: str | None = Field(default=None, max_length=128)
    external_route_allowed: bool = False
    transfer_allowed: bool = False

    @model_validator(mode="after")
    def validate_public_ids(self) -> TelephonyCommandPayload:
        values = (
            self.endpoint_public_id,
            self.source_endpoint_public_id,
            self.destination_endpoint_public_id,
            self.agent_public_id,
            self.phone_public_id,
            self.call_public_id,
        )
        if not any(values):
            raise ValueError("at least one target public ID is required")
        for value in values:
            if value and not PUBLIC_ID.fullmatch(value):
                raise ValueError("invalid target public ID")
        return self


class TelephonyCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = Field(pattern=r"^1[.]0$")
    command_public_id: str | None = Field(default=None, min_length=4, max_length=144)
    originating_outbox_public_id: str | None = Field(
        default=None, min_length=4, max_length=144
    )
    event_id: str | None = Field(default=None, min_length=4, max_length=144)
    command_type: TelephonyCommandType
    aggregate_type: str = Field(min_length=1, max_length=64)
    aggregate_public_id: str = Field(min_length=4, max_length=144)
    aggregate_version: int = Field(ge=1)
    environment: str = Field(pattern=r"^(staging|test|production)$")
    organization_public_id: str = Field(default="", max_length=144)
    business_unit_public_id: str = Field(min_length=4, max_length=144)
    campaign_public_id: str = Field(min_length=4, max_length=144)
    idempotency_key: str = Field(min_length=8, max_length=255)
    correlation_id: str = Field(min_length=8, max_length=128)
    causation_id: str = Field(min_length=1, max_length=128)
    policy_decision_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    policy_decision_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_at: datetime | None = None
    expires_at: datetime | None = None
    payload: TelephonyCommandPayload

    @model_validator(mode="before")
    @classmethod
    def normalize_v1_envelope(cls, value: Any) -> Any:
        if not isinstance(value, dict) or "aggregate" not in value:
            return value
        data = dict(value)
        aggregate = dict(data.pop("aggregate"))
        target = dict(data.pop("target"))
        allocation = dict(data.pop("allocation"))
        desired = dict(data.pop("desired_state"))
        policy_hash = str(data.pop("policy_hash")).removeprefix("sha256:")
        data.update(
            aggregate_type=aggregate["type"],
            aggregate_public_id=aggregate["public_id"],
            aggregate_version=aggregate["version"],
            policy_decision_hash=policy_hash,
            payload={
                "endpoint_public_id": (
                    target["public_id"]
                    if target["resource_type"] == "ENDPOINT"
                    else None
                ),
                "agent_public_id": (
                    target["public_id"]
                    if target["resource_type"] == "USER"
                    else aggregate["public_id"]
                    if aggregate["type"] == "agent"
                    else None
                ),
                "phone_public_id": (
                    target["public_id"] if target["resource_type"] == "PHONE" else None
                ),
                "allocation_reservation_id": allocation["reservation_public_id"],
                "reservation_generation": allocation["reservation_generation"],
                "reservation_hash": allocation["reservation_hash"],
                "desired_state_version": desired["version"],
                "desired_state_hash": desired["hash"],
                "state": "ENABLED" if desired.get("enabled") else "DISABLED",
                "context_key": desired.get("context_key"),
                "external_route_allowed": desired.get("external_route_allowed", False),
                "transfer_allowed": desired.get("transfer_allowed", False),
            },
        )
        return data

    @model_validator(mode="after")
    def forbid_application_selected_resources(self) -> TelephonyCommandRequest:
        if self.requested_at and self.expires_at:
            if self.requested_at.tzinfo is None or self.expires_at.tzinfo is None:
                raise ValueError("command timestamps must be timezone-aware")
            if self.expires_at <= self.requested_at:
                raise ValueError("command expiry must follow request time")
            if self.expires_at <= datetime.now(UTC):
                raise ValueError("command is expired")
        raw = self.payload.model_dump(exclude_none=True)
        if FORBIDDEN_PAYLOAD_KEYS.intersection(raw):
            raise ValueError("application-selected telephony resource is prohibited")
        requirements = {
            TelephonyCommandType.USER_APPLY: ("agent_public_id",),
            TelephonyCommandType.USER_DISABLE: ("agent_public_id",),
            TelephonyCommandType.PHONE_APPLY: ("phone_public_id",),
            TelephonyCommandType.PHONE_DISABLE: ("phone_public_id",),
            TelephonyCommandType.ENDPOINT_APPLY: ("endpoint_public_id",),
            TelephonyCommandType.ENDPOINT_DISABLE: ("endpoint_public_id",),
            TelephonyCommandType.CONTACT_REVOKE: ("endpoint_public_id", "contact_id"),
            TelephonyCommandType.CONTACTS_REVOKE_ALL: ("endpoint_public_id",),
        }
        missing = [
            field
            for field in requirements.get(self.command_type, ())
            if not getattr(self.payload, field)
        ]
        if missing:
            raise ValueError(
                f"{self.command_type.value} requires {', '.join(sorted(missing))}"
            )
        return self

    def request_hash(self) -> str:
        return payload_hash(self.model_dump(mode="json"))

    def policy_scope(self) -> dict[str, str]:
        return {
            "action": "sync",
            "subject": self.aggregate_public_id,
            "resource": self.command_type.value,
            "environment": self.environment,
            "business_unit": self.business_unit_public_id,
            "campaign": self.campaign_public_id,
            "agent": self.payload.agent_public_id or "",
        }

    def desired_state(self) -> dict[str, Any]:
        return self.payload.model_dump(
            mode="json", exclude_none=True, exclude_unset=True
        )

    def target_system(self) -> str:
        return (
            "ASTERISK"
            if self.command_type.value.startswith("telephony.asterisk.")
            else "VICIDIAL"
        )

    def target_public_id(self) -> str:
        return (
            self.payload.endpoint_public_id
            or self.payload.phone_public_id
            or self.payload.agent_public_id
            or self.aggregate_public_id
        )

    def stable_idempotency_key(self) -> str:
        material = "\x1f".join(
            (
                self.environment,
                self.command_type.value,
                self.aggregate_public_id,
                str(self.payload.desired_state_version),
                self.target_system(),
                self.target_public_id(),
            )
        )
        return hashlib.sha256(material.encode()).hexdigest()


def normalized_actual_state(
    command: TelephonyCommandRequest, actual: dict[str, Any]
) -> dict[str, Any]:
    candidate = actual.get("desired_state", actual)
    if not isinstance(candidate, dict):
        raise ValueError("readback desired_state must be an object")
    expected = command.desired_state()
    return {key: candidate.get(key) for key in expected}


class TelephonyOperationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation_id: str
    command_id: str
    state: TelephonyCommandState
    endpoint_key: str
    readback_endpoint_key: str
    target_configuration_checksum: str
    target_attested: bool
    desired_hash: str
    actual_hash: str | None = None
    readback_matches: bool | None = None
    correlation_id: str
    completed_at: datetime | None = None


def new_command_record(command: TelephonyCommandRequest) -> dict[str, Any]:
    now = datetime.now(UTC)
    return {
        "command_public_id": command.command_public_id
        or "CMD-" + command.stable_idempotency_key()[:32],
        "command_type": command.command_type.value,
        "aggregate_type": command.aggregate_type,
        "aggregate_public_id": command.aggregate_public_id,
        "aggregate_version": command.aggregate_version,
        "environment": command.environment,
        "business_unit_public_id": command.business_unit_public_id,
        "campaign_public_id": command.campaign_public_id,
        "idempotency_hash": command.stable_idempotency_key(),
        "idempotency_key": command.idempotency_key,
        "request_hash": command.request_hash(),
        "correlation_id": command.correlation_id,
        "causation_id": command.causation_id,
        "policy_decision_id": command.policy_decision_id,
        "policy_decision_hash": command.policy_decision_hash,
        "payload_json": command.payload.model_dump(mode="json", exclude_none=True),
        "request_json": command.model_dump(mode="json"),
        "state": TelephonyCommandState.POLICY_PENDING.value,
        "attempt_count": 0,
        "created_at": now,
        "updated_at": now,
    }
