from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from app.adapters.odoo.lead_automation import (
    AckValidationError,
    build_apply_payload,
    classify_ack,
    validate_ack,
)

ACTIONS = {
    "CREATE_LEAD",
    "UPDATE_ALLOWLISTED_FIELDS",
    "ASSIGN_AUTHORIZED_TEAM",
    "ASSIGN_AUTHORIZED_USER",
    "CHANGE_AUTHORIZED_STAGE",
    "CREATE_INTERNAL_CALLBACK_ACTIVITY",
}
ATTRIBUTE_SCHEMA_FIELDS = {
    "transportation-logistics-lead-v1": {
        "contact_reference",
        "shipment_mode",
        "origin_region",
        "destination_region",
        "load_class",
        "estimated_volume_band",
    },
    "web-mobile-ai-lead-v1": {
        "contact_reference",
        "solution_type",
        "company_size_band",
        "budget_band",
        "delivery_window",
    },
    "senior-citizen-products-lead-v1": {
        "contact_reference",
        "product_category",
        "service_region",
        "accessibility_support",
    },
    "business-loan-lead-v1": {
        "contact_reference",
        "loan_purpose",
        "amount_band",
        "business_age_band",
        "industry_key",
    },
    "real-estate-lead-v1": {
        "contact_reference",
        "transaction_type",
        "property_type",
        "region_key",
        "budget_band",
    },
    "fundraising-lead-v1": {
        "contact_reference",
        "campaign_type",
        "interest_band",
        "region_key",
    },
    "trading-ai-lead-v1": {
        "contact_reference",
        "experience_band",
        "product_interest",
        "risk_profile_reference",
    },
    "farming-lead-v1": {
        "contact_reference",
        "operation_type",
        "acreage_band",
        "region_key",
        "solution_interest",
    },
}
CONTACT_ELIGIBLE = {"CREATE_INTERNAL_CALLBACK_ACTIVITY"}
TERMINAL = {
    "POLICY_DENIED",
    "CONSENT_BLOCKED",
    "DNC_BLOCKED",
    "QUARANTINED",
    "FAILED_TERMINAL",
    "COMPLETED",
}


class State(StrEnum):
    RECEIVED = "RECEIVED"
    SCHEMA_VALIDATED = "SCHEMA_VALIDATED"
    POLICY_EVALUATING = "POLICY_EVALUATING"
    POLICY_ALLOWED = "POLICY_ALLOWED"
    POLICY_DENIED = "POLICY_DENIED"
    CONSENT_BLOCKED = "CONSENT_BLOCKED"
    DNC_BLOCKED = "DNC_BLOCKED"
    OUTBOX_PENDING = "OUTBOX_PENDING"
    DISPATCH_RESERVED = "DISPATCH_RESERVED"
    DISPATCHED = "DISPATCHED"
    N8N_ACKNOWLEDGED = "N8N_ACKNOWLEDGED"
    RESULT_RECEIVED = "RESULT_RECEIVED"
    RESULT_VALIDATED = "RESULT_VALIDATED"
    ODOO_APPLY_PENDING = "ODOO_APPLY_PENDING"
    ODOO_APPLIED = "ODOO_APPLIED"
    COMPLETED = "COMPLETED"
    RETRY_PENDING = "RETRY_PENDING"
    QUARANTINED = "QUARANTINED"
    FAILED_TERMINAL = "FAILED_TERMINAL"


TRANSITIONS = {
    State.RECEIVED: {State.SCHEMA_VALIDATED, State.QUARANTINED},
    State.SCHEMA_VALIDATED: {State.POLICY_EVALUATING},
    State.POLICY_EVALUATING: {
        State.POLICY_ALLOWED,
        State.POLICY_DENIED,
        State.CONSENT_BLOCKED,
        State.DNC_BLOCKED,
    },
    State.POLICY_ALLOWED: {State.OUTBOX_PENDING},
    State.OUTBOX_PENDING: {State.DISPATCH_RESERVED},
    State.DISPATCH_RESERVED: {State.DISPATCHED, State.RETRY_PENDING, State.QUARANTINED},
    State.DISPATCHED: {State.N8N_ACKNOWLEDGED, State.RETRY_PENDING, State.QUARANTINED},
    State.N8N_ACKNOWLEDGED: {State.RESULT_RECEIVED, State.RETRY_PENDING},
    State.RESULT_RECEIVED: {State.RESULT_VALIDATED, State.QUARANTINED},
    State.RESULT_VALIDATED: {State.ODOO_APPLY_PENDING},
    State.ODOO_APPLY_PENDING: {
        State.ODOO_APPLIED,
        State.POLICY_DENIED,
        State.CONSENT_BLOCKED,
        State.DNC_BLOCKED,
        State.RETRY_PENDING,
        State.QUARANTINED,
    },
    State.ODOO_APPLIED: {State.COMPLETED, State.QUARANTINED},
    State.RETRY_PENDING: {
        State.DISPATCH_RESERVED,
        State.ODOO_APPLY_PENDING,
        State.FAILED_TERMINAL,
    },
}


class LeadAutomationError(ValueError):
    pass


class Conflict(LeadAutomationError):
    pass


@dataclass(frozen=True)
class Policy:
    environment: str
    business_unit_key: str
    campaign_key: str
    event_type: str
    action: str
    policy_version: str
    allow: bool = False
    requires_consent: bool = False
    contact_eligible: bool = False
    allowed_fields: frozenset[str] = frozenset()
    enabled: bool = False


@dataclass(frozen=True)
class TenantScope:
    environment: str
    business_unit_key: str
    campaign_key: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TenantScope:
        return cls(
            environment=str(payload.get("environment", "")),
            business_unit_key=str(payload.get("business_unit_key", "")),
            campaign_key=str(payload.get("campaign_key", "")),
        )


@dataclass
class Event:
    automation_event_id: str
    payload: dict[str, Any]
    payload_hash: str
    state: State = State.RECEIVED
    result_hash: str | None = None
    result_response: dict[str, Any] | None = None
    workflow_execution_id: str | None = None
    result_payload: dict[str, Any] | None = None
    odoo_ack: dict[str, Any] | None = None
    audit: list[dict[str, str]] = field(default_factory=list)


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class LeadAutomationService:
    def __init__(self) -> None:
        self.enabled = False
        self.binding_enabled = False
        self.result_processing_enabled = False
        self.odoo_apply_enabled = False
        self.action_switches = {action: False for action in ACTIONS}
        self.policies: dict[tuple[str, ...], Policy] = {}
        self.events: dict[tuple[str, str, str, str], Event] = {}
        self.idempotency: dict[
            tuple[str, str, str, str], tuple[str, dict[str, Any]]
        ] = {}
        self.workflow_ids: set[tuple[str, str]] = set()
        self.outbox: list[dict[str, Any]] = []
        self.quarantine: list[dict[str, str]] = []
        self.odoo_operations = 0

    def add_policy(self, policy: Policy) -> None:
        key = (
            policy.environment,
            policy.business_unit_key,
            policy.campaign_key,
            policy.event_type,
            policy.action,
            policy.policy_version,
        )
        self.policies[key] = policy

    def _transition(self, event: Event, target: State, code: str = "") -> None:
        if target not in TRANSITIONS.get(event.state, set()):
            raise LeadAutomationError(f"invalid transition {event.state}->{target}")
        event.state = target
        event.audit.append({"state": target, "result_code": code})

    def receive(self, payload: dict[str, Any]) -> dict[str, Any]:
        environment = payload.get("environment", "")
        scope = TenantScope.from_payload(payload)
        event_id = payload.get("event_id", "")
        idem = payload.get("idempotency_key", "")
        digest = canonical_hash(payload)
        idem_key = (*self._scope_key(scope), idem)
        if idem_key in self.idempotency:
            previous_hash, response = self.idempotency[idem_key]
            if previous_hash != digest:
                self.quarantine.append(
                    {"event_id": event_id, "reason": "IDEMPOTENCY_CONFLICT"}
                )
                raise Conflict("conflicting event replay")
            return response
        required = {
            "contract_version",
            "event_id",
            "event_type",
            "environment",
            "company_key",
            "business_unit_key",
            "campaign_key",
            "automation_action",
            "policy_version",
            "attributes",
            "consent_snapshot",
        }
        if (
            payload.get("contract_version") != "1.1"
            or not required <= payload.keys()
            or payload.get("automation_action") not in ACTIONS
            or not re.fullmatch(
                r"COMPANY-[1-9][0-9]{0,9}", payload.get("company_key", "")
            )
        ):
            raise LeadAutomationError("schema violation")
        schema_key = payload.get("attributes_schema_key")
        if (
            schema_key not in ATTRIBUTE_SCHEMA_FIELDS
            or not isinstance(payload.get("attributes"), dict)
            or set(payload["attributes"]) - ATTRIBUTE_SCHEMA_FIELDS[schema_key]
        ):
            raise LeadAutomationError("business-unit attribute schema violation")
        event = Event("LAE-" + uuid4().hex, payload, digest)
        self.events[(*self._scope_key(scope), event_id)] = event
        self._transition(event, State.SCHEMA_VALIDATED)
        self._transition(event, State.POLICY_EVALUATING)
        policy_key = (
            environment,
            payload["business_unit_key"],
            payload["campaign_key"],
            payload["event_type"],
            payload["automation_action"],
            payload["policy_version"],
        )
        policy = self.policies.get(policy_key)
        consent = payload["consent_snapshot"]
        if (
            not policy
            or not policy.enabled
            or not policy.allow
            or not self.enabled
            or not self.action_switches[payload["automation_action"]]
        ):
            self._transition(event, State.POLICY_DENIED, "DEFAULT_DENY")
        elif policy.contact_eligible and consent.get("dnc_status") is True:
            self._transition(event, State.DNC_BLOCKED, "DNC_BLOCKED")
        elif policy.requires_consent and consent.get("consent_status") != "granted":
            self._transition(event, State.CONSENT_BLOCKED, "CONSENT_REQUIRED")
        elif set(payload["attributes"]) - policy.allowed_fields:
            self._transition(event, State.POLICY_DENIED, "ATTRIBUTE_NOT_ALLOWED")
        else:
            self._transition(event, State.POLICY_ALLOWED)
            self._transition(event, State.OUTBOX_PENDING)
            self.outbox.append(
                {
                    "automation_event_id": event.automation_event_id,
                    "binding_key": "n8n.leads.ingest",
                    "environment": scope.environment,
                    "business_unit_key": scope.business_unit_key,
                    "campaign_key": scope.campaign_key,
                    "enabled": self.binding_enabled,
                    "attempts": 0,
                }
            )
        response = self.status(event)
        self.idempotency[idem_key] = (digest, response)
        return response

    def reserve_dispatch(self, event_id: str, scope: TenantScope) -> bool:
        event = self._find(event_id, scope)
        if (
            event.state != State.OUTBOX_PENDING
            or not self.enabled
            or not self.binding_enabled
        ):
            return False
        self._transition(event, State.DISPATCH_RESERVED)
        return True

    def mark_dispatched(self, event_id: str, scope: TenantScope) -> None:
        self._transition(self._find(event_id, scope), State.DISPATCHED)

    def acknowledge_n8n(self, event_id: str, scope: TenantScope) -> None:
        self._transition(self._find(event_id, scope), State.N8N_ACKNOWLEDGED)

    def receive_result(
        self, payload: dict[str, Any], scope: TenantScope
    ) -> dict[str, Any]:
        if scope != TenantScope.from_payload(payload):
            raise LeadAutomationError("event not found")
        event = self._find(payload.get("event_id", ""), scope)
        digest = canonical_hash(payload)
        if event.result_hash:
            if event.result_hash != digest:
                event.state = State.QUARANTINED
                self.quarantine.append(
                    {
                        "event_id": payload.get("event_id", ""),
                        "reason": "RESULT_CONFLICT",
                    }
                )
                raise Conflict("conflicting result replay")
            return event.result_response or {}
        if not self.result_processing_enabled:
            raise LeadAutomationError("result processing disabled")
        required = {
            "contract_version",
            "event_id",
            "workflow_execution_id",
            "binding_key",
            "environment",
            "company_key",
            "business_unit_key",
            "campaign_key",
            "automation_action",
            "result_status",
            "result_code",
            "result_payload",
            "occurred_at",
            "idempotency_key",
        }
        if (
            set(payload) != required
            or payload.get("contract_version") != "1.1"
            or not re.fullmatch(
                r"COMPANY-[1-9][0-9]{0,9}", payload.get("company_key", "")
            )
        ):
            raise LeadAutomationError("result schema violation")
        original = event.payload
        immutable = (
            "environment",
            "company_key",
            "business_unit_key",
            "campaign_key",
            "automation_action",
        )
        if (
            any(payload.get(key) != original.get(key) for key in immutable)
            or payload.get("binding_key") != "n8n.leads.ingest"
        ):
            event.state = State.QUARANTINED
            raise Conflict("immutable binding conflict")
        policy_key = (
            original["environment"],
            original["business_unit_key"],
            original["campaign_key"],
            original["event_type"],
            original["automation_action"],
            original["policy_version"],
        )
        allowed_fields = self.policies[policy_key].allowed_fields
        result_fields = set(payload.get("result_payload", {}).get("field_updates", {}))
        immutable_fields = {
            "consent_status",
            "dnc_status",
            "environment",
            "business_unit_key",
            "campaign_key",
            "policy_version",
        }
        if result_fields - allowed_fields or result_fields & immutable_fields:
            event.state = State.QUARANTINED
            raise Conflict("result field outside policy allowlist")
        workflow_key = (payload["environment"], payload["workflow_execution_id"])
        if workflow_key in self.workflow_ids:
            event.state = State.QUARANTINED
            raise Conflict("duplicate workflow execution")
        self.workflow_ids.add(workflow_key)
        self._transition(event, State.RESULT_RECEIVED)
        self._transition(event, State.RESULT_VALIDATED)
        self._transition(event, State.ODOO_APPLY_PENDING)
        response = {
            "automation_event_id": event.automation_event_id,
            "state": event.state,
            "accepted": True,
        }
        event.result_hash, event.result_response = digest, response
        event.result_payload = dict(payload)
        return response

    def apply_odoo_ack(
        self, event_id: str, ack: dict[str, Any], scope: TenantScope
    ) -> dict[str, Any]:
        event = self._find(event_id, scope)
        if not self.odoo_apply_enabled:
            raise LeadAutomationError("Odoo apply disabled")
        if event.odoo_ack is not None:
            if canonical_hash(event.odoo_ack) == canonical_hash(ack):
                return self.status(event)
            previous_was_retryable = classify_ack(event.odoo_ack) == "retry"
            if not (previous_was_retryable and event.state == State.ODOO_APPLY_PENDING):
                event.state = State.QUARANTINED
                self.quarantine.append(
                    {
                        "event_id": event.payload["event_id"],
                        "reason": "ODOO_ACK_CONFLICT",
                    }
                )
                raise Conflict("conflicting Odoo acknowledgement replay")
        if event.state != State.ODOO_APPLY_PENDING or event.result_payload is None:
            event.state = State.QUARANTINED
            raise Conflict("Odoo acknowledgement without pending apply")
        request = build_apply_payload(
            event=event.payload,
            result=event.result_payload,
            automation_event_id=event.automation_event_id,
        )
        try:
            validate_ack(ack, request)
        except AckValidationError as exc:
            event.state = State.QUARANTINED
            self.quarantine.append(
                {"event_id": event.payload["event_id"], "reason": "ODOO_ACK_INVALID"}
            )
            raise Conflict("Odoo acknowledgement schema or binding mismatch") from exc
        classification = classify_ack(ack)
        event.odoo_ack = ack
        self.odoo_operations += 1
        if classification == "complete":
            self._transition(event, State.ODOO_APPLIED)
            self._transition(event, State.COMPLETED)
        elif classification == "retry":
            self._transition(event, State.RETRY_PENDING, ack["result_code"])
        elif ack["result"] == "DENIED":
            self._transition(
                event, State.POLICY_DENIED, ack.get("result_code", "DENIED")
            )
        elif ack["result"] == "CONSENT_BLOCKED":
            self._transition(
                event, State.CONSENT_BLOCKED, ack.get("result_code", "CONSENT_BLOCKED")
            )
        elif ack["result"] == "DNC_BLOCKED":
            self._transition(
                event, State.DNC_BLOCKED, ack.get("result_code", "DNC_BLOCKED")
            )
        else:
            self._transition(
                event, State.QUARANTINED, ack.get("result_code", ack["result"])
            )
        return self.status(event)

    def record_retry(
        self,
        event_id: str,
        scope: TenantScope,
        attempts: int,
        maximum_attempts: int = 5,
    ) -> State:
        event = self._find(event_id, scope)
        target = (
            State.FAILED_TERMINAL
            if attempts >= maximum_attempts
            else State.RETRY_PENDING
        )
        if target == State.FAILED_TERMINAL and event.state != State.RETRY_PENDING:
            self._transition(event, State.RETRY_PENDING)
        self._transition(event, target)
        return event.state

    def reconcile(self, scope: TenantScope) -> list[str]:
        gaps = []
        for event in self.events.values():
            if TenantScope.from_payload(event.payload) != scope:
                continue
            has_outbox = any(
                row["automation_event_id"] == event.automation_event_id
                for row in self.outbox
            )
            if (
                event.state not in TERMINAL
                and event.state.value
                not in {"RECEIVED", "SCHEMA_VALIDATED", "POLICY_EVALUATING"}
                and not has_outbox
            ):
                gaps.append(f"{event.automation_event_id}:event_without_outbox")
            if event.state == State.ODOO_APPLIED and not event.odoo_ack:
                gaps.append(f"{event.automation_event_id}:missing_acknowledgement")
        return gaps

    @staticmethod
    def _scope_key(scope: TenantScope) -> tuple[str, str, str]:
        return scope.environment, scope.business_unit_key, scope.campaign_key

    def _find(self, event_id: str, scope: TenantScope) -> Event:
        for (*candidate_scope, candidate_id), event in self.events.items():
            if tuple(candidate_scope) != self._scope_key(scope):
                continue
            if candidate_id == event_id or event.automation_event_id == event_id:
                return event
        raise LeadAutomationError("event not found")

    @staticmethod
    def status(event: Event) -> dict[str, Any]:
        return {
            "contract_version": "1.0",
            "automation_event_id": event.automation_event_id,
            "event_id": event.payload["event_id"],
            "environment": event.payload["environment"],
            "state": event.state,
            "policy_version": event.payload["policy_version"],
            "updated_at": datetime.now(UTC).isoformat(),
        }
