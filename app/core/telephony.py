"""Fail-closed telephony allocation and provisioning domain rules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Mapping


class ExtensionState(StrEnum):
    AVAILABLE = "AVAILABLE"
    RESERVED = "RESERVED"
    ASSIGNED = "ASSIGNED"
    ACTIVE = "ACTIVE"
    COOLDOWN = "COOLDOWN"
    HISTORICAL_HOLD = "HISTORICAL_HOLD"
    COLLISION = "COLLISION"
    EXCLUDED = "EXCLUDED"
    UNKNOWN_REQUIRES_REVIEW = "UNKNOWN_REQUIRES_REVIEW"


AUTHORITATIVE_SOURCES = frozenset(
    {
        "pjsip_endpoint",
        "pjsip_auth",
        "pjsip_aor",
        "pjsip_contact",
        "chan_sip_peer",
        "vicidial_phone",
        "vicidial_user",
        "vicidial_session",
        "asterisk_channel",
        "registration",
        "voicemail",
        "dialplan",
        "configuration_include",
        "static_queue",
        "historical_reservation",
        "call_history",
        "odoo_assignment",
        "odoo_provisioning_request",
        "middleware_reservation",
        "postgres_lease",
        "redis_lease",
        "deprovisioning_record",
        "cooldown",
    }
)
ACTIVE_MARKERS = frozenset({"ACTIVE"})
ASSIGNED_MARKERS = frozenset({"ASSIGNED", "PRESENT"})
RESERVED_MARKERS = frozenset({"RESERVED", "LEASED"})
HISTORICAL_MARKERS = frozenset({"HISTORICAL_HOLD", "AMBIGUOUS"})


@dataclass(frozen=True)
class AuditResult:
    extension: int
    classification: ExtensionState
    evidence_hash: str
    missing_sources: tuple[str, ...]
    collision_sources: tuple[str, ...]


def audit_extension(extension: int, evidence: Mapping[str, str]) -> AuditResult:
    normalized = {str(k): str(v).upper() for k, v in evidence.items()}
    missing = tuple(sorted(AUTHORITATIVE_SOURCES - normalized.keys()))
    collisions = tuple(
        sorted(
            key
            for key, value in normalized.items()
            if value not in {"AVAILABLE", "ABSENT", "CLEAR", "NONE"}
        )
    )
    if extension in {1001, 6101}:
        state = ExtensionState.EXCLUDED
    elif missing:
        state = ExtensionState.UNKNOWN_REQUIRES_REVIEW
    elif any(normalized[key] in ACTIVE_MARKERS for key in collisions):
        state = ExtensionState.ACTIVE
    elif any(normalized[key] in {"COLLISION", "CONFLICT"} for key in collisions):
        state = ExtensionState.COLLISION
    elif any(normalized[key] in HISTORICAL_MARKERS for key in collisions):
        state = ExtensionState.HISTORICAL_HOLD
    elif normalized.get("cooldown") not in {"AVAILABLE", "ABSENT", "CLEAR", "NONE"}:
        state = ExtensionState.COOLDOWN
    elif any(normalized[key] in RESERVED_MARKERS for key in collisions):
        state = ExtensionState.RESERVED
    elif any(normalized[key] in ASSIGNED_MARKERS for key in collisions):
        state = ExtensionState.ASSIGNED
    else:
        state = ExtensionState.AVAILABLE
    document = {"extension": extension, "evidence": dict(sorted(normalized.items()))}
    fingerprint = hashlib.sha256(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return AuditResult(extension, state, fingerprint, missing, collisions)


SAGA_TRANSITIONS = {
    "DRAFT": {"PENDING_APPROVAL"},
    "PENDING_APPROVAL": {"APPROVED", "FAILED"},
    "APPROVED": {"INVENTORY_CHECK", "FAILED"},
    "INVENTORY_CHECK": {"RESERVED", "FAILED"},
    "RESERVED": {"PROVISIONING", "ROLLED_BACK"},
    "PROVISIONING": {"DISABLED_READY", "FAILED", "ROLLED_BACK"},
    "DISABLED_READY": {"ACTIVATION_PENDING", "SUSPENDING", "DEPROVISIONING"},
    "ACTIVATION_PENDING": {"ACTIVE", "FAILED", "ROLLED_BACK"},
    "ACTIVE": {"SUSPENDING", "DEPROVISIONING"},
    "FAILED": {"ROLLED_BACK"},
    "SUSPENDING": {"SUSPENDED", "FAILED"},
    "SUSPENDED": {"ACTIVATION_PENDING", "DEPROVISIONING"},
    "DEPROVISIONING": {"COOLDOWN", "FAILED"},
    "COOLDOWN": set(),
    "ROLLED_BACK": set(),
}


def transition_allowed(current: str, target: str) -> bool:
    return target in SAGA_TRANSITIONS.get(current, set())


def canonical_event(
    event_type: str,
    correlation_id: str,
    idempotency_key: str,
    source: str,
    actor: str,
    employee_id: str,
    business_unit_id: str,
    campaign_id: str,
    object_type: str,
    object_id: str,
    revision: int,
    payload: dict,
) -> dict:
    return {
        "schema_version": "1.0",
        "event_id": hashlib.sha256(
            f"{event_type}:{idempotency_key}".encode()
        ).hexdigest(),
        "correlation_id": correlation_id,
        "idempotency_key": idempotency_key,
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": source,
        "actor": actor,
        "employee_id": employee_id,
        "business_unit_id": business_unit_id,
        "campaign_id": campaign_id,
        "object_type": object_type,
        "object_id": object_id,
        "revision": revision,
        "event_type": event_type,
        "payload": payload,
    }
