"""Fail-closed, synthetic-only IVR control-plane domain services."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from threading import Lock
from typing import Any, Final

BUSINESS_UNITS: Final = {"TL", "DEV", "SCP", "SHARED"}
LOOKUP_STATES: Final = {
    "exact_match",
    "multiple_matches",
    "no_match",
    "restricted_match",
    "manual_verification_required",
}
APPOINTMENT_STATES: Final = {
    "agent_available",
    "agent_busy",
    "agent_offline",
    "appointment_early",
    "appointment_overdue",
    "appointment_not_found",
    "appointment_cancelled",
    "reschedule_required",
}
APPROVED_INTENTS: Final = {
    "freight_quote",
    "dispatch_service",
    "medical_trip_support",
    "website_development",
    "mobile_development",
    "ai_project",
    "odoo_implementation",
    "existing_order",
    "reorder",
    "warranty",
    "billing",
    "appointment",
    "cancellation",
    "support",
    "complaint",
}
IVR_FEATURE_FLAGS: Final = {
    "ENABLE_MAIN_IVR",
    "ENABLE_TL_IVR",
    "ENABLE_DEV_IVR",
    "ENABLE_SCP_IVR",
    "ENABLE_IVR_CUSTOMER_LOOKUP",
    "ENABLE_IVR_APPOINTMENT_LOOKUP",
    "ENABLE_IVR_CALLBACKS",
    "ENABLE_IVR_VOICEMAIL",
    "ENABLE_IVR_AI_INTENT",
    "ENABLE_IVR_PRIORITY_ROUTING",
    "ENABLE_IVR_AFTER_HOURS",
    "ENABLE_IVR_SCREEN_POP",
}


class IvrDenied(PermissionError):
    pass


class IdempotencyConflict(ValueError):
    pass


@dataclass(frozen=True)
class DidMapping:
    did_reference: str
    environment: str
    business_unit: str
    default_campaign: str | None
    root_menu: str
    language: str = "en"
    production_eligible: bool = False
    active: bool = False


@dataclass(frozen=True)
class Destination:
    campaign: str
    native_campaign: str
    inbound_group: str
    business_unit: str
    department: str
    queue: str
    supervisor_group: str
    languages: tuple[str, ...]
    permitted_transfers: tuple[str, ...]
    callback_policy: str
    active: bool = False


@dataclass(frozen=True)
class IvrSession:
    session_id: str
    call_uniqueid: str
    did_reference: str
    masked_caller_reference: str
    business_unit: str
    campaign: str | None
    initial_language: str
    final_language: str
    ivr_path: tuple[str, ...] = ()
    intent_code: str | None = None
    campaign_lock: str | None = None
    final_result: str | None = None
    correlation_id: str = ""


MAIN_MENU: Final = {
    "1": ("TL", "TL-GENERAL", "transportation"),
    "2": ("DEV", "DEV-GENERAL", "development"),
    "3": ("SCP", "SCP-GENERAL", "senior-products"),
    "4": ("SHARED", None, "appointments"),
    "5": ("SHARED", None, "support"),
    "9": ("SHARED", None, "language-es"),
    "0": ("SHARED", None, "repeat"),
}

DEFAULT_DIDS: Final = {
    "TST-MAIN": DidMapping("TST-MAIN", "staging", "SHARED", None, "main"),
    "TST-TL": DidMapping("TST-TL", "staging", "TL", "TL-GENERAL", "transportation"),
    "TST-DEV": DidMapping("TST-DEV", "staging", "DEV", "DEV-GENERAL", "development"),
    "TST-SCP": DidMapping(
        "TST-SCP", "staging", "SCP", "SCP-GENERAL", "senior-products"
    ),
    "TST-SUPPORT": DidMapping("TST-SUPPORT", "staging", "SHARED", None, "support"),
    "TST-APPT": DidMapping("TST-APPT", "staging", "SHARED", None, "appointments"),
}


def resolve_did(
    did_reference: str, mappings: dict[str, DidMapping] | None = None
) -> DidMapping:
    result = (mappings or DEFAULT_DIDS).get(did_reference)
    if not result or result.environment != "staging" or result.production_eligible:
        raise IvrDenied("unknown or production-eligible DID denied")
    return result


def select_main(session: IvrSession, keypad: str) -> IvrSession:
    if keypad not in MAIN_MENU:
        return replace(session, ivr_path=session.ivr_path + ("invalid-input",))
    unit, campaign, node = MAIN_MENU[keypad]
    if keypad == "9":
        return replace(
            session, final_language="es", ivr_path=session.ivr_path + (node,)
        )
    if unit == "SHARED":
        return replace(session, ivr_path=session.ivr_path + (node,))
    return replace(
        session,
        business_unit=unit,
        campaign=campaign,
        campaign_lock=campaign,
        ivr_path=session.ivr_path + (node,),
    )


def validate_destination(destination: Destination, session: IvrSession) -> None:
    if destination.business_unit not in BUSINESS_UNITS:
        raise IvrDenied("unknown business unit")
    if not destination.supervisor_group or not destination.inbound_group:
        raise IvrDenied("destination lacks an approved supervisor or inbound group")
    if session.business_unit != destination.business_unit:
        raise IvrDenied("cross-business-unit route denied")
    if session.campaign_lock != destination.campaign:
        raise IvrDenied("cross-campaign route denied")
    if destination.active:
        raise IvrDenied("active telephony destination unavailable in staging")


def sign_context(session: IvrSession, secret: bytes) -> str:
    if len(secret) < 32:
        raise ValueError("routing signing key is too short")
    body = json.dumps(
        {
            "session_id": session.session_id,
            "business_unit": session.business_unit,
            "campaign": session.campaign_lock,
            "language": session.final_language,
            "correlation_id": session.correlation_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_context(session: IvrSession, secret: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign_context(session, secret), signature)


def customer_lookup(state: str, masked_reference: str) -> dict[str, str]:
    if state not in LOOKUP_STATES or not masked_reference.startswith("***"):
        raise ValueError("unsafe lookup result")
    return {"state": state, "reference": masked_reference}


def appointment_lookup(
    state: str, business_unit: str, campaign: str, session: IvrSession
) -> dict[str, str]:
    if state not in APPOINTMENT_STATES:
        raise ValueError("invalid appointment outcome")
    if session.business_unit != business_unit or session.campaign_lock != campaign:
        raise IvrDenied("appointment cannot cross session scope")
    return {"state": state, "business_unit": business_unit, "campaign": campaign}


def classify_intent(
    intent: str,
    confidence: float,
    session: IvrSession,
    proposed_unit: str,
    proposed_campaign: str,
) -> dict[str, Any]:
    if intent not in APPROVED_INTENTS or not 0 <= confidence <= 1:
        return {
            "intent": None,
            "confirmation_required": True,
            "fallback_menu": "keypad",
        }
    if (
        proposed_unit != session.business_unit
        or proposed_campaign != session.campaign_lock
    ):
        raise IvrDenied("AI cannot bypass campaign lock")
    return {
        "intent": intent,
        "confidence": confidence,
        "business_unit": proposed_unit,
        "campaign": proposed_campaign,
        "confirmation_required": confidence < 0.85,
        "fallback_menu": "keypad",
    }


def reclassify(
    session: IvrSession, corrected_intent: str, new_session_id: str, reason: str
) -> tuple[IvrSession, IvrSession, dict[str, str]]:
    if corrected_intent not in APPROVED_INTENTS or not reason.strip():
        raise ValueError("approved intent and reason required")
    closed = replace(session, final_result="MISROUTED_IVR")
    linked = replace(
        session,
        session_id=new_session_id,
        intent_code=corrected_intent,
        ivr_path=session.ivr_path + ("controlled-reclassification",),
        final_result=None,
    )
    return (
        closed,
        linked,
        {
            "original_session": session.session_id,
            "linked_session": new_session_id,
            "reason": reason,
        },
    )


class IdempotencyLedger:
    """Thread-safe contract; production persistence is PostgreSQL-backed."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, Any]] = {}
        self._lock = Lock()

    def claim(self, key: str, body: dict[str, Any], result: Any) -> Any:
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        with self._lock:
            prior = self._values.get(key)
            if prior:
                if prior[0] != digest:
                    raise IdempotencyConflict(
                        "idempotency key reused with changed body"
                    )
                return prior[1]
            self._values[key] = (digest, result)
            return result


class FeaturePolicy:
    """Environment/unit/campaign overrides with a universally false default."""

    def __init__(self, overrides: dict[tuple[str, str, str, str], bool] | None = None):
        self._overrides = overrides or {}

    def enabled(
        self, flag: str, environment: str, business_unit: str, campaign: str
    ) -> bool:
        if flag not in IVR_FEATURE_FLAGS:
            raise ValueError("unknown IVR feature flag")
        return self._overrides.get((environment, business_unit, campaign, flag), False)


class FakeIvrAdapter:
    """Never answers, originates, registers, or changes a queue."""

    def route(self, destination: Destination, session: IvrSession) -> dict[str, str]:
        validate_destination(destination, session)
        return {"state": "synthetic_route_validated", "campaign": destination.campaign}

    def answer(self) -> None:
        raise IvrDenied("live inbound call authorization is not granted")

    def originate(self) -> None:
        raise IvrDenied("live call authorization is not granted")

    def activate_did(self) -> None:
        raise IvrDenied("public DID activation is not granted")
