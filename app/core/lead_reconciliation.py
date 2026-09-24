"""Deterministic CRM/VICIdial identity resolution with fail-closed safety.

This module never talks to VICIdial tables.  An adapter may execute a returned
decision only after the durable repository has reserved its idempotency key.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class MatchStatus(str, Enum):
    MAPPED = "MAPPED"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"
    UNIQUE_PHONE = "UNIQUE_PHONE"
    UNIQUE_EMAIL = "UNIQUE_EMAIL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    NO_MATCH = "NO_MATCH"


class SyncAction(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DEACTIVATE = "DEACTIVATE"
    WITHDRAW = "WITHDRAW"
    SUPPRESS = "SUPPRESS"
    REACTIVATE_AFTER_APPROVAL = "REACTIVATE_AFTER_APPROVAL"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"


@dataclass(frozen=True)
class OdooIdentity:
    company_id: str
    environment_id: str
    connector_id: str
    model: str
    record_id: int
    revision: str

    @property
    def lock_key(self) -> str:
        return ":".join(
            (self.environment_id, self.connector_id, self.model, str(self.record_id))
        )


@dataclass(frozen=True)
class Candidate:
    odoo_model: str
    odoo_record_id: int

    @property
    def key(self) -> tuple[str, int]:
        return self.odoo_model, self.odoo_record_id


@dataclass(frozen=True)
class Resolution:
    status: MatchStatus
    candidate: Candidate | None = None
    reason: str = ""


class SuppressionUnavailable(PermissionError):
    pass


class SuppressionActive(PermissionError):
    pass


def normalize_phone(
    raw: str | None, default_country_code: str | None = None
) -> str | None:
    """Return conservative E.164 or None; extensions are deliberately excluded."""
    if not raw:
        return None
    main = re.split(r"(?i)(?:ext\.?|x|#)\s*\d+\s*$", raw.strip(), maxsplit=1)[0]
    has_plus = main.lstrip().startswith("+")
    digits = re.sub(r"\D", "", main)
    if not has_plus:
        if not default_country_code:
            return None
        country = re.sub(r"\D", "", default_country_code)
        digits = digits.lstrip("0")
        digits = country + digits
    if not 8 <= len(digits) <= 15 or digits.startswith("0"):
        return None
    return f"+{digits}"


def normalize_email(raw: str | None) -> str | None:
    if not raw:
        return None
    value = raw.strip().lower()
    if len(value) > 254 or value.count("@") != 1:
        return None
    local, domain = value.split("@", 1)
    if not local or not domain or "." not in domain:
        return None
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        return None
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain):
        return None
    return value


def payload_checksum(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


def idempotency_key(identity: OdooIdentity, campaign_or_list_id: str) -> str:
    return (
        f"odoo:{identity.model}:{identity.record_id}:campaign:{campaign_or_list_id}:"
        f"{identity.revision}:vicidial:{identity.connector_id}"
    )


def _unique(candidates: Iterable[Candidate]) -> set[Candidate]:
    return set(candidates)


def resolve_identity(
    *,
    mapped: Candidate | None,
    external_reference: Candidate | None,
    phone_candidates: Iterable[Candidate],
    email_candidates: Iterable[Candidate],
) -> Resolution:
    """Apply strict priority while blocking ambiguous or cross-channel matches."""
    if mapped:
        return Resolution(MatchStatus.MAPPED, mapped)
    if external_reference:
        return Resolution(MatchStatus.EXTERNAL_REFERENCE, external_reference)

    phones = _unique(phone_candidates)
    emails = _unique(email_candidates)
    if len(phones) > 1:
        return Resolution(MatchStatus.REVIEW_REQUIRED, reason="PHONE_AMBIGUOUS")
    if len(emails) > 1:
        return Resolution(MatchStatus.REVIEW_REQUIRED, reason="EMAIL_AMBIGUOUS")
    phone = next(iter(phones), None)
    email = next(iter(emails), None)
    if phone and email and phone.key != email.key:
        return Resolution(MatchStatus.IDENTITY_CONFLICT, reason="PHONE_EMAIL_CONFLICT")
    if phone:
        return Resolution(MatchStatus.UNIQUE_PHONE, phone)
    if email:
        return Resolution(MatchStatus.UNIQUE_EMAIL, email)
    return Resolution(MatchStatus.NO_MATCH)


def verify_suppression(*, available: bool, active: bool, consent: str) -> None:
    if not available:
        raise SuppressionUnavailable("SUPPRESSION_STATE_UNAVAILABLE")
    if active or consent.lower() not in {"granted", "approved"}:
        raise SuppressionActive("SUPPRESSION_ACTIVE")


def decide_action(
    resolution: Resolution,
    *,
    suppression_available: bool,
    suppression_active: bool,
    consent: str,
    eligible: bool,
    payload_changed: bool,
) -> SyncAction:
    verify_suppression(
        available=suppression_available, active=suppression_active, consent=consent
    )
    if not eligible:
        return SyncAction.WITHDRAW
    if resolution.status == MatchStatus.REVIEW_REQUIRED:
        return SyncAction.REVIEW_REQUIRED
    if resolution.status == MatchStatus.IDENTITY_CONFLICT:
        return SyncAction.IDENTITY_CONFLICT
    if resolution.status == MatchStatus.NO_MATCH:
        return SyncAction.CREATE
    return SyncAction.UPDATE if payload_changed else SyncAction.NO_CHANGE


METRIC_NAMES = (
    "sync_run_total",
    "sync_run_duration_seconds",
    "sync_records_processed_total",
    "sync_leads_created_total",
    "sync_leads_updated_total",
    "sync_leads_deactivated_total",
    "sync_duplicates_detected_total",
    "sync_identity_conflicts_total",
    "sync_phone_conflicts_total",
    "sync_email_conflicts_total",
    "sync_suppression_rejections_total",
    "sync_idempotency_replay_total",
    "sync_overlap_skipped_total",
    "sync_last_success_timestamp",
    "sync_cursor_lag_seconds",
)
