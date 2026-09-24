"""Fail-closed canonical-to-VICIdial campaign identifier mapping."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable


CANONICAL_PATTERN = re.compile(r"^(MOY|COD|SCP|MBL|RLP|FTP|TRX|CAL)-[A-Z0-9-]+$")
PHYSICAL_PATTERN = re.compile(r"^[A-Z0-9]{8}$")
VALID_ENVIRONMENTS = frozenset({"development", "staging", "production"})


class MappingValidationError(ValueError):
    """Raised when a mapping violates an isolation or identifier invariant."""


@dataclass(frozen=True)
class CampaignIdentity:
    environment: str
    business_unit_code: str
    canonical_campaign_code: str
    vicidial_campaign_id: str
    mapping_version: int = 1
    active: bool = False

    def validate(self) -> None:
        environment = self.environment.lower()
        if environment not in VALID_ENVIRONMENTS:
            raise MappingValidationError("unsupported environment")
        if not CANONICAL_PATTERN.fullmatch(self.canonical_campaign_code):
            raise MappingValidationError("invalid canonical campaign code")
        canonical_business_unit = self.canonical_campaign_code.split("-", 1)[0]
        if canonical_business_unit != self.business_unit_code:
            raise MappingValidationError("campaign business unit mismatch")
        if not PHYSICAL_PATTERN.fullmatch(self.vicidial_campaign_id):
            raise MappingValidationError(
                "physical campaign ID must be 8 uppercase alphanumerics"
            )
        if self.mapping_version < 1:
            raise MappingValidationError("mapping version must be positive")
        if environment == "production" and self.active:
            raise MappingValidationError(
                "production activation requires a separate approval gate"
            )


def physical_campaign_id(
    canonical_campaign_code: str,
    *,
    reserved_ids: Iterable[str] = (),
    max_attempts: int = 4096,
) -> str:
    """Return a deterministic collision-free eight-character physical ID.

    The business-unit prefix remains visible. The five-character SHA-256 suffix
    prevents meaning-by-truncation and is stable for a given collision set.
    """

    if not CANONICAL_PATTERN.fullmatch(canonical_campaign_code):
        raise MappingValidationError("invalid canonical campaign code")
    reserved = {value.upper() for value in reserved_ids}
    prefix = canonical_campaign_code[:3]
    for attempt in range(max_attempts):
        material = (
            canonical_campaign_code
            if attempt == 0
            else f"{canonical_campaign_code}:{attempt}"
        )
        candidate = (
            prefix + hashlib.sha256(material.encode("ascii")).hexdigest()[:5].upper()
        )
        if candidate not in reserved:
            return candidate
    raise MappingValidationError(
        "unable to allocate collision-free physical campaign ID"
    )


def validate_registry(records: Iterable[CampaignIdentity]) -> None:
    canonical_keys: set[tuple[str, str]] = set()
    physical_ids: set[str] = set()
    for record in records:
        record.validate()
        canonical_key = (record.environment.lower(), record.canonical_campaign_code)
        if canonical_key in canonical_keys:
            raise MappingValidationError("duplicate canonical campaign in environment")
        if record.vicidial_campaign_id in physical_ids:
            raise MappingValidationError("duplicate physical VICIdial campaign ID")
        canonical_keys.add(canonical_key)
        physical_ids.add(record.vicidial_campaign_id)


def validate_version_change(current_version: int, requested_version: int) -> None:
    if requested_version < current_version:
        raise MappingValidationError("mapping version cannot decrease")
