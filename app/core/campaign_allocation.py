"""Precise campaign extension-allocation validation and database errors."""

from __future__ import annotations

from dataclasses import dataclass
from sqlalchemy.exc import IntegrityError


class CampaignAllocationError(ValueError):
    pass


@dataclass(frozen=True)
class AllocationInput:
    campaign_id: str
    campaign_number: int
    allocation_public_id: str
    extension_start: int
    extension_end: int


def validate_allocation(value: AllocationInput) -> AllocationInput:
    if value.extension_start < 6100 or value.extension_end > 9999:
        raise CampaignAllocationError("EXTENSION_OUT_OF_SUPPORTED_RANGE")
    if value.extension_start > value.extension_end:
        raise CampaignAllocationError("EXTENSION_RANGE_INVALID")
    if value.campaign_number <= 0 or value.campaign_number % 100:
        raise CampaignAllocationError("CAMPAIGN_NUMBER_INVALID")
    if not value.campaign_id or not value.allocation_public_id:
        raise CampaignAllocationError("CAMPAIGN_ALLOCATION_IDENTITY_INVALID")
    return value


CONSTRAINT_ERRORS = {
    "ex_campaign_extension_allocation_no_overlap": "EXTENSION_RANGE_OVERLAP",
    "ck_campaign_extension_allocation_start": "EXTENSION_OUT_OF_SUPPORTED_RANGE",
    "ck_campaign_extension_allocation_end": "EXTENSION_OUT_OF_SUPPORTED_RANGE",
    "ck_campaign_extension_allocation_order": "EXTENSION_RANGE_INVALID",
    "campaign_extension_allocation_campaign_id_key": "CAMPAIGN_ALLOCATION_ALREADY_EXISTS",
    "campaign_extension_allocation_campaign_number_key": "CAMPAIGN_ALLOCATION_ALREADY_EXISTS",
    "campaign_extension_allocation_allocation_public_id_key": "CAMPAIGN_ALLOCATION_ALREADY_EXISTS",
    "tr_campaign_extension_allocation_no_delete": "HISTORICAL_RANGE_REUSE_PROHIBITED",
    "tr_campaign_extension_allocation_immutable": "HISTORICAL_RANGE_REUSE_PROHIBITED",
}


def translate_integrity_error(exc: IntegrityError) -> CampaignAllocationError:
    original = getattr(exc, "orig", None)
    diagnostic = getattr(original, "diag", None)
    name = getattr(diagnostic, "constraint_name", None)
    if not isinstance(name, str):
        raise exc
    code = CONSTRAINT_ERRORS.get(name)
    if code is None:
        raise exc
    return CampaignAllocationError(code)
