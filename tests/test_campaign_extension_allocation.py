from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.campaign_allocation import (
    AllocationInput,
    CampaignAllocationError,
    translate_integrity_error,
    validate_allocation,
)
from app.db.models import CampaignExtensionAllocation


def allocation(start=7100, end=7199):
    return AllocationInput("RLP100", 100, "CMP-100-RLP-RANGE", start, end)


def test_supported_boundaries_and_inclusive_model():
    assert validate_allocation(allocation(6100, 9999))
    table = CampaignExtensionAllocation.__table__
    computed = table.c.extension_range.computed.sqltext.text
    assert computed == "int4range(extension_start, extension_end, '[]')"
    assert table.c.allocation_status.server_default.arg == "PROPOSED"


@pytest.mark.parametrize(
    "start,end,code",
    [
        (6099, 6199, "EXTENSION_OUT_OF_SUPPORTED_RANGE"),
        (9900, 10000, "EXTENSION_OUT_OF_SUPPORTED_RANGE"),
        (7200, 7199, "EXTENSION_RANGE_INVALID"),
    ],
)
def test_precise_input_validation(start, end, code):
    with pytest.raises(CampaignAllocationError, match=code):
        validate_allocation(allocation(start, end))


def integrity_error(constraint):
    original = Exception("redacted")
    original.diag = SimpleNamespace(constraint_name=constraint)
    return IntegrityError("statement", {}, original)


@pytest.mark.parametrize(
    "constraint,code",
    [
        ("ex_campaign_extension_allocation_no_overlap", "EXTENSION_RANGE_OVERLAP"),
        ("ck_campaign_extension_allocation_start", "EXTENSION_OUT_OF_SUPPORTED_RANGE"),
        ("ck_campaign_extension_allocation_end", "EXTENSION_OUT_OF_SUPPORTED_RANGE"),
        ("ck_campaign_extension_allocation_order", "EXTENSION_RANGE_INVALID"),
        (
            "campaign_extension_allocation_campaign_id_key",
            "CAMPAIGN_ALLOCATION_ALREADY_EXISTS",
        ),
        (
            "tr_campaign_extension_allocation_no_delete",
            "HISTORICAL_RANGE_REUSE_PROHIBITED",
        ),
        (
            "tr_campaign_extension_allocation_immutable",
            "HISTORICAL_RANGE_REUSE_PROHIBITED",
        ),
    ],
)
def test_known_database_constraints_translate_precisely(constraint, code):
    translated = translate_integrity_error(integrity_error(constraint))
    assert isinstance(translated, CampaignAllocationError)
    assert str(translated) == code


def test_unrelated_database_error_is_not_misclassified():
    error = integrity_error("unrelated_constraint")
    with pytest.raises(IntegrityError):
        translate_integrity_error(error)


@pytest.mark.parametrize("constraint", [None, 123])
def test_missing_or_non_string_constraint_is_not_misclassified(constraint):
    error = integrity_error(constraint)
    with pytest.raises(IntegrityError):
        translate_integrity_error(error)
