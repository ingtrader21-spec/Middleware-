import pytest

from app.core.vicidial_mapping import (
    CampaignIdentity,
    MappingValidationError,
    physical_campaign_id,
    validate_registry,
    validate_version_change,
)


def test_identifier_is_deterministic_and_fits_vicidial_limit():
    first = physical_campaign_id("COD-WEB-OUT")
    assert first == physical_campaign_id("COD-WEB-OUT")
    assert len(first) == 8
    assert first.isalnum() and first.isupper()


def test_reserved_collision_is_resolved_deterministically():
    original = physical_campaign_id("COD-WEB-OUT")
    replacement = physical_campaign_id("COD-WEB-OUT", reserved_ids={original})
    assert replacement != original
    assert replacement == physical_campaign_id("COD-WEB-OUT", reserved_ids={original})


def test_cross_business_unit_mapping_is_rejected():
    record = CampaignIdentity("staging", "MOY", "COD-WEB-OUT", "COD12345")
    with pytest.raises(MappingValidationError, match="business unit mismatch"):
        record.validate()


def test_cross_environment_duplicate_physical_id_is_rejected():
    records = [
        CampaignIdentity("development", "COD", "COD-WEB-OUT", "COD12345"),
        CampaignIdentity("staging", "COD", "COD-WEB-OUT", "COD12345"),
    ]
    with pytest.raises(MappingValidationError, match="duplicate physical"):
        validate_registry(records)


def test_production_activation_is_fail_closed():
    record = CampaignIdentity(
        "production", "COD", "COD-WEB-OUT", "COD12345", active=True
    )
    with pytest.raises(MappingValidationError, match="separate approval"):
        record.validate()


def test_mapping_version_cannot_decrease():
    with pytest.raises(MappingValidationError, match="cannot decrease"):
        validate_version_change(3, 2)
