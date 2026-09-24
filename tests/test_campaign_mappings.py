import pytest
from fastapi import HTTPException

from app.api.v1.mappings import _authorize_scope, _serialize


def test_scope_accepts_matching_staging_unit():
    _authorize_scope("staging", "COD", "COD")


@pytest.mark.parametrize(
    "environment,requested,authorized",
    [
        ("production", "COD", "COD"),
        ("staging", "COD", "MOY"),
        ("staging", "BAD", "BAD"),
    ],
)
def test_scope_fails_closed(environment, requested, authorized):
    with pytest.raises(HTTPException) as exc:
        _authorize_scope(environment, requested, authorized)
    assert exc.value.status_code == 403


def test_serialized_mapping_is_never_operational_or_production_eligible():
    item = _serialize(
        {
            "mapping_uuid": "78a11f21-0a11-4d65-8d4b-31575fb54b6f",
            "active": False,
            "mapping_version": 1,
        }
    )
    assert item["production_eligible"] is False
    assert item["operational_allowed"] is False
