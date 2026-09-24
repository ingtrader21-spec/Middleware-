from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.registry import Envelope


def envelope(business_unit: str | None) -> dict:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "event_type": "vicidial.call.ended",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "correlation_id": "synthetic-scope-test",
        "client_instance": "vicidial-server-b",
        "business_unit": business_unit,
        "payload": {},
    }


@pytest.mark.parametrize(
    "business_unit", ["MOY", "COD", "SCP", "MBL", "RLP", "FTP", "TRX", "CAL", None]
)
def test_governed_business_units_are_accepted(business_unit):
    assert (
        Envelope.model_validate(envelope(business_unit)).business_unit == business_unit
    )


def test_unknown_business_unit_is_rejected():
    with pytest.raises(ValidationError):
        Envelope.model_validate(envelope("WRONG_TENANT_SYN"))
