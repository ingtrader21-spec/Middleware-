from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.db.models import CallbackDelivery, CallbackRecord
from app.workers.callback_realtime import _document


def callback() -> CallbackRecord:
    return CallbackRecord(
        id=uuid4(),
        tenant_id="COD",
        campaign_id="TEST_SYN",
        assigned_agent_id="synthetic.agent.test.syn.6101",
        assigned_user_id="keycloak-user-6101",
        assigned_team_id=None,
        phone_number="+1 809 555 0123",
        scheduled_at=datetime.now(UTC),
        customer_timezone="America/Santo_Domingo",
        priority="HIGH",
        reason="Synthetic reminder",
        state="DUE",
        version=4,
        correlation_id="callback-correlation",
        context_json={"customer_name": "TEST SYNTHETIC", "last_disposition": "TEST"},
    )


def delivery(row: CallbackRecord) -> CallbackDelivery:
    return CallbackDelivery(
        id=uuid4(),
        callback_id=row.id,
        callback_version=row.version,
        channel="POPUP",
        stage="DUE",
        idempotency_key=f"callback:{row.id}:v{row.version}:popup:due",
    )


def test_realtime_document_is_tenant_campaign_and_identity_bound() -> None:
    row = callback()
    document = _document(delivery(row), row)
    assert document["type"] == "callback.due"
    assert document["tenant_id"] == "COD"
    assert document["campaign_id"] == "TEST_SYN"
    assert document["user_id"] == "keycloak-user-6101"
    assert document["agent_id"] == "synthetic.agent.test.syn.6101"
    assert document["event_id"].endswith(":popup:due")
    assert document["payload"]["phone_masked"] == "***0123"
    assert "+1 809" not in str(document)


def test_realtime_document_rejects_incomplete_target() -> None:
    row = callback()
    row.assigned_user_id = None
    with pytest.raises(ValueError, match="target is incomplete"):
        _document(delivery(row), row)


def test_realtime_document_rejects_unknown_stage() -> None:
    row = callback()
    item = delivery(row)
    item.stage = "UNAPPROVED"
    with pytest.raises(ValueError, match="unsupported"):
        _document(item, row)
