from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.v1 import integrations


RESULT = {
    "event_id": "event-1",
    "correlation_id": "correlation-1",
    "idempotency_key": "result:event-1:1",
    "workflow_key": "CDST_" + "FollowupDue_v1",
    "execution_id": "execution-1",
    "status": "COMPLETED",
    "actions": [],
    "completed_at": "2026-08-22T18:00:00Z",
}


class FakeSession:
    def __init__(self, values):
        self.values = iter(values)
        self.added = []
        self.commits = 0
        self.rollbacks = 0

    async def scalar(self, _query):
        return next(self.values)

    async def execute(self, _query, _values):
        return None

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


def claims():
    return {"campaigns": ["CMP-MBL"], "business_units": ["MBL"]}


def event():
    return SimpleNamespace(
        id=17,
        original_event_id="event-1",
        correlation_id="correlation-1",
        idempotency_key="result:event-1:1",
        payload_json={
            "event_id": "event-1", "campaign_id": "CMP-MBL",
            "business_unit_id": "MBL",
        },
    )


@pytest.mark.asyncio
async def test_standard_result_requires_durable_source_binding(monkeypatch):
    monkeypatch.setattr(integrations, "_authenticate_n8n", lambda *_: claims())
    with pytest.raises(HTTPException) as raised:
        await integrations.n8n_result(
            RESULT, authorization="Bearer synthetic", idempotency_key="result:event-1:1",
            db=FakeSession([None]),
        )
    assert raised.value.status_code == 409


@pytest.mark.asyncio
async def test_action_result_remains_fail_closed_before_durable_delivery(monkeypatch):
    monkeypatch.setattr(integrations, "_authenticate_n8n", lambda *_: claims())
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", False)
    body = {**RESULT, "actions": [{
        "action_type": "SET_NEXT_ACTION", "entity_type": "crm.lead", "entity_id": "17",
        "values": {"next_action_type": "CALL"},
    }]}
    with pytest.raises(HTTPException) as raised:
        await integrations.n8n_result(
            body, authorization="Bearer synthetic", idempotency_key="result:event-1:1",
            db=FakeSession([event()]),
        )
    assert raised.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action_type", ["CREATE_ACTIVITY", "CREATE_DRAFT", "SEND_EMAIL", "SEND_SMS"]
)
async def test_action_without_production_adapter_is_rejected_before_delivery(
    monkeypatch, action_type
):
    monkeypatch.setattr(integrations, "_authenticate_n8n", lambda *_: claims())
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", True)
    body = {**RESULT, "actions": [{
        "action_type": action_type, "entity_type": "crm.lead", "entity_id": "17",
        "values": {},
    }]}
    db = FakeSession([event()])
    with pytest.raises(HTTPException) as raised:
        await integrations.n8n_result(
            body, authorization="Bearer synthetic", idempotency_key="result:event-1:1",
            db=db,
        )
    assert raised.value.status_code == 503
    assert "adapter is not production enabled" in raised.value.detail
    assert db.added == []
    assert db.commits == 0


@pytest.mark.asyncio
async def test_action_result_is_enqueued_when_writes_are_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(integrations, "_authenticate_n8n", lambda *_: claims())
    monkeypatch.setattr(integrations.settings, "odoo_automation_writes_enabled", True)
    body = {**RESULT, "actions": [{
        "action_type": "SET_NEXT_ACTION", "entity_type": "crm.lead", "entity_id": "17",
        "values": {
            "next_action_type": "CALL", "next_action_at": "2026-08-23T12:00:00Z",
            "next_action_owner_id": 9,
        },
    }]}
    db = FakeSession([event(), None])
    response = await integrations.n8n_result(
        body, authorization="Bearer synthetic", idempotency_key="result:event-1:1", db=db,
    )
    assert response["accepted"] == "true"
    assert len(db.added) == 3
    delivery = db.added[1]
    assert delivery.integration_event_id == 17
    assert delivery.status == "PENDING"
    assert delivery.standard_result_json["actions"] == body["actions"]
    assert db.commits == 1


@pytest.mark.asyncio
async def test_empty_result_is_durably_idempotent_and_audited(monkeypatch):
    monkeypatch.setattr(integrations, "_authenticate_n8n", lambda *_: claims())
    db = FakeSession([event(), None])
    response = await integrations.n8n_result(
        RESULT, authorization="Bearer synthetic", idempotency_key="result:event-1:1", db=db,
    )
    assert response == {"accepted": "true", "event_id": "event-1", "status": "COMPLETED"}
    assert len(db.added) == 2
    assert db.commits == 1
