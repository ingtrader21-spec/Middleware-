import pytest
from fastapi import HTTPException

from app.api.v1 import automation


EVENT = {
    "schema_version": "1",
    "event_id": "event-1",
    "event_type": "followup.due",
    "correlation_id": "correlation-1",
    "idempotency_key": "event-1:1",
    "tenant_id": "codestra",
    "business_unit_id": "MBL",
    "campaign_id": "MBL-NEW-LOAN-OUT",
    "entity_type": "crm.lead",
    "entity_id": "17",
    "actor_type": "SYSTEM",
    "actor_id": "middleware",
    "previous_status": "DOCUMENTS_REQUESTED",
    "current_status": "DOCUMENTS_PARTIAL",
    "occurred_at": "2026-08-22T18:00:00Z",
    "automation_key": "moneybee_documents_partial",
    "payload": {},
}


@pytest.mark.asyncio
async def test_campaign_policy_requires_bearer_token():
    with pytest.raises(HTTPException) as raised:
        await automation.policy_check(EVENT, authorization="")
    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_campaign_policy_binds_token_scope(monkeypatch):
    monkeypatch.setattr(
        automation,
        "_authenticate_campaign_policy",
        lambda _: {"campaigns": ["MBL-NEW-LOAN-OUT"], "business_units": ["MBL"]},
    )
    monkeypatch.setattr(
        automation.settings,
        "automation_allowed_campaigns",
        "MBL-NEW-LOAN-OUT,SRP-STUDENT-OUT",
    )
    response = await automation.policy_check(EVENT, authorization="Bearer synthetic")
    assert response["allowed"] is True
    assert response["campaign_id"] == "MBL-NEW-LOAN-OUT"


@pytest.mark.asyncio
async def test_campaign_policy_denies_cross_campaign_token(monkeypatch):
    monkeypatch.setattr(
        automation,
        "_authenticate_campaign_policy",
        lambda _: {"campaigns": ["SRP-STUDENT-OUT"], "business_units": ["SRP"]},
    )
    monkeypatch.setattr(
        automation.settings,
        "automation_allowed_campaigns",
        "MBL-NEW-LOAN-OUT,SRP-STUDENT-OUT",
    )
    with pytest.raises(HTTPException) as raised:
        await automation.policy_check(EVENT, authorization="Bearer synthetic")
    assert raised.value.status_code == 403
