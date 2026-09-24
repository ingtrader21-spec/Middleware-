"""Fail-closed orchestration APIs.

These APIs persist intent and disabled work only. They never create an account,
return a secret, send mail, or write to VICIdial while production provisioning
is disabled.
"""

import hashlib
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LeadSyncRequest, OrchestrationRequest
from app.db.session import get_session

router = APIRouter(prefix="/api/v1/orchestration", tags=["orchestration"])
UNITS = frozenset({"TL", "DEV", "SCP", "SHR", "TST"})
RESOURCES = frozenset({"odoo", "keycloak", "vicidial", "inbound_group", "endpoint"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProvisioningIntent(StrictModel):
    request_uid: str = Field(min_length=1, max_length=128)
    operation: Literal["provision", "offboard"]
    business_unit: str = Field(min_length=2, max_length=16)
    subject_reference: str = Field(min_length=1, max_length=128)
    department_reference: str = Field(min_length=1, max_length=128)
    team_reference: str = Field(min_length=1, max_length=128)
    supervisor_reference: str = Field(min_length=1, max_length=128)
    campaign_references: list[str] = Field(max_length=50)
    requested_resources: list[str] = Field(min_length=1, max_length=10)
    correlation_id: str = Field(min_length=1, max_length=128)
    expires_at: datetime


class LeadSyncIntent(StrictModel):
    source_reference: str = Field(min_length=1, max_length=128)
    business_unit: str = Field(min_length=2, max_length=16)
    campaign_reference: str = Field(min_length=1, max_length=128)
    list_reference: str = Field(min_length=1, max_length=128)
    lead_reference: str = Field(min_length=1, max_length=128)
    preferred_language: str = Field(min_length=2, max_length=8)
    correlation_id: str = Field(min_length=1, max_length=128)


def _validate_unit(unit: str) -> None:
    if unit not in UNITS:
        raise HTTPException(422, "business unit is not authorized")


@router.post("/provisioning", status_code=202)
async def create_provisioning_intent(
    body: ProvisioningIntent,
    response: Response,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_session),
):
    _validate_unit(body.business_unit)
    if body.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(422, "authorization has expired")
    if not set(body.requested_resources).issubset(RESOURCES):
        raise HTTPException(422, "requested resource is not authorized")
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    existing = await db.scalar(
        select(OrchestrationRequest).where(
            OrchestrationRequest.idempotency_hash == key_hash
        )
    )
    canonical = body.model_dump(mode="json")
    if existing:
        expected = {
            "request_uid": existing.request_uid,
            "operation": existing.operation,
            "business_unit": existing.business_unit,
            "subject_reference": existing.subject_reference,
            "department_reference": existing.department_reference,
            "team_reference": existing.team_reference,
            "supervisor_reference": existing.supervisor_reference,
            "campaign_references": existing.campaign_references,
            "requested_resources": existing.requested_resources,
            "correlation_id": existing.correlation_id,
            "expires_at": existing.expires_at.isoformat().replace("+00:00", "Z"),
        }
        if canonical != expected:
            raise HTTPException(409, "idempotency key conflict")
        response.headers["X-Idempotent-Replay"] = "true"
        return {"request_id": str(existing.id), "state": existing.state}
    record = OrchestrationRequest(
        id=uuid4(),
        request_uid=body.request_uid,
        operation=body.operation,
        business_unit=body.business_unit,
        subject_reference=body.subject_reference,
        department_reference=body.department_reference,
        team_reference=body.team_reference,
        supervisor_reference=body.supervisor_reference,
        campaign_references=body.campaign_references,
        requested_resources=body.requested_resources,
        correlation_id=body.correlation_id,
        idempotency_hash=key_hash,
        state="disabled",
        expires_at=body.expires_at,
    )
    db.add(record)
    await db.commit()
    response.headers["X-Idempotent-Replay"] = "false"
    return {"request_id": str(record.id), "state": "disabled"}


@router.post("/lead-sync", status_code=202)
async def create_lead_sync_intent(
    body: LeadSyncIntent,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_session),
):
    _validate_unit(body.business_unit)
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    payload = body.model_dump(mode="json")
    payload_hash = hashlib.sha256(repr(sorted(payload.items())).encode()).hexdigest()
    existing = await db.scalar(
        select(LeadSyncRequest).where(LeadSyncRequest.idempotency_hash == key_hash)
    )
    if existing:
        if existing.payload_hash != payload_hash:
            raise HTTPException(409, "idempotency key conflict")
        return {"request_id": str(existing.id), "state": existing.state}
    record = LeadSyncRequest(
        id=uuid4(),
        source_reference=body.source_reference,
        business_unit=body.business_unit,
        campaign_reference=body.campaign_reference,
        list_reference=body.list_reference,
        canonical_payload=payload,
        payload_hash=payload_hash,
        idempotency_hash=key_hash,
        correlation_id=body.correlation_id,
        state="disabled",
    )
    db.add(record)
    await db.commit()
    return {"request_id": str(record.id), "state": "disabled"}
