"""Authenticated, fail-closed campaign mapping projection."""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditEvent
from app.db.session import get_session

router = APIRouter(prefix="/v1/mappings/campaigns", tags=["campaign-mappings"])
ALLOWED_UNITS = frozenset({"MOY", "COD", "SCP", "MBL", "RLP", "FTP", "TRX", "CAL"})
_requests: dict[str, deque[float]] = defaultdict(deque)


def _authorize_scope(
    environment: str, requested_unit: str, authorized_unit: str
) -> None:
    if environment != "staging":
        raise HTTPException(403, "only staging mappings are available")
    if requested_unit not in ALLOWED_UNITS or authorized_unit not in ALLOWED_UNITS:
        raise HTTPException(403, "business unit is not authorized")
    if requested_unit != authorized_unit:
        raise HTTPException(403, "cross-business-unit mapping lookup denied")


def _rate_limit(key: str) -> None:
    now = time.monotonic()
    bucket = _requests[key]
    while bucket and bucket[0] < now - 60:
        bucket.popleft()
    if len(bucket) >= 60:
        raise HTTPException(429, "mapping lookup rate limit exceeded")
    bucket.append(now)


def _serialize(row) -> dict:
    item = dict(row)
    for key, value in tuple(item.items()):
        if value is not None and key.endswith("_uuid"):
            item[key] = str(value)
    item["production_eligible"] = False
    item["operational_allowed"] = False
    return item


async def _audit(
    db: AsyncSession, action: str, unit: str, count: int, correlation: str
) -> None:
    db.add(
        AuditEvent(
            action=action,
            subject=unit,
            correlation_id=correlation,
            decision="read-only",
            redacted_payload={"business_unit": unit, "result_count": count},
        )
    )
    await db.commit()


BASE_SQL = """
SELECT mapping_uuid, schema_version, mapping_version, environment,
       business_unit_code AS business_unit, canonical_campaign_code,
       vicidial_campaign_id, direction, n8n_scope, desired_state_hash,
       active, drift_status, odoo_business_unit_uuid, odoo_crm_team_uuid,
       odoo_campaign_uuid
FROM vicidial_campaign_registry
"""


@router.get("")
async def list_campaign_mappings(
    request: Request,
    response: Response,
    business_unit: str = Query(..., min_length=3, max_length=3),
    environment: str = Query("staging"),
    operational_action: bool = Query(False),
    authorized_unit: str = Header(..., alias="X-Business-Unit"),
    correlation: str | None = Header(None, alias="X-Correlation-ID"),
    db: AsyncSession = Depends(get_session),
):
    business_unit = business_unit.upper()
    authorized_unit = authorized_unit.upper()
    _authorize_scope(environment, business_unit, authorized_unit)
    _rate_limit(
        f"{request.client.host if request.client else 'unknown'}:{authorized_unit}"
    )
    if operational_action:
        raise HTTPException(
            409, "inactive mappings cannot authorize operational actions"
        )
    rows = (
        (
            await db.execute(
                text(
                    BASE_SQL
                    + " WHERE environment=:environment AND business_unit_code=:unit "
                    "ORDER BY canonical_campaign_code"
                ),
                {"environment": environment, "unit": business_unit},
            )
        )
        .mappings()
        .all()
    )
    items = [_serialize(row) for row in rows]
    digest = hashlib.sha256(
        json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    correlation = correlation or str(uuid4())
    await _audit(db, "campaign.mapping.listed", business_unit, len(items), correlation)
    response.headers["X-Response-SHA256"] = digest
    return {
        "mapping_version": max((x["mapping_version"] for x in items), default=0),
        "response_hash": digest,
        "items": items,
    }


@router.get("/{canonical_campaign_code}")
async def get_campaign_mapping(
    canonical_campaign_code: str,
    request: Request,
    response: Response,
    environment: str = Query("staging"),
    operational_action: bool = Query(False),
    authorized_unit: str = Header(..., alias="X-Business-Unit"),
    correlation: str | None = Header(None, alias="X-Correlation-ID"),
    db: AsyncSession = Depends(get_session),
):
    code = canonical_campaign_code.upper()
    row = (
        (
            await db.execute(
                text(
                    BASE_SQL + " WHERE environment=:environment "
                    "AND canonical_campaign_code=:code"
                ),
                {"environment": environment, "code": code},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(404, "unknown canonical campaign")
    unit = row["business_unit"]
    _authorize_scope(environment, unit, authorized_unit.upper())
    _rate_limit(
        f"{request.client.host if request.client else 'unknown'}:{authorized_unit.upper()}"
    )
    if operational_action or row["active"]:
        raise HTTPException(
            409, "inactive mappings cannot authorize operational actions"
        )
    item = _serialize(row)
    digest = hashlib.sha256(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    correlation = correlation or str(uuid4())
    await _audit(db, "campaign.mapping.read", unit, 1, correlation)
    response.headers["X-Response-SHA256"] = digest
    return {
        "mapping_version": item["mapping_version"],
        "response_hash": digest,
        "item": item,
    }
