"""Typed Odoo campaign-control adapter.

This module is deliberately narrow: callers select a versioned resource
operation, while endpoint resolution, authentication, retries, and transport
remain owned by :class:`OdooDeliveryClient`. Operation names, scopes, the
effective-state vocabulary and the readback field list come from
``contracts/odoo/campaign-control.v1.json``.
"""

from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.adapters.odoo.client import OdooDeliveryClient

CATALOG_PATH = Path(__file__).resolve().parents[3] / "contracts" / "odoo" / "campaign-control.v1.json"

EffectiveState = Literal[
    "unknown", "absent", "provisioned_disabled", "synthetic_tested", "active", "disabled"
]
CampaignOperation = Literal["provision", "synthetic_test", "activate", "disable", "reconcile"]
STALE_CONFIGURATION_VERSION = "STALE_CONFIGURATION_VERSION"


class OdooCampaignAdapterError(RuntimeError):
    """Raised when Odoo returns an invalid or unsuccessful adapter response."""


class OdooCampaignStaleVersion(OdooCampaignAdapterError):
    """Odoo rejected the readback because the configuration version is stale (409)."""


class OdooCampaignAdapterUnavailable(OdooCampaignAdapterError):
    """Odoo answered 5xx; the caller may retry with the same idempotency key."""


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


class DesiredState(BaseModel):
    """Odoo's authoritative answer to ``desired_state.read``."""

    model_config = ConfigDict(extra="ignore")

    campaign_public_id: str = Field(min_length=1, max_length=128)
    configuration_version: int = Field(ge=0)
    desired_state: EffectiveState
    manifest_ref: str = Field(min_length=1, max_length=256)
    manifest_hash: str = Field(min_length=1, max_length=80)


class ActualStateReadback(BaseModel):
    """Body of ``campaign.actual_state.write``; every field is required."""

    model_config = ConfigDict(extra="forbid")

    event_uuid: str = Field(min_length=1, max_length=128)
    command_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=160)
    attempt: int = Field(ge=1)
    organization_public_id: str = Field(min_length=1, max_length=128)
    business_unit_public_id: str = Field(min_length=1, max_length=128)
    campaign_public_id: str = Field(min_length=1, max_length=128)
    configuration_version: int = Field(ge=0)
    operation: CampaignOperation
    effective_state: EffectiveState
    manifest_ref: str = Field(min_length=1, max_length=256)
    manifest_hash: str = Field(min_length=1, max_length=80)
    evidence: dict[str, Any]
    observed_at: datetime
    correlation_id: str = Field(min_length=1, max_length=128)
    causation_id: str = Field(min_length=1, max_length=128)


async def read_campaign(
    client: OdooDeliveryClient,
    payload: dict[str, Any],
    *,
    request_id: str,
    correlation_id: str,
    traceparent: str,
) -> dict[str, Any]:
    response = await client.request(
        "campaigns.read",
        payload,
        idempotency_key=f"read:{payload.get('campaign_public_id', '')}",
        request_id=request_id,
        correlation_id=correlation_id,
        causation_id=correlation_id,
        traceparent=traceparent,
    )
    return _decode(response, "campaigns.read")


async def read_desired_state(
    client: OdooDeliveryClient,
    payload: dict[str, Any],
    *,
    request_id: str,
    correlation_id: str,
    traceparent: str,
) -> dict[str, Any]:
    response = await client.request(
        "desired_state.read",
        payload,
        idempotency_key=f"desired-state:{payload.get('campaign_public_id', '')}",
        request_id=request_id,
        correlation_id=correlation_id,
        causation_id=correlation_id,
        traceparent=traceparent,
    )
    return _decode(response, "desired_state.read")


async def report_actual_state(
    client: OdooDeliveryClient,
    readback: ActualStateReadback,
    *,
    request_id: str,
    traceparent: str,
) -> dict[str, Any]:
    """Post verified actual state to Odoo.

    The ``Idempotency-Key`` header is the body's ``idempotency_key`` by
    construction. A 409 is a stale configuration version and is never retried;
    a 2xx must echo the readback identity (see ``response_binding`` in the
    catalog) or it is treated as an invalid response.
    """

    payload = readback.model_dump(mode="json")
    response = await client.request(
        "campaign.actual_state.write",
        payload,
        idempotency_key=readback.idempotency_key,
        request_id=request_id,
        correlation_id=readback.correlation_id,
        causation_id=readback.causation_id,
        traceparent=traceparent,
    )
    if response.status_code == 409:
        raise OdooCampaignStaleVersion(STALE_CONFIGURATION_VERSION)
    body = _decode(response, "campaign.actual_state.write")
    bound = {
        "status": "APPLIED",
        "event_uuid": readback.event_uuid,
        "command_id": readback.command_id,
        "configuration_version": readback.configuration_version,
        "effective_state": readback.effective_state,
        "correlation_id": readback.correlation_id,
    }
    if any(body.get(key) != value for key, value in bound.items()):
        raise OdooCampaignAdapterError("campaign.actual_state.write response binding mismatch")
    if not body.get("readback_id"):
        raise OdooCampaignAdapterError("campaign.actual_state.write receipt is missing")
    return body


def _decode(response: httpx.Response, operation: str) -> dict[str, Any]:
    if response.status_code >= 500:
        raise OdooCampaignAdapterUnavailable(f"{operation} upstream unavailable")
    if response.status_code >= 400:
        raise OdooCampaignAdapterError(f"{operation} rejected by Odoo")
    try:
        body = response.json()
    except ValueError as exc:
        raise OdooCampaignAdapterError(f"{operation} returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise OdooCampaignAdapterError(f"{operation} returned a non-object response")
    return body
