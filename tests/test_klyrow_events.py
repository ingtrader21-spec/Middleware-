from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from jsonschema import Draft202012Validator

from app.api.internal.klyrow_events import (
    KLYROW_EVENT_TYPES,
    PATH,
    KlyrowEvent,
    klyrow_event_schema,
    operation_id_for_klyrow_event,
    receive_klyrow_event,
    router,
)
from app.core.config import Settings as CoreSettings
from app.storage import (
    KLYROW_ODOO_PROJECTION_DESTINATION,
    MemoryInboxStore,
)


API_KEY = "klyrow-api-key-fixture"
HMAC_SECRET = b"klyrow-hmac-secret-fixture-at-least-32-bytes"
EVENT_DATA = {
    "klyrow.tenant.created": {
        "tenant_id": "tenant-1",
        "name": "Tenant One",
        "organization_id": "org-1",
        "enabled": True,
    },
    "klyrow.tenant.updated": {
        "tenant_id": "tenant-1",
        "name": "Tenant One Updated",
        "organization_id": "org-1",
        "enabled": True,
    },
    "klyrow.subscription.changed": {
        "subscription_id": "subscription-1",
        "status": "ACTIVE",
        "plan_id": "plan-1",
        "price_id": "price-1",
        "version": 2,
        "effective_at": "2026-09-13T00:00:00Z",
    },
    "klyrow.usage.daily": {
        "date": "2026-09-12",
        "unit": "accepted_message",
        "quantity": 7,
        "snapshot_at": "2026-09-13T00:00:00Z",
    },
    "klyrow.kpi.daily": {
        "date": "2026-09-12",
        "accepted": 10,
        "delivered": 9,
        "bounced": 1,
        "complained": 0,
        "snapshot_at": "2026-09-13T00:00:00Z",
    },
    "klyrow.campaign.summary": {
        "campaign_id": "campaign-1",
        "campaign_version": 1,
        "status": "COMPLETED",
        "audience_count": 10,
        "delivered_count": 9,
        "suppressed_count": 0,
        "failed_count": 1,
    },
    "klyrow.domain.status": {
        "domain_id": "domain-1",
        "domain": "example.test",
        "status": "VERIFIED",
        "verified_at": "2026-09-13T00:00:00Z",
    },
    "klyrow.provider.health": {
        "provider": "postal",
        "status": "HEALTHY",
        "checked_at": "2026-09-13T00:00:00Z",
        "reason_code": None,
    },
    "klyrow.account.held": {
        "status": "HELD",
        "reason": "synthetic fixture",
        "changed_at": "2026-09-13T00:00:00Z",
    },
    "klyrow.account.released": {
        "status": "RELEASED",
        "reason": "synthetic fixture",
        "changed_at": "2026-09-13T00:00:00Z",
    },
}
ROOT = Path(__file__).parents[1]


def _body(*, event_id: str = "evt_usage_1", quantity: int = 7) -> bytes:
    return json.dumps(
        {
            "id": event_id,
            "type": "klyrow.usage.daily",
            "version": 1,
            "source": "klyrow",
            "tenant_id": "tenant-1",
            "correlation_id": "correlation-1",
            "causation_id": "operation-1",
            "occurred_at": "2026-09-13T00:00:00Z",
            "data": {
                "date": "2026-09-12",
                "unit": "accepted_message",
                "quantity": quantity,
                "snapshot_at": "2026-09-13T00:00:00Z",
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _request(
    body: bytes,
    inbox: MemoryInboxStore,
    *,
    timestamp: str | None = None,
    api_key: str = API_KEY,
    signature: str | None = None,
    enabled: bool = True,
    maximum: int | str = 1_048_576,
) -> Request:
    payload = json.loads(body)
    event_id = payload["id"]
    timestamp = timestamp or str(int(time.time()))
    signature = (
        signature
        or hmac.new(
            HMAC_SECRET,
            f"{timestamp}\n{event_id}\nklyrow\n".encode() + body,
            hashlib.sha256,
        ).hexdigest()
    )
    raw_headers = [
        (b"content-type", b"application/json"),
        (b"authorization", f"Bearer {api_key}".encode()),
        (b"x-event-id", event_id.encode()),
        (b"x-timestamp", timestamp.encode()),
        (b"x-signature", f"sha256={signature}".encode()),
        (b"idempotency-key", event_id.encode()),
        (b"x-correlation-id", payload["correlation_id"].encode()),
        (
            b"traceparent",
            b"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        ),
        (b"tracestate", b"vendor=value"),
    ]
    settings = SimpleNamespace(
        klyrow_event_ingress_enabled=enabled,
        klyrow_event_api_key=API_KEY,
        klyrow_event_api_key_file="",
        klyrow_event_hmac_secret=HMAC_SECRET.decode(),
        klyrow_event_hmac_secret_file="",
        klyrow_event_signature_ttl_seconds=300,
        klyrow_event_request_max_bytes=maximum,
    )
    app = FastAPI()
    app.state.runtime = SimpleNamespace(settings=settings, inbox=inbox)

    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": PATH,
            "headers": raw_headers,
            "app": app,
        },
        receive=receive,
    )


def _receive(request: Request) -> dict[str, str]:
    return asyncio.run(receive_klyrow_event(request, cast(AsyncSession, object())))


def test_exact_route_and_all_ten_closed_event_types_are_registered() -> None:
    route = next(item for item in router.routes if getattr(item, "path", None) == PATH)
    assert isinstance(route, APIRoute)
    assert route.methods is not None and "POST" in route.methods
    assert KLYROW_EVENT_TYPES == {
        "klyrow.tenant.created",
        "klyrow.tenant.updated",
        "klyrow.subscription.changed",
        "klyrow.usage.daily",
        "klyrow.kpi.daily",
        "klyrow.campaign.summary",
        "klyrow.domain.status",
        "klyrow.provider.health",
        "klyrow.account.held",
        "klyrow.account.released",
    }
    assert KlyrowEvent.model_json_schema()["additionalProperties"] is False
    schema = klyrow_event_schema()
    assert schema["required"] == [
        "id",
        "type",
        "version",
        "source",
        "tenant_id",
        "correlation_id",
        "occurred_at",
        "data",
    ]
    assert len(schema["allOf"]) == 10
    assert schema["properties"]["id"]["maxLength"] == 200
    assert schema["properties"]["tenant_id"]["maxLength"] == 200


@pytest.mark.parametrize(("event_type", "data"), EVENT_DATA.items())
def test_all_ten_event_payload_models_match_the_producer_contract(
    event_type: str,
    data: dict[str, object],
) -> None:
    event = KlyrowEvent.model_validate(
        {
            "id": "evt_contract_1",
            "type": event_type,
            "version": 1,
            "source": "klyrow",
            "tenant_id": "tenant-1",
            "correlation_id": "correlation-1",
            "causation_id": "cause-1",
            "occurred_at": "2026-09-13T00:00:00Z",
            "data": data,
        }
    )
    assert event.type == event_type

    schema = KlyrowEvent.model_json_schema()["properties"]
    assert schema["id"]["maxLength"] == 200
    assert schema["tenant_id"]["maxLength"] == 200
    assert schema["correlation_id"]["maxLength"] == 200


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("version"),
        lambda value: value.pop("source"),
        lambda value: value["data"].pop("unit"),
    ),
)
def test_wire_required_fields_cannot_be_filled_by_receiver_defaults(mutation) -> None:
    value = json.loads(_body())
    mutation(value)
    body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(HTTPException) as invalid:
        _receive(_request(body, MemoryInboxStore()))
    assert invalid.value.status_code == 422
    assert invalid.value.detail == "invalid_klyrow_event"


def test_tenant_enabled_is_required_on_the_wire() -> None:
    value = json.loads(_body())
    value["type"] = "klyrow.tenant.created"
    value["data"] = {"tenant_id": value["tenant_id"]}
    body = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(HTTPException) as invalid:
        _receive(_request(body, MemoryInboxStore()))
    assert invalid.value.status_code == 422


def test_valid_signed_event_is_durable_before_exact_ack_and_duplicate_is_safe() -> None:
    inbox = MemoryInboxStore()
    body = _body()
    first = _receive(_request(body, inbox))
    second = _receive(_request(body, inbox))

    assert first == second
    assert first["status"] == "ACCEPTED"
    assert first["operation_id"] == operation_id_for_klyrow_event("evt_usage_1")
    assert len(inbox.ledger_records) == 1
    persisted = inbox.ledger_records[0].payload
    assert persisted["source"] == "klyrow-gateway"
    assert persisted["event_type"] == "codestra.klyrow.usage.daily"
    assert persisted["correlation_id"] == "correlation-1"
    assert persisted["payload"]["operation_id"] == first["operation_id"]
    assert persisted["payload"]["trace_context"]["traceparent"].startswith("00-")
    assert persisted["payload"]["trace_context"]["tracestate"] == "vendor=value"


@pytest.mark.parametrize(
    ("api_key", "signature"),
    (("wrong-api-key", None), (API_KEY, "0" * 64)),
)
def test_invalid_bearer_or_hmac_is_rejected(
    api_key: str,
    signature: str | None,
) -> None:
    request = _request(
        _body(), MemoryInboxStore(), api_key=api_key, signature=signature
    )
    with pytest.raises(HTTPException) as error:
        _receive(request)
    assert error.value.status_code == 401


def test_stale_timestamp_and_oversized_body_are_rejected() -> None:
    with pytest.raises(HTTPException) as stale:
        _receive(
            _request(
                _body(),
                MemoryInboxStore(),
                timestamp=str(int(time.time()) - 301),
            )
        )
    assert stale.value.status_code == 401
    assert stale.value.detail == "expired_klyrow_signature"

    with pytest.raises(HTTPException) as oversized:
        _receive(_request(_body(), MemoryInboxStore(), maximum=16))
    assert oversized.value.status_code == 413

    with pytest.raises(HTTPException) as invalid_limit:
        _receive(_request(_body(), MemoryInboxStore(), maximum="not-an-integer"))
    assert invalid_limit.value.status_code == 503
    assert invalid_limit.value.detail == "klyrow_request_configuration_invalid"


def test_same_event_id_with_different_payload_is_a_security_conflict() -> None:
    inbox = MemoryInboxStore()
    _receive(_request(_body(quantity=7), inbox))
    with pytest.raises(HTTPException) as conflict:
        _receive(_request(_body(quantity=8), inbox))
    assert conflict.value.status_code == 409
    assert len(inbox.ledger_records) == 1


def test_ingress_flag_defaults_fail_closed_and_projection_destination_is_explicit() -> (
    None
):
    settings = CoreSettings()
    assert settings.klyrow_event_ingress_enabled is False
    assert settings.klyrow_odoo_projection_enabled is False
    with pytest.raises(HTTPException) as disabled:
        _receive(_request(_body(), MemoryInboxStore(), enabled=False))
    assert disabled.value.status_code == 503
    assert disabled.value.detail == "klyrow_event_ingress_disabled"
    assert KLYROW_ODOO_PROJECTION_DESTINATION == "odoo-klyrow-projection-v1"


def test_composed_runtime_flags_default_off(test_settings) -> None:
    assert test_settings.klyrow_event_ingress_enabled is False
    assert test_settings.klyrow_odoo_projection_enabled is False


def test_versioned_contracts_and_production_lock_statement_are_valid() -> None:
    paths = {
        "klyrow-event-v1.schema.json",
        "klyrow-usage-daily-v1.schema.json",
        "klyrow-kpi-daily-v1.schema.json",
        "klyrow-campaign-summary-v1.schema.json",
        "klyrow-domain-status-v1.schema.json",
        "klyrow-provider-health-v1.schema.json",
    }
    for name in paths:
        Draft202012Validator.check_schema(
            json.loads((ROOT / "contracts" / name).read_text())
        )
    ingress = json.loads((ROOT / "config/klyrow-event-ingress.v1.json").read_text())
    assert set(ingress["event_types"]) == KLYROW_EVENT_TYPES
    assert ingress["enabled_by_default"] is False
    assert ingress["projection_enabled_by_default"] is False
    assert ingress["production"] == {
        "authorized": False,
        "lock_decision": "NO_GO",
        "live_effects_enabled": False,
        "odoo_write_enabled": False,
    }
