from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from app.models import EventEnvelope
from app.vicidial_odoo_projection import (
    CALL_EVENT_PATH,
    DeterministicRejection,
    KnownNotDelivered,
    OdooCallEventDispatcher,
    OutcomeUnknown,
    ProjectionConflict,
    ProjectionSettings,
    ProjectionState,
    project_envelope,
)


def envelope(event_type="codestra.vicidial.call.lifecycle.created") -> EventEnvelope:
    now = datetime.now(timezone.utc)
    return EventEnvelope(
        event_id="vici-evt-1234567890abcdef",
        event_type=event_type,
        event_version="1.0",
        occurred_at=now,
        received_at=now,
        source="vicidial-adapter",
        tenant_id="COD",
        correlation_id="vici-call-123",
        causation_id="ami-12345678",
        idempotency_key="vici-evt-1234567890abcdef",
        payload={
            "schema_version": "1.0",
            "business_unit_id": "COD",
            "campaign_id": "TEST_SYN",
            "call_id": "vici-call-123",
            "asterisk_uniqueid": "1710000000.1",
            "linkedid": "1710000000.1",
            "agent_id": "SYN6101",
            "extension": "6101",
            "keycloak_subject": "00000000-0000-0000-0000-000000006101",
            "sequence": 1,
            "direction": "inbound",
            "caller_number": "+18095550100",
        },
        metadata={"transport": "ami"},
    )


def evidence(event, *, recorded=True):
    return {
        "event_id": event.event_id,
        "tenant_id": event.tenant_id,
        "call_id": event.call_id,
        "event_type": event.event_type,
        "sequence": event.sequence,
        "recorded": recorded,
    }


def dispatcher(client: httpx.AsyncClient) -> OdooCallEventDispatcher:
    return OdooCallEventDispatcher(
        client=client,
        base_url="https://odoo.example.test",
        tenant_secrets={"COD": b"s" * 32},
    )


def test_projection_maps_current_ami_namespace() -> None:
    event = project_envelope(envelope(), synthetic_only=True)
    assert event.event_type == "call.created"
    assert event.synthetic_test is True
    assert event.sequence == 1


def test_projection_state_is_idempotent_and_detects_conflict(tmp_path: Path) -> None:
    state = ProjectionState(tmp_path / "state.sqlite3")
    event = project_envelope(envelope(), synthetic_only=True)
    assert state.register(event) == "received"
    assert state.register(event) == "received"
    changed = event.model_copy(update={"caller_number": "+18095550999"})
    with pytest.raises(ProjectionConflict):
        state.register(changed)


@pytest.mark.asyncio
async def test_exact_odoo_evidence_completes() -> None:
    event = project_envelope(envelope(), synthetic_only=True)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == CALL_EVENT_PATH
        assert request.headers["x-codestra-event-id"] == event.event_id
        return httpx.Response(202, json=evidence(event))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await dispatcher(client).submit(event)


@pytest.mark.asyncio
async def test_ambiguous_post_uses_readback_and_never_blindly_retries() -> None:
    event = project_envelope(envelope(), synthetic_only=True)
    methods = []

    async def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.method == "POST":
            return httpx.Response(504)
        return httpx.Response(200, json=evidence(event))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await dispatcher(client).submit(event)
    assert methods == ["POST", "GET"]


@pytest.mark.asyncio
async def test_sequence_gap_contract_is_the_only_retryable_post_conflict() -> None:
    event = project_envelope(envelope(), synthetic_only=True).model_copy(
        update={"sequence": 3}
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                **evidence(event, recorded=False),
                "error": "sequence_gap",
                "retryable": True,
                "detail": "one or more earlier lifecycle events are not recorded",
                "expected_sequence": 2,
                "current_sequence": 1,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(KnownNotDelivered, match="waiting for 2"):
            await dispatcher(client).submit(event)


@pytest.mark.asyncio
async def test_terminal_odoo_conflict_is_not_retried() -> None:
    event = project_envelope(envelope(), synthetic_only=True)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                **evidence(event, recorded=False),
                "error": "lifecycle_conflict",
                "retryable": False,
                "detail": "invalid state transition",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(DeterministicRejection, match="lifecycle_conflict"):
            await dispatcher(client).submit(event)


@pytest.mark.asyncio
async def test_mismatched_conflict_evidence_keeps_outcome_unknown() -> None:
    event = project_envelope(envelope(), synthetic_only=True)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                **evidence(event, recorded=False),
                "event_id": "different-event",
                "error": "sequence_gap",
                "retryable": True,
                "expected_sequence": 1,
                "current_sequence": 0,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(OutcomeUnknown, match="event_id"):
            await dispatcher(client).submit(event)


@pytest.mark.asyncio
async def test_readback_404_is_the_only_safe_retry_signal() -> None:
    event = project_envelope(envelope(), synthetic_only=True)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(KnownNotDelivered):
            await dispatcher(client).reconcile(event, reason="test")


def test_settings_are_disabled_by_default() -> None:
    settings = ProjectionSettings.from_env({"APP_ENV": "development"})
    assert settings.enabled is False
    assert settings.synthetic_only is True
