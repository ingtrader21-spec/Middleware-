import asyncio
import os
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.v1 import telephony
from app.api.v1.telephony import OriginateCallRequest
from app.core.config import settings
from app.core.webrtc_production_policy import Decision
from app.db.models import AuditEvent, TelephonyCallLifecycle

AGENT_IDENTITY = {
    "campaign_ids": ["TEST_SYN"],
    "endpoint": "6101",
    "vicidial_username": "agent.syn",
    "business_unit_id": "COD",
}


def _request(**overrides) -> OriginateCallRequest:
    # Every call gets a fresh idempotency key by default -- tests that
    # specifically exercise replay pass their own matching key explicitly.
    values = {
        "idempotency_key": f"originate-test-key-{uuid4().hex}",
        "employee_id": "EMP-001",
        "campaign": "TEST_SYN",
        "business_unit": "COD",
        "destination": "+15551234567",
        "destination_class": "mobile",
        "destination_country": "US",
        "destination_timezone": "America/New_York",
        "caller_id": "+15557654321",
        "lead_model": "crm.lead",
        "lead_id": 42,
    }
    values.update(overrides)
    return OriginateCallRequest.model_validate(values)


def test_originate_fails_closed_while_policy_is_default_deny(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_default_deny(database_url, monkeypatch))


async def _scenario_default_deny(database_url: str, monkeypatch) -> None:
    monkeypatch.setattr(
        telephony,
        "_lookup_agent_assignment",
        AsyncMock(return_value=dict(AGENT_IDENTITY)),
    )
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            response = await telephony.originate_call(_request(), session, None)

        # The checked-in policy file is enabled=false/kill_switch=true, so
        # this must never reach ALLOW no matter how well-formed the request
        # is -- that is the whole point of shipping this endpoint while
        # LIVE_PSTN_DIALING stays false.
        assert response["policy_decision"] != Decision.ALLOW.value
        assert response["dialing"] == "blocked"
        # A policy-denied call is a real terminal outcome, not an
        # in-progress one -- it never reaches VICIdial, and this is recorded
        # as such (ENDED/rejected), not left looking like it's still open.
        assert response["lifecycle_state"] == "ENDED"
        assert response["fine_state"] == "rejected"
        assert response["call_id"]
        assert response["correlation_id"]

        async with factory() as session:
            lifecycle = (
                await session.execute(
                    select(TelephonyCallLifecycle).where(
                        TelephonyCallLifecycle.correlation_id
                        == response["correlation_id"]
                    )
                )
            ).scalar_one()
            assert lifecycle.destination == "+15551234567"
            assert lifecycle.source_extension == "6101"
            assert lifecycle.disposition == "REJECTED"
            assert lifecycle.lead_model == "crm.lead"
            assert lifecycle.lead_id == 42

            audit = (
                await session.execute(
                    select(AuditEvent).where(AuditEvent.subject == response["call_id"])
                )
            ).scalar_one()
            assert audit.action == "telephony.calls.originate"
            assert audit.redacted_payload["employee_id"] == "EMP-001"
            assert "destination" not in audit.redacted_payload
    finally:
        await engine.dispose()


def test_originate_is_idempotent_on_replay(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_idempotent_replay(database_url, monkeypatch))


async def _scenario_idempotent_replay(database_url: str, monkeypatch) -> None:
    lookup = AsyncMock(return_value=dict(AGENT_IDENTITY))
    monkeypatch.setattr(telephony, "_lookup_agent_assignment", lookup)
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        request = _request(idempotency_key="originate-replay-key-000000001")
        async with factory() as session:
            first = await telephony.originate_call(request, session, None)
        async with factory() as session:
            second = await telephony.originate_call(request, session, None)
        assert first == second
        # The identity lookup (and every check downstream of it) must not
        # run again on replay -- only the first call should have hit it.
        assert lookup.await_count == 1

        async with factory() as session:
            count = await session.scalar(
                select(TelephonyCallLifecycle.id).where(
                    TelephonyCallLifecycle.correlation_id == first["correlation_id"]
                )
            )
            assert count is not None
    finally:
        await engine.dispose()


def test_originate_rejects_production_campaign(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_production_campaign_rejected(database_url, monkeypatch))


async def _scenario_production_campaign_rejected(
    database_url: str, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "allow_non_test_campaigns", False)
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        from fastapi import HTTPException

        correlation_id = f"originate-prodcamp-{uuid4().hex}"
        async with factory() as session:
            with pytest.raises(HTTPException) as exc:
                await telephony.originate_call(
                    _request(campaign="PROD_CAMPAIGN"), session, correlation_id
                )
        assert exc.value.status_code == 403

        # A call rejected before ever reaching VICIdial must still leave
        # persisted evidence that it was requested (and then rejected) --
        # this is Middleware's own control-plane state, not fabricated.
        async with factory() as session:
            lifecycle = (
                await session.execute(
                    select(TelephonyCallLifecycle).where(
                        TelephonyCallLifecycle.correlation_id == correlation_id
                    )
                )
            ).scalar_one()
            assert lifecycle.fine_state == "rejected"
            assert lifecycle.lifecycle_state == "ENDED"
            assert lifecycle.hangup_cause == "pre_dial_validation:403"
            # Campaign gating happens before identity lookup -- the real
            # extension was never known, so it must stay the placeholder,
            # not silently default to something misleading.
            assert lifecycle.source_extension == ""

            audit = (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.correlation_id == correlation_id
                    )
                )
            ).scalar_one()
            assert audit.decision == "DENY"
            assert audit.redacted_payload["rejection_reason"] == (
                "pre_dial_validation:403"
            )
            assert "destination" not in audit.redacted_payload
    finally:
        await engine.dispose()


def test_originate_rejects_agent_not_assigned_to_campaign(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_unauthorized_campaign(database_url, monkeypatch))


async def _scenario_unauthorized_campaign(database_url: str, monkeypatch) -> None:
    unauthorized_identity = dict(AGENT_IDENTITY)
    unauthorized_identity["campaign_ids"] = ["SOME_OTHER_CAMPAIGN"]
    monkeypatch.setattr(
        telephony,
        "_lookup_agent_assignment",
        AsyncMock(return_value=unauthorized_identity),
    )
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        from fastapi import HTTPException

        async with factory() as session:
            with pytest.raises(HTTPException) as exc:
                await telephony.originate_call(
                    _request(idempotency_key="originate-unauth-key-00000001"),
                    session,
                    None,
                )
        assert exc.value.status_code == 403
    finally:
        await engine.dispose()


def test_originate_rejects_invalid_destination(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_invalid_destination(database_url, monkeypatch))


async def _scenario_invalid_destination(database_url: str, monkeypatch) -> None:
    monkeypatch.setattr(
        telephony,
        "_lookup_agent_assignment",
        AsyncMock(return_value=dict(AGENT_IDENTITY)),
    )
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        from fastapi import HTTPException

        correlation_id = f"originate-baddest-{uuid4().hex}"
        async with factory() as session:
            with pytest.raises(HTTPException) as exc:
                await telephony.originate_call(
                    _request(
                        idempotency_key="originate-baddest-key-000000001",
                        destination="not-a-phone-number",
                    ),
                    session,
                    correlation_id,
                )
        assert exc.value.status_code == 422

        async with factory() as session:
            lifecycle = (
                await session.execute(
                    select(TelephonyCallLifecycle).where(
                        TelephonyCallLifecycle.correlation_id == correlation_id
                    )
                )
            ).scalar_one()
            assert lifecycle.fine_state == "rejected"
            assert lifecycle.hangup_cause == "pre_dial_validation:422"
            # Identity lookup succeeded before the destination check, so the
            # real extension should have been filled in even though the call
            # was ultimately rejected.
            assert lifecycle.source_extension == "6101"

            audit = (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.correlation_id == correlation_id
                    )
                )
            ).scalar_one()
            assert audit.decision == "DENY"
            assert audit.redacted_payload["rejection_reason"] == (
                "pre_dial_validation:422"
            )
    finally:
        await engine.dispose()


def test_originate_records_accepted_when_policy_allows(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    asyncio.run(_scenario_accepted_on_allow(database_url, monkeypatch))


async def _scenario_accepted_on_allow(database_url: str, monkeypatch) -> None:
    # requested/accepted are Middleware's own control-plane states, not
    # AMI-sourced -- force the normally-default-deny policy to ALLOW so the
    # accepted transition (recorded only once dispatch is actually attempted)
    # can be exercised without needing a real VICIdial connection.
    monkeypatch.setattr(telephony, "authorize_call", lambda *_a, **_k: Decision.ALLOW)
    monkeypatch.setattr(
        telephony,
        "_lookup_agent_assignment",
        AsyncMock(return_value=dict(AGENT_IDENTITY)),
    )

    class _FakeVicidialClient:
        def __init__(self, *_a, **_k):
            pass

        def originate(self, *_a, **_k):
            return None

        def close(self):
            pass

    monkeypatch.setattr(telephony, "VicidialMtlsClient", _FakeVicidialClient)

    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        correlation_id = f"originate-accepted-{uuid4().hex}"
        async with factory() as session:
            response = await telephony.originate_call(
                _request(), session, correlation_id
            )
        assert response["policy_decision"] == Decision.ALLOW.value
        assert response["dialing"] == "attempting"
        assert response["fine_state"] == "accepted"

        async with factory() as session:
            lifecycle = (
                await session.execute(
                    select(TelephonyCallLifecycle).where(
                        TelephonyCallLifecycle.correlation_id == correlation_id
                    )
                )
            ).scalar_one()
            assert lifecycle.fine_state == "accepted"
            assert lifecycle.source_extension == "6101"
    finally:
        await engine.dispose()
