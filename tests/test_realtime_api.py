from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from app.main import create_app
from app.realtime import MemoryRealtimeStore, RealtimeEvent, RealtimePrincipal, stream_events
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


class RealtimeTokenVerifier:
    def __init__(self, *, campaign_id: str = "campaign-1", agent_id: str = "agent-1") -> None:
        self.campaign_id = campaign_id
        self.agent_id = agent_id

    async def verify(self, authorization: str, *, expected_client_id: str,
                     required_scope: str) -> dict[str, Any]:
        from app.security import AuthenticationError
        if authorization != "Bearer gateway-token" or expected_client_id != "websocket-gateway":
            raise AuthenticationError("invalid test token")
        return {"azp": expected_client_id, "scope": required_scope,
                "tenant_id": "tenant-1", "campaign_id": self.campaign_id,
                "agent_id": self.agent_id}

    async def ready(self) -> bool: return True


def _runtime(test_settings, store, verifier=None):
    return Runtime(settings=test_settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(),
                   tokens=verifier or RealtimeTokenVerifier(), realtime=store)


def test_ticket_is_consumed_exactly_once(test_settings) -> None:
    store = MemoryRealtimeStore()
    ticket = "a" * 32
    asyncio.run(store.issue_for_test(ticket, RealtimePrincipal(
        tenant_id="tenant-1", campaign_id="campaign-1", agent_id="agent-1",
        role="agent", expires_at=datetime.now(UTC) + timedelta(minutes=1))))
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings, store))) as client:
        headers = {"Authorization": "Bearer gateway-token"}
        first = client.post("/internal/v1/realtime/tickets/consume", json={"ticket": ticket, "tenant_id": "tenant-1"}, headers=headers)
        second = client.post("/internal/v1/realtime/tickets/consume", json={"ticket": ticket, "tenant_id": "tenant-1"}, headers=headers)
    assert first.status_code == 200
    assert first.json()["campaign_id"] == "campaign-1"
    assert first.headers["cache-control"] == "no-store"
    assert second.status_code == 401


def test_ticket_consume_rejects_token_tenant_mismatch(test_settings) -> None:
    store = MemoryRealtimeStore()
    ticket = "c" * 32
    asyncio.run(store.issue_for_test(ticket, RealtimePrincipal(
        tenant_id="tenant-1", campaign_id="campaign-1", agent_id="agent-1",
        role="agent", expires_at=datetime.now(UTC) + timedelta(minutes=1))))
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings, store))) as client:
        response = client.post(
            "/internal/v1/realtime/tickets/consume",
            json={"ticket": ticket, "tenant_id": "tenant-2"},
            headers={"Authorization": "Bearer gateway-token"},
        )
    assert response.status_code == 403


def test_concurrent_ticket_consumption_has_one_winner() -> None:
    async def scenario() -> list[RealtimePrincipal | None]:
        store = MemoryRealtimeStore()
        ticket = "b" * 32
        await store.issue_for_test(ticket, RealtimePrincipal(
            "tenant-1", "campaign-1", "agent-1", "agent",
            datetime.now(UTC) + timedelta(minutes=1)))
        return await asyncio.gather(*(store.consume_ticket(ticket, datetime.now(UTC), "tenant-1") for _ in range(20)))
    assert sum(item is not None for item in asyncio.run(scenario())) == 1


def test_event_stream_is_strictly_scope_filtered() -> None:
    async def scenario() -> list[dict[str, Any]]:
        store = MemoryRealtimeStore()
        now = datetime.now(UTC)
        for sequence, tenant, campaign, agent in (
            (1, "tenant-1", "campaign-1", "agent-1"),
            (2, "tenant-1", "campaign-2", "agent-1"),
            (3, "tenant-1", "campaign-1", "agent-2"),
            (4, "tenant-2", "campaign-1", "agent-1"),
        ):
            await store.append_for_test(RealtimeEvent(sequence, tenant, campaign, agent,
                "telephony.call-state.v1", {"state": "ringing"}, now))
        calls = 0
        async def disconnected() -> bool:
            nonlocal calls
            calls += 1
            return calls > 1
        chunks = [chunk async for chunk in stream_events(store, tenant_id="tenant-1",
            campaign_id="campaign-1", agent_id="agent-1", after=0,
            disconnected=disconnected, poll_seconds=0)]
        return [json.loads(chunk) for chunk in chunks]
    events = asyncio.run(scenario())
    assert [item["sequence"] for item in events] == [1]


def test_stream_rejects_campaign_or_agent_claim_mismatch(test_settings) -> None:
    store = MemoryRealtimeStore()
    with TestClient(create_app(settings=test_settings, runtime=_runtime(test_settings, store))) as client:
        response = client.get("/internal/v1/realtime/events/stream", params={
            "tenant_id": "tenant-1", "campaign_id": "campaign-other", "agent_id": "agent-1"},
            headers={"Authorization": "Bearer gateway-token"})
    assert response.status_code == 403
