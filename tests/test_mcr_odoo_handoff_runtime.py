from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import mcr_odoo_handoff as api
from app.appolon_routes import install_error_handlers
from app.core.mcr_odoo_handoff import (
    HandoffAcceptance,
    McrOdooHandoffConflict,
    McrOdooHandoffNotFound,
    expected_idempotency_key,
)


TENANT = "TEST_SYN_TENANT"
COMMAND_ID = UUID("00000000-0000-4000-8000-000000000901")
CORR = "corr-mcr-odoo"
CAUS = "cause-mcr-odoo"


class FakeTokens:
    def __init__(self):
        self.calls = []

    async def verify(self, authorization, *, expected_client_id, required_scope):
        self.calls.append((authorization, expected_client_id, required_scope))
        if authorization != "Bearer good":
            raise api.AuthenticationError("bad token")
        return {"tenant_id": TENANT, "azp": expected_client_id, "scope": required_scope}


class FakeStore:
    records: dict[str, dict] = {}
    accept_calls = []
    reconcile_calls = []

    def __init__(self, pool):
        self.pool = pool

    @classmethod
    def reset(cls):
        cls.records = {}
        cls.accept_calls = []
        cls.reconcile_calls = []

    async def accept(self, command, *, causation_id, accepted_at=None):
        FakeStore.accept_calls.append((command, causation_id))
        key = str(command["command_id"])
        existing = FakeStore.records.get(key)
        if existing is not None:
            if existing["_command"] != command:
                raise McrOdooHandoffConflict("handoff identity was reused with different evidence")
            return HandoffAcceptance(
                command_id=UUID(key),
                correlation_id=command["correlation_id"],
                idempotency_key=command["idempotency_key"],
                duplicate=True,
            )
        p = command["payload"]
        FakeStore.records[key] = {
            "_command": json.loads(json.dumps(command)),
            "schema_version": "1.0",
            "tenant_id": command["tenant_id"],
            "lead_id": p["lead_id"],
            "campaign_id": p["campaign_id"],
            "campaign_version": p["campaign_version"],
            "lifecycle_version": p["lifecycle_version"],
            "policy_version": p["policy_version"],
            "handoff": p["handoff"],
            "command_id": key,
            "correlation_id": command["correlation_id"],
            "idempotency_key": command["idempotency_key"],
            "payload_hash": "f" * 64,
            "status": "accepted",
            "odoo_record_id": None,
            "observed_lifecycle_version": None,
            "observed_at": "2026-09-25T12:00:00+00:00",
        }
        return HandoffAcceptance(
            command_id=UUID(key),
            correlation_id=command["correlation_id"],
            idempotency_key=command["idempotency_key"],
            duplicate=False,
        )

    async def readback(self, tenant_id, command_id):
        row = FakeStore.records.get(str(command_id))
        if row is None or row["tenant_id"] != tenant_id:
            raise McrOdooHandoffNotFound("handoff not found")
        return {k: v for k, v in row.items() if k != "_command"}

    async def request_reconciliation(
        self,
        tenant_id,
        command_id,
        *,
        idempotency_key,
        correlation_id,
        causation_id,
        requested_at=None,
    ):
        FakeStore.reconcile_calls.append(
            (tenant_id, command_id, idempotency_key, correlation_id, causation_id)
        )
        return await self.readback(tenant_id, command_id)


@pytest.fixture(autouse=True)
def reset_store(monkeypatch):
    FakeStore.reset()
    monkeypatch.setattr(api, "PostgresMcrOdooHandoffStore", FakeStore)


def command_body(*, evidence_hash="a" * 64):
    payload = {
        "schema_version": "1.0",
        "lead_id": "100-L-00000001",
        "campaign_id": "klyrow:test-syn-mcr",
        "campaign_version": 1,
        "lifecycle_version": 2,
        "policy_version": "mcr-policy-1.0.0",
        "handoff": "engaged",
        "lifecycle_state": "ENGAGED",
        "signal": "reply",
        "evidence_source": "middleware",
        "evidence_id": "evt-mcr-odoo-1",
        "evidence_hash": evidence_hash,
        "occurred_at": "2026-09-25T12:00:00Z",
        "dry_run": True,
        "allow_external_contact": False,
    }
    body = {
        "command_id": str(COMMAND_ID),
        "command_type": "crm.lifecycle.handoff",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": TENANT,
        "requested_by": "svc:mcr",
        "correlation_id": CORR,
        "idempotency_key": "pending",
        "capability": "ODOO_WRITE",
        "payload": payload,
    }
    body["idempotency_key"] = expected_idempotency_key(body)
    return body


def headers(body=None, *, token="good", include_idempotency=True):
    result = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": TENANT,
        "X-Correlation-ID": CORR,
        "X-Causation-ID": CAUS,
    }
    if include_idempotency and body is not None:
        result["Idempotency-Key"] = body["idempotency_key"]
    return result


def app_with(*, clients="middleware-worker"):
    tokens = FakeTokens()
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(api.router)
    app.state.runtime = SimpleNamespace(
        pool=object(),
        tokens=tokens,
        settings=SimpleNamespace(mcr_odoo_handoff_client_ids=clients),
    )
    return app, tokens


def test_empty_caller_allowlist_fails_closed_before_store():
    app, tokens = app_with(clients="")
    body = command_body()
    with TestClient(app) as client:
        response = client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dependency_unavailable"
    assert FakeStore.accept_calls == []
    assert tokens.calls == []


def test_first_acceptance_is_durable_and_has_no_crm_effect():
    app, tokens = app_with()
    body = command_body()
    with TestClient(app) as client:
        response = client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body)
    assert response.status_code == 202, response.text
    assert response.json() == {
        "command_id": str(COMMAND_ID),
        "correlation_id": CORR,
        "status": "accepted",
        "duplicate": False,
        "crm_completed": False,
    }
    assert len(FakeStore.accept_calls) == 1
    assert tokens.calls[-1][1:] == ("middleware-worker", "crm.handoff.write")


def test_exact_replay_returns_200_without_second_effect():
    app, _ = app_with()
    body = command_body()
    with TestClient(app) as client:
        first = client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body)
        second = client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body)
    assert first.status_code == 202
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert len(FakeStore.records) == 1


def test_conflicting_replay_returns_409():
    app, _ = app_with()
    body = command_body()
    with TestClient(app) as client:
        assert client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body).status_code == 202
        conflict = command_body(evidence_hash="b" * 64)
        conflict["idempotency_key"] = body["idempotency_key"]
        response = client.post("/platform/v1/crm/handoffs", headers=headers(conflict), json=conflict)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "command_conflict"


def test_readback_and_reconcile_are_tenant_bound_and_no_effect():
    app, tokens = app_with()
    body = command_body()
    with TestClient(app) as client:
        assert client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body).status_code == 202
        read = client.get(f"/platform/v1/crm/handoffs/{COMMAND_ID}", headers=headers())
        reconcile = client.post(
            f"/platform/v1/crm/handoffs/{COMMAND_ID}/reconcile",
            headers={**headers(), "Idempotency-Key": "reconcile-odoo-0001"},
        )
    assert read.status_code == 200
    assert read.json()["status"] == "accepted"
    assert read.json()["odoo_record_id"] is None
    assert reconcile.status_code == 200
    assert reconcile.json() == read.json()
    assert len(FakeStore.reconcile_calls) == 1
    assert [call[2] for call in tokens.calls[-2:]] == [
        "crm.handoff.read",
        "crm.handoff.reconcile",
    ]


def test_wrong_tenant_never_discloses_handoff():
    app, _ = app_with()
    body = command_body()
    with TestClient(app) as client:
        assert client.post("/platform/v1/crm/handoffs", headers=headers(body), json=body).status_code == 202
        bad = headers()
        bad["X-Tenant-ID"] = "OTHER"
        response = client.get(f"/platform/v1/crm/handoffs/{COMMAND_ID}", headers=bad)
    assert response.status_code == 403
