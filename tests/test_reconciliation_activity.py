from __future__ import annotations

import json
from contextlib import AbstractAsyncContextManager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from temporalio.exceptions import ApplicationError

from app.commands import (
    AUTHENTICATED_CLIENT_ID_KEY,
    CommandEnvelope,
    PostgresCommandStore,
    authenticated_command_digest,
)
from app.calling_contract import CAPABILITY, CLIENT_ID, HANGUP, TARGET
from app.temporal_activities import (
    CommandLedgerWorkflowActivities,
    FailClosedWorkflowActivities,
)
from app.temporal_workflows import ActivityResult, ReconciliationRequest


class _Context(AbstractAsyncContextManager[Any]):
    def __init__(self, value: Any) -> None:
        self.value = value

    async def __aenter__(self) -> Any:
        return self.value

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


class FakeConnection:
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    def transaction(self) -> _Context:
        return _Context(self)

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        normalized = " ".join(query.split())
        if normalized.startswith("SELECT * FROM middleware_commands"):
            return dict(self.row)
        if "UPDATE middleware_commands" in normalized:
            if "SET state='completed'" in normalized:
                self.row["state"] = "completed"
                self.row["provider_operation_id"] = (
                    args[2] or self.row.get("provider_operation_id")
                )
                self.row["last_error"] = None
            else:
                self.row["provider_operation_id"] = (
                    args[2] or self.row.get("provider_operation_id")
                )
                self.row["last_error"] = args[3]
                self.row["reconciliation_reason"] = args[3]
            self.row["resource_version"] += 1
            return dict(self.row)
        raise AssertionError(f"unexpected fetchrow query: {normalized}")

    async def execute(self, query: str, *args: Any) -> str:
        self.executed.append((" ".join(query.split()), args))
        return "OK"


class FakePool:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def acquire(self) -> _Context:
        return _Context(self.connection)


class FakeStore:
    def __init__(self, row: dict[str, Any]) -> None:
        self.pool = FakePool(FakeConnection(row))

    async def get(self, tenant_id, command_id):
        return SimpleNamespace(
            provider_operation_id=self.pool.connection.row.get(
                "provider_operation_id"
            ),
            readback_evidence={"status": "matched"},
        )


class FakeAdapter:
    def __init__(self, result: ActivityResult) -> None:
        self.result = result
        self.requests: list[Any] = []

    async def execute(self, request):
        raise AssertionError("reconciliation must never execute a provider write")

    async def readback(self, request):
        self.requests.append(request)
        return self.result


class MutatingReadbackAdapter(FakeAdapter):
    def __init__(self, result: ActivityResult, row: dict[str, Any]) -> None:
        super().__init__(result)
        self.row = row

    async def readback(self, request):
        self.requests.append(request)
        payload = json.loads(self.row["payload"])
        payload["requested_by"] = "tampered-during-readback"
        self.row["payload"] = json.dumps(payload)
        self.row["payload_sha256"] = "0" * 64
        return self.result


def durable_row(*, state: str = "reconciliation_required") -> dict[str, Any]:
    command_id = str(uuid4())
    authenticated_client_id = "test-client"
    public_payload = {
        "command_id": command_id,
        "command_type": "crm.contact.create.v1",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "user-123",
        "correlation_id": "correlation-123",
        "idempotency_key": "idempotency-123",
        "capability": "ODOO_WRITE",
        "payload": {"contact_id": "contact-1"},
    }
    command = CommandEnvelope.model_validate(public_payload)
    payload = {
        **public_payload,
        AUTHENTICATED_CLIENT_ID_KEY: authenticated_client_id,
    }
    return {
        "command_id": command_id,
        "tenant_id": "tenant-1",
        "state": state,
        "payload": json.dumps(payload),
        "payload_sha256": authenticated_command_digest(
            command,
            authenticated_client_id,
        ),
        "provider_operation_id": None,
        "last_error": "outcome unknown",
        "reconciliation_reason": "operator requested readback",
        "resource_version": 1,
    }


def completed_hangup_row() -> dict[str, Any]:
    row = durable_row(state="completed")
    public_payload = {
        "command_id": row["command_id"], "command_type": HANGUP,
        "command_version": "1.0", "target": TARGET, "tenant_id": "tenant-1",
        "requested_by": "subject-appolon", "correlation_id": "correlation-123",
        "idempotency_key": "hangup-restart-0001", "capability": CAPABILITY,
        "payload": {
            "actor": {"tenant_id": "tenant-1", "subject": "subject-appolon",
                      "employee_id": "employee-appolon", "campaign_id": "TEST_SYN",
                      "business_unit": "business-test", "extension": "6901"},
            "originate": {}, "origin_operation_id": str(uuid4()),
            "call_id": "codestra-call-1",
            "authorization_reference": "CHG-APPOLON-TEST-0001",
            "policy_sha256": "a" * 64, "reason": "Agent hangup",
        },
    }
    command = CommandEnvelope.model_validate(public_payload)
    row["payload"] = json.dumps({
        **public_payload, AUTHENTICATED_CLIENT_ID_KEY: CLIENT_ID,
    })
    row["payload_sha256"] = authenticated_command_digest(command, CLIENT_ID)
    row["provider_operation_id"] = "codestra-call-1"
    return row


@pytest.mark.asyncio
async def test_completed_hangup_retry_repairs_original_without_provider_mutation() -> None:
    row = completed_hangup_row()
    store = FakeStore(row)
    adapter = FakeAdapter(ActivityResult("matched", "must not be called"))
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        store, vicidial_internal=adapter,  # type: ignore[arg-type]
    )
    activities.complete_originating_call = AsyncMock(  # type: ignore[method-assign]
        return_value=ActivityResult("completed", "original repaired")
    )

    result = await activities.reconcile_operation(ReconciliationRequest(
        row["command_id"], row["tenant_id"], "restart recovery",
    ))

    assert result.status == "completed"
    activities.complete_originating_call.assert_awaited_once()
    assert adapter.requests == []


@pytest.mark.asyncio
async def test_matched_reconciliation_reads_back_and_completes_durably() -> None:
    row = durable_row()
    store = FakeStore(row)
    adapter = FakeAdapter(
        ActivityResult(
            status="matched",
            detail="provider identity matched",
            provider_operation_id=row["command_id"],
            readback_evidence={"schema_version": "1.0", "status": "matched"},
        )
    )
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        Mock(spec=PostgresCommandStore, wraps=store, pool=store.pool),
        odoo=adapter,  # type: ignore[arg-type]
    )

    result = await activities.reconcile_operation(
        ReconciliationRequest(
            operation_id=row["command_id"],
            tenant_id=row["tenant_id"],
            reason="operator requested authoritative readback",
        )
    )

    assert result.status == "completed"
    assert store.pool.connection.row["state"] == "completed"
    assert store.pool.connection.row["resource_version"] == 2
    assert len(adapter.requests) == 1
    assert adapter.requests[0].authenticated_client_id == "test-client"
    assert any(
        "INSERT INTO middleware_command_audit" in query
        for query, _ in store.pool.connection.executed
    )
    assert any(
        "UPDATE middleware_command_attempts" in query
        for query, _ in store.pool.connection.executed
    )


@pytest.mark.asyncio
async def test_mismatch_is_persisted_without_blind_provider_resubmission() -> None:
    row = durable_row()
    store = FakeStore(row)
    adapter = FakeAdapter(
        ActivityResult(
            status="mismatch",
            detail="provider did not confirm the durable intent",
            provider_operation_id=row["command_id"],
        )
    )
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        Mock(spec=PostgresCommandStore, wraps=store, pool=store.pool),
        odoo=adapter,  # type: ignore[arg-type]
    )

    result = await activities.reconcile_operation(
        ReconciliationRequest(
            operation_id=row["command_id"],
            tenant_id=row["tenant_id"],
            reason="operator requested authoritative readback",
        )
    )

    assert result.status == "reconciliation_required"
    assert store.pool.connection.row["state"] == "reconciliation_required"
    assert store.pool.connection.row["resource_version"] == 2
    assert store.pool.connection.row["last_error"] == (
        "provider did not confirm the durable intent"
    )
    assert len(adapter.requests) == 1


@pytest.mark.asyncio
async def test_missing_durable_client_provenance_fails_closed() -> None:
    row = durable_row()
    payload = json.loads(row["payload"])
    del payload[AUTHENTICATED_CLIENT_ID_KEY]
    row["payload"] = payload
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        Mock(spec=PostgresCommandStore, wraps=FakeStore(row), pool=FakePool(FakeConnection(row))),
        odoo=FakeAdapter(ActivityResult("matched", "unused")),  # type: ignore[arg-type]
    )

    with pytest.raises(ApplicationError, match="client provenance"):
        await activities.reconcile_operation(
            ReconciliationRequest(
                operation_id=row["command_id"],
                tenant_id=row["tenant_id"],
                reason="operator requested authoritative readback",
            )
        )


@pytest.mark.asyncio
async def test_tampered_durable_payload_digest_fails_before_provider_readback() -> None:
    row = durable_row()
    payload = json.loads(row["payload"])
    payload["requested_by"] = "tampered-before-readback"
    row["payload"] = json.dumps(payload)
    adapter = FakeAdapter(ActivityResult("matched", "must not run"))
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        Mock(spec=PostgresCommandStore, wraps=FakeStore(row), pool=FakePool(FakeConnection(row))),
        odoo=adapter,  # type: ignore[arg-type]
    )

    with pytest.raises(ApplicationError, match="payload digest"):
        await activities.reconcile_operation(
            ReconciliationRequest(
                operation_id=row["command_id"],
                tenant_id=row["tenant_id"],
                reason="operator requested authoritative readback",
            )
        )
    assert adapter.requests == []


@pytest.mark.asyncio
async def test_command_change_during_readback_cannot_complete_operation() -> None:
    row = durable_row()
    store = FakeStore(row)
    adapter = MutatingReadbackAdapter(
        ActivityResult(
            status="matched",
            detail="provider identity matched",
            provider_operation_id=row["command_id"],
        ),
        store.pool.connection.row,
    )
    activities = CommandLedgerWorkflowActivities(  # type: ignore[arg-type]
        Mock(spec=PostgresCommandStore, wraps=store, pool=store.pool),
        odoo=adapter,  # type: ignore[arg-type]
    )

    with pytest.raises(ApplicationError, match="payload digest"):
        await activities.reconcile_operation(
            ReconciliationRequest(
                operation_id=row["command_id"],
                tenant_id=row["tenant_id"],
                reason="operator requested authoritative readback",
            )
        )
    assert store.pool.connection.row["state"] == "reconciliation_required"
    assert store.pool.connection.row["resource_version"] == 1
    assert len(adapter.requests) == 1


def test_fail_closed_registry_no_longer_shadows_reconciliation_activity() -> None:
    names = {item.__name__ for item in FailClosedWorkflowActivities().registered()}
    assert "reconcile_operation" not in names
