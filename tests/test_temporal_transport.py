from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest.mock import Mock
from temporalio.client import Client
from uuid import uuid4

import pytest
from temporalio.common import WorkflowIDConflictPolicy, WorkflowIDReusePolicy

from app.commands import AUTHENTICATED_CLIENT_ID_KEY, TEMPORAL_COMMAND_DESTINATION
from app.storage import OutboxRecord
from app.temporal_transport import (
    RECONCILIATION_EVENT_TYPE,
    TemporalCommandDispatcher,
    TemporalTransportError,
    command_workflow_id,
    reconciliation_workflow_id,
)
from app.temporal_workflows import CommandExecutionRequest, ReconciliationRequest


def command_record() -> OutboxRecord:
    command_id = str(uuid4())
    payload = {
        AUTHENTICATED_CLIENT_ID_KEY: "n8n-automation",
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
    return OutboxRecord(
        id=1,
        tenant_id="tenant-1",
        destination=TEMPORAL_COMMAND_DESTINATION,
        event_type="crm.contact.create.v1",
        idempotency_key="idempotency-123",
        payload=payload,
        attempt_count=1,
    )


def reconciliation_record() -> OutboxRecord:
    command_id = str(uuid4())
    return OutboxRecord(
        id=2,
        tenant_id="tenant-1",
        destination=TEMPORAL_COMMAND_DESTINATION,
        event_type=RECONCILIATION_EVENT_TYPE,
        idempotency_key="operation-reconcile:" + "a" * 64,
        payload={
            "command_id": command_id,
            "action": "reconcile",
            "reason": "operator requested authoritative provider readback",
        },
        attempt_count=1,
    )


async def trusted_reconciliation_command_id(record: OutboxRecord) -> str | None:
    value = record.payload.get("command_id")
    return value if isinstance(value, str) else None


class RecordingTemporalClient:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, Any, dict[str, Any]]] = []

    async def start_workflow(self, workflow, request, **options):
        self.calls.append((workflow, request, options))
        return object()


@pytest.mark.asyncio
async def test_command_dispatch_uses_deterministic_exactly_once_workflow_identity() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")
    record = command_record()

    await dispatcher.dispatch(record)
    assert len(client.calls) == 1
    _, request, options = client.calls[0]
    assert request.tenant_id == record.tenant_id
    assert request.authenticated_client_id == "n8n-automation"
    assert options["id"] == command_workflow_id(
        record.tenant_id,
        record.payload["command_id"],
        record.idempotency_key,
    )
    assert options["id_reuse_policy"] is WorkflowIDReusePolicy.REJECT_DUPLICATE
    assert options["id_conflict_policy"] is WorkflowIDConflictPolicy.USE_EXISTING


@pytest.mark.asyncio
async def test_reconciliation_dispatch_uses_supported_dedicated_workflow_request() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(
        client,
        "codestra-test-critical",
        reconciliation_command_id_lookup=trusted_reconciliation_command_id,
    )
    record = reconciliation_record()

    await dispatcher.dispatch(record)

    assert len(client.calls) == 1
    _, request, options = client.calls[0]
    assert isinstance(request, ReconciliationRequest)
    assert request.operation_id == record.payload["command_id"]
    assert request.tenant_id == record.tenant_id
    assert request.reason == record.payload["reason"]
    assert options["id"] == reconciliation_workflow_id(
        record.tenant_id,
        record.payload["command_id"],
        record.idempotency_key,
    )
    assert options["id_reuse_policy"] is WorkflowIDReusePolicy.REJECT_DUPLICATE
    assert options["id_conflict_policy"] is WorkflowIDConflictPolicy.USE_EXISTING


@pytest.mark.asyncio
async def test_reconciliation_dispatch_requires_durable_outbox_identity_lookup() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")

    with pytest.raises(TemporalTransportError, match="identity verification"):
        await dispatcher.dispatch(reconciliation_record())
    assert client.calls == []


@pytest.mark.asyncio
async def test_reconciliation_dispatch_rejects_payload_command_identity_mismatch() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    record = reconciliation_record()
    trusted_command_id = str(record.payload["command_id"])
    tampered = replace(
        record,
        payload={**record.payload, "command_id": str(uuid4())},
    )

    async def lookup(_record: OutboxRecord) -> str | None:
        return trusted_command_id

    dispatcher = TemporalCommandDispatcher(
        client,
        "codestra-test-critical",
        reconciliation_command_id_lookup=lookup,
    )

    with pytest.raises(TemporalTransportError, match="durable outbox command"):
        await dispatcher.dispatch(tampered)
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload_update", "idempotency_key", "message"),
    [
        ({"action": "retry"}, None, "unsupported action"),
        ({"reason": ""}, None, "invalid safe reason"),
        ({"command_id": ""}, None, "invalid operation identity"),
        ({"unexpected": True}, None, "versioned contract"),
        ({}, "wrong-prefix", "invalid idempotency identity"),
    ],
)
async def test_reconciliation_dispatch_fails_closed_on_invalid_intent(
    payload_update: dict[str, Any],
    idempotency_key: str | None,
    message: str,
) -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")
    record = reconciliation_record()
    payload = {**record.payload, **payload_update}
    record = replace(
        record,
        payload=payload,
        idempotency_key=idempotency_key or record.idempotency_key,
    )

    with pytest.raises(TemporalTransportError, match=message):
        await dispatcher.dispatch(record)
    assert client.calls == []


@pytest.mark.asyncio
async def test_command_dispatch_rejects_cross_tenant_outbox_payload() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")
    record = command_record()
    record.payload["tenant_id"] = "different-tenant"
    with pytest.raises(TemporalTransportError):
        await dispatcher.dispatch(record)
    assert client.calls == []


@pytest.mark.asyncio
async def test_retry_dispatch_resumes_from_durable_queued_state() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")
    record = command_record()
    retry_key = "operation-retry:" + "a" * 64
    payload = {**record.payload, "idempotency_key": retry_key}
    record = replace(record, idempotency_key=retry_key, payload=payload)

    await dispatcher.dispatch(record)

    assert client.calls[0][1].resume_from_queued is True


@pytest.mark.asyncio
async def test_command_dispatch_rejects_missing_authenticated_client_provenance() -> None:
    client = Mock(spec=Client, wraps=RecordingTemporalClient())
    client.calls = client._mock_wraps.calls
    dispatcher = TemporalCommandDispatcher(client, "codestra-test-critical")
    record = command_record()
    del record.payload[AUTHENTICATED_CLIENT_ID_KEY]
    with pytest.raises(TemporalTransportError, match="client provenance"):
        await dispatcher.dispatch(record)
    assert client.calls == []


def test_legacy_workflow_payload_deserializes_with_fail_closed_provenance() -> None:
    request = CommandExecutionRequest(
        command_id="command-legacy-1",
        command_type="crm.lead.upsert",
        command_version="1.0",
        target="odoo-19",
        tenant_id="tenant-1",
        requested_by="user-1",
        correlation_id="correlation-legacy-1",
        idempotency_key="idempotency-legacy-1",
        capability="ODOO_WRITE",
        payload={"source_record_id": "lead-1"},
    )

    assert request.authenticated_client_id == ""
