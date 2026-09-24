"""Durable telephony-result callback and authoritative Odoo readback."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    TelephonyCommandJournal,
    TelephonyOperationJournal,
    TelephonyTerminalResult,
)
from app.core.telephony_commands import stable_result_idempotency_key


class OdooTelephonyResultError(RuntimeError):
    pass


class OdooTelephonyClient(Protocol):
    async def request(
        self, operation: str, payload: dict[str, Any], **kwargs: Any
    ) -> httpx.Response: ...


def _request_kwargs(
    result: TelephonyTerminalResult, command: TelephonyCommandJournal
) -> dict[str, str]:
    return {
        "idempotency_key": stable_result_idempotency_key(
            command.command_public_id,
            result.immutable_json["operation_public_id"],
            result.target_public_id,
            result.observed_state_version,
            result.result_hash,
        ),
        "request_id": f"REQ-{uuid4()}",
        "correlation_id": result.correlation_id,
        "causation_id": result.result_public_id,
        "traceparent": (
            "00-" + result.result_hash[:32] + "-" + result.application_hash[:16] + "-01"
        ),
    }


async def deliver_telephony_result(
    session: AsyncSession,
    result_public_id: str,
    *,
    client: OdooTelephonyClient,
) -> dict[str, Any]:
    """Deliver once, recover by readback, and reconcile only after all projections match."""
    result = await session.scalar(
        select(TelephonyTerminalResult)
        .where(TelephonyTerminalResult.result_public_id == result_public_id)
        .with_for_update()
    )
    if not result:
        raise OdooTelephonyResultError("telephony result not found")
    operation = await session.get(TelephonyOperationJournal, result.operation_id)
    command = await session.get(TelephonyCommandJournal, result.command_id)
    if not operation or not command:
        raise OdooTelephonyResultError("telephony result source binding is incomplete")
    request = command.request_json
    originating_outbox = request.get("originating_outbox_public_id")
    event_id = request.get("event_id")
    if not originating_outbox or not event_id:
        raise OdooTelephonyResultError("originating Odoo binding is incomplete")
    body = {
        "schema_version": "1.0",
        "result_public_id": result.result_public_id,
        "originating_outbox_public_id": originating_outbox,
        "event_id": event_id,
        "command_id": command.command_public_id,
        "operation_public_id": operation.operation_public_id,
        "adapter_result_id": result.result_public_id,
        "correlation_id": result.correlation_id,
        "environment": command.environment,
        "organization_public_id": request.get("organization_public_id", ""),
        "business_unit_public_id": command.business_unit_public_id,
        "campaign_public_id": command.campaign_public_id,
        "result_domain": "TELEPHONY",
        "target_system": result.target_system,
        "target_resource_type": result.target_resource_type,
        "target_public_id": result.target_public_id,
        "allocation_reservation_id": command.payload_json["allocation_reservation_id"],
        "requested_state_version": result.requested_state_version,
        "applied_state_version": result.applied_state_version,
        "observed_state_version": result.observed_state_version,
        "application_status": result.application_status,
        "readback_status": result.readback_status,
        "application_hash": f"sha256:{result.application_hash}",
        "readback_hash": f"sha256:{result.readback_hash}",
        "result_hash": f"sha256:{result.result_hash}",
        "policy_hash": f"sha256:{result.policy_hash}",
        "applied_at": result.applied_at.isoformat(),
        "readback_at": result.readback_at.isoformat(),
        "payload": {"safe_summary": result.safe_summary},
    }
    kwargs = _request_kwargs(result, command)
    result.odoo_callback_status = "SUBMITTING"
    await session.commit()
    try:
        response = await client.request("results.create", body, **kwargs)
    except httpx.TimeoutException:
        response = await client.request(
            "results.read",
            {"result_public_id": result.result_public_id},
            **kwargs,
        )
    if response.status_code not in {200, 201, 202}:
        raise OdooTelephonyResultError("Odoo result callback failed")
    accepted = response.json()
    if accepted.get("result_public_id") != result.result_public_id:
        raise OdooTelephonyResultError("Odoo result callback binding mismatch")
    readbacks = {}
    for operation_name, payload in (
        ("results.read", {"result_public_id": result.result_public_id}),
        (
            "telephony.projections.read",
            {"agent_public_id": command.aggregate_public_id},
        ),
        (
            "telephony.mappings.read",
            {"target_public_id": result.target_public_id},
        ),
        ("traces.read", {"correlation_id": result.correlation_id}),
    ):
        readback = await client.request(operation_name, payload, **kwargs)
        if readback.status_code != 200:
            raise OdooTelephonyResultError(f"Odoo {operation_name} readback failed")
        readbacks[operation_name] = readback.json()
    projection = readbacks["telephony.projections.read"]
    mapping = readbacks["telephony.mappings.read"]
    drift_public_id = projection.get("reconciliation_drift_public_id")
    if drift_public_id:
        drift = await client.request(
            "reconciliation.drifts.read",
            {"drift_public_id": drift_public_id},
            **kwargs,
        )
        if drift.status_code != 200:
            raise OdooTelephonyResultError("Odoo reconciliation drift readback failed")
        readbacks["reconciliation.drifts.read"] = drift.json()
    if (
        projection.get("observed_state_version") != result.observed_state_version
        or projection.get("observed_state_hash")
        not in {result.readback_hash, f"sha256:{result.readback_hash}"}
        or mapping.get("target_public_id") != result.target_public_id
    ):
        result.odoo_callback_status = "RECONCILIATION_REQUIRED"
        operation.state = "READBACK_MISMATCH"
        command.state = "RECONCILIATION_REQUIRED"
        await session.commit()
        raise OdooTelephonyResultError("Odoo projection readback mismatch")
    result.odoo_callback_status = "DELIVERED"
    operation.state = "SUCCEEDED"
    command.state = "RECONCILED"
    await session.commit()
    return readbacks
