from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from temporalio.client import Client
from temporalio.common import WorkflowIDConflictPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from .commands import (
    AUTHENTICATED_CLIENT_ID_KEY,
    CommandEnvelope,
    TEMPORAL_COMMAND_DESTINATION,
)
from .storage import OutboxRecord
from .temporal_workflows import (
    CommandExecutionRequest,
    CommandExecutionWorkflow,
    ReconciliationRequest,
    ReconciliationWorkflow,
)


RECONCILIATION_EVENT_TYPE = "operation.reconcile.v1"
ReconciliationCommandIdentityLookup = Callable[
    [OutboxRecord],
    Awaitable[str | None],
]


class TemporalTransportError(RuntimeError):
    """Raised before workflow start when durable intent violates its contract."""


def command_workflow_id(tenant_id: str, command_id: str, idempotency_key: str) -> str:
    identity = hashlib.sha256(
        f"{tenant_id}\0{command_id}\0{idempotency_key}".encode("utf-8")
    ).hexdigest()
    return f"codestra-command-{identity}"


def reconciliation_workflow_id(
    tenant_id: str,
    operation_id: str,
    idempotency_key: str,
) -> str:
    identity = hashlib.sha256(
        f"{tenant_id}\0{operation_id}\0{idempotency_key}".encode("utf-8")
    ).hexdigest()
    return f"codestra-reconciliation-{identity}"


@dataclass(slots=True)
class TemporalCommandDispatcher:
    client: Client
    task_queue: str
    reconciliation_command_id_lookup: ReconciliationCommandIdentityLookup | None = None

    async def _start_reconciliation(self, record: OutboxRecord) -> None:
        payload = dict(record.payload)
        if set(payload) != {"command_id", "action", "reason"}:
            raise TemporalTransportError(
                "reconciliation outbox payload does not match its versioned contract"
            )
        operation_id = payload.get("command_id")
        action = payload.get("action")
        reason = payload.get("reason")
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or len(operation_id) > 180
        ):
            raise TemporalTransportError(
                "reconciliation outbox payload has an invalid operation identity"
            )
        if action != "reconcile":
            raise TemporalTransportError(
                "reconciliation outbox payload has an unsupported action"
            )
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise TemporalTransportError(
                "reconciliation outbox payload has an invalid safe reason"
            )
        if not record.idempotency_key.startswith("operation-reconcile:"):
            raise TemporalTransportError(
                "reconciliation outbox payload has an invalid idempotency identity"
            )
        if self.reconciliation_command_id_lookup is None:
            raise TemporalTransportError(
                "reconciliation dispatch is missing durable outbox identity verification"
            )
        try:
            trusted_command_id = await self.reconciliation_command_id_lookup(record)
        except Exception as exc:
            raise TemporalTransportError(
                "reconciliation outbox identity could not be verified"
            ) from exc
        if not isinstance(trusted_command_id, str) or not trusted_command_id:
            raise TemporalTransportError(
                "reconciliation outbox has no durable command identity"
            )
        if operation_id != trusted_command_id:
            raise TemporalTransportError(
                "reconciliation payload identity does not match the durable outbox command"
            )

        request = ReconciliationRequest(
            operation_id=operation_id,
            tenant_id=record.tenant_id,
            reason=reason,
        )
        try:
            await self.client.start_workflow(
                ReconciliationWorkflow.run,
                request,
                id=reconciliation_workflow_id(
                    record.tenant_id,
                    operation_id,
                    record.idempotency_key,
                ),
                task_queue=self.task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            )
        except WorkflowAlreadyStartedError:
            return

    async def dispatch(self, record: OutboxRecord) -> None:
        if record.destination != TEMPORAL_COMMAND_DESTINATION:
            raise TemporalTransportError(
                "outbox row targets an unsupported Temporal destination"
            )
        if record.event_type == RECONCILIATION_EVENT_TYPE:
            await self._start_reconciliation(record)
            return

        durable_payload = dict(record.payload)
        authenticated_client_id = durable_payload.pop(
            AUTHENTICATED_CLIENT_ID_KEY,
            None,
        )
        if not isinstance(authenticated_client_id, str) or not authenticated_client_id:
            raise TemporalTransportError(
                "outbox command is missing authenticated client provenance"
            )
        try:
            command = CommandEnvelope.model_validate(durable_payload)
        except Exception as exc:
            raise TemporalTransportError(
                "outbox command does not match the canonical command envelope"
            ) from exc
        if command.tenant_id != record.tenant_id:
            raise TemporalTransportError(
                "outbox tenant does not match the command envelope"
            )
        if command.command_type != record.event_type:
            raise TemporalTransportError(
                "outbox event type does not match the command type"
            )
        if command.idempotency_key != record.idempotency_key:
            raise TemporalTransportError(
                "outbox idempotency key does not match the command envelope"
            )

        request = CommandExecutionRequest(
            **command.model_dump(mode="json"),
            authenticated_client_id=authenticated_client_id,
            resume_from_queued=command.idempotency_key.startswith("operation-retry:"),
        )
        try:
            await self.client.start_workflow(
                CommandExecutionWorkflow.run,
                request,
                id=command_workflow_id(
                    command.tenant_id,
                    str(command.command_id),
                    command.idempotency_key,
                ),
                task_queue=self.task_queue,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
                id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            )
        except WorkflowAlreadyStartedError:
            # A completed execution with the same deterministic workflow ID proves
            # that this durable intent was already handed to Temporal.
            return
