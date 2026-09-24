from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

from .provider_canary import (
    TARGET_CHANNELS,
    validate_provider_canary_evidence,
)
from .calling_contract import (
    HANGUP, ORIGINATE, TARGET, validate_call_evidence,
    validate_terminal_call_evidence,
)


@dataclass(frozen=True)
class ActivityResult:
    status: str
    detail: str
    provider_operation_id: str | None = None
    readback_evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class WorkflowOutcome:
    operation_id: str
    workflow_type: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReconciliationRequest:
    operation_id: str
    tenant_id: str
    reason: str


@dataclass(frozen=True)
class DelayedCallbackRequest:
    operation_id: str
    tenant_id: str
    callback_id: str
    delay_seconds: int


@dataclass(frozen=True)
class ProvisioningRequest:
    operation_id: str
    tenant_id: str
    principal_id: str
    products: tuple[str, ...]


@dataclass(frozen=True)
class ProvisioningStepRequest:
    operation_id: str
    tenant_id: str
    principal_id: str
    product: str | None = None


@dataclass(frozen=True)
class DeadLetterRecoveryRequest:
    operation_id: str
    tenant_id: str
    dead_letter_id: str


@dataclass(frozen=True)
class DeadLetterApproval:
    operator_id: str
    reason: str
    approved: bool


@dataclass(frozen=True)
class DeadLetterReplayRequest:
    operation_id: str
    tenant_id: str
    dead_letter_id: str
    operator_id: str
    approval_reason: str


@dataclass(frozen=True)
class CommandExecutionRequest:
    command_id: str
    command_type: str
    command_version: str
    target: str
    tenant_id: str
    requested_by: str
    correlation_id: str
    idempotency_key: str
    capability: str
    payload: dict[str, Any]
    authenticated_client_id: str = ""
    resume_from_queued: bool = False


@dataclass(frozen=True)
class CommandTransitionRequest:
    command_id: str
    tenant_id: str
    new_state: str
    actor_id: str
    reason: str
    provider_operation_id: str | None = None
    readback_evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class OriginalCallCompletionRequest:
    hangup_command_id: str
    tenant_id: str
    readback_evidence: dict[str, Any]


ACTIVITY_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=5,
)


def _require_identity(value: str, label: str) -> None:
    if not value or len(value) > 180:
        raise ApplicationError(
            f"{label} must contain 1-180 characters",
            non_retryable=True,
        )


async def _activity(name: str, request: object) -> ActivityResult:
    return await workflow.execute_activity(
        name,
        request,
        result_type=ActivityResult,
        start_to_close_timeout=timedelta(seconds=30),
        retry_policy=ACTIVITY_RETRY_POLICY,
    )


async def _command_transition(request: CommandTransitionRequest) -> ActivityResult:
    return await workflow.execute_activity(
        "record_command_transition",
        request,
        result_type=ActivityResult,
        start_to_close_timeout=timedelta(seconds=15),
        retry_policy=ACTIVITY_RETRY_POLICY,
    )


@workflow.defn(name="codestra.reconciliation.v1")
class ReconciliationWorkflow:
    @workflow.run
    async def run(self, request: ReconciliationRequest) -> WorkflowOutcome:
        _require_identity(request.operation_id, "operation_id")
        _require_identity(request.tenant_id, "tenant_id")
        result = await _activity("reconcile_operation", request)
        return WorkflowOutcome(
            operation_id=request.operation_id,
            workflow_type="reconciliation",
            status=result.status,
            detail=result.detail,
        )


@workflow.defn(name="codestra.delayed-callback.v1")
class DelayedCallbackWorkflow:
    @workflow.run
    async def run(self, request: DelayedCallbackRequest) -> WorkflowOutcome:
        _require_identity(request.operation_id, "operation_id")
        _require_identity(request.tenant_id, "tenant_id")
        _require_identity(request.callback_id, "callback_id")
        if request.delay_seconds < 0 or request.delay_seconds > 2_592_000:
            raise ApplicationError(
                "delay_seconds must be between 0 and 2592000",
                non_retryable=True,
            )
        await workflow.sleep(timedelta(seconds=request.delay_seconds))
        result = await _activity("dispatch_delayed_callback", request)
        return WorkflowOutcome(
            operation_id=request.operation_id,
            workflow_type="delayed_callback",
            status=result.status,
            detail=result.detail,
        )


@workflow.defn(name="codestra.provisioning.v1")
class ProvisioningWorkflow:
    @workflow.run
    async def run(self, request: ProvisioningRequest) -> WorkflowOutcome:
        _require_identity(request.operation_id, "operation_id")
        _require_identity(request.tenant_id, "tenant_id")
        _require_identity(request.principal_id, "principal_id")
        if not request.products or len(request.products) > 32:
            raise ApplicationError(
                "products must contain 1-32 entries",
                non_retryable=True,
            )

        base = ProvisioningStepRequest(
            operation_id=request.operation_id,
            tenant_id=request.tenant_id,
            principal_id=request.principal_id,
        )
        completed_products: list[str] = []
        try:
            await _activity("provision_identity", base)
            for product in request.products:
                _require_identity(product, "product")
                await _activity(
                    "provision_product",
                    ProvisioningStepRequest(
                        operation_id=request.operation_id,
                        tenant_id=request.tenant_id,
                        principal_id=request.principal_id,
                        product=product,
                    ),
                )
                completed_products.append(product)
            result = await _activity("verify_provisioning", base)
        except ActivityError as exc:
            await _activity(
                "compensate_provisioning",
                ProvisioningStepRequest(
                    operation_id=request.operation_id,
                    tenant_id=request.tenant_id,
                    principal_id=request.principal_id,
                    product=",".join(completed_products) or None,
                ),
            )
            return WorkflowOutcome(
                operation_id=request.operation_id,
                workflow_type="provisioning",
                status="failed_compensated",
                detail=str(exc),
            )

        return WorkflowOutcome(
            operation_id=request.operation_id,
            workflow_type="provisioning",
            status=result.status,
            detail=result.detail,
        )


@workflow.defn(name="codestra.dead-letter-recovery.v1")
class DeadLetterRecoveryWorkflow:
    def __init__(self) -> None:
        self._approval: DeadLetterApproval | None = None

    @workflow.signal
    def approve(self, approval: DeadLetterApproval) -> None:
        _require_identity(approval.operator_id, "operator_id")
        _require_identity(approval.reason, "reason")
        self._approval = approval

    @workflow.query
    def approval_status(self) -> str:
        if self._approval is None:
            return "awaiting_approval"
        return "approved" if self._approval.approved else "denied"

    @workflow.run
    async def run(self, request: DeadLetterRecoveryRequest) -> WorkflowOutcome:
        _require_identity(request.operation_id, "operation_id")
        _require_identity(request.tenant_id, "tenant_id")
        _require_identity(request.dead_letter_id, "dead_letter_id")
        await workflow.wait_condition(lambda: self._approval is not None)
        approval = self._approval
        if approval is None or not approval.approved:
            return WorkflowOutcome(
                operation_id=request.operation_id,
                workflow_type="dead_letter_recovery",
                status="denied",
                detail="operator denied replay",
            )
        result = await _activity(
            "replay_dead_letter",
            DeadLetterReplayRequest(
                operation_id=request.operation_id,
                tenant_id=request.tenant_id,
                dead_letter_id=request.dead_letter_id,
                operator_id=approval.operator_id,
                approval_reason=approval.reason,
            ),
        )
        return WorkflowOutcome(
            operation_id=request.operation_id,
            workflow_type="dead_letter_recovery",
            status=result.status,
            detail=result.detail,
        )


@workflow.defn(name="codestra.command-execution.v1")
class CommandExecutionWorkflow:
    @workflow.run
    async def run(self, request: CommandExecutionRequest) -> WorkflowOutcome:
        _require_identity(request.command_id, "command_id")
        _require_identity(request.tenant_id, "tenant_id")
        actor = "temporal:codestra.command-execution.v1"
        if not request.resume_from_queued:
            await _command_transition(
                CommandTransitionRequest(
                    request.command_id,
                    request.tenant_id,
                    "queued",
                    actor,
                    "Temporal workflow accepted durable command intent",
                )
            )
        await _command_transition(
            CommandTransitionRequest(
                request.command_id,
                request.tenant_id,
                "dispatching",
                actor,
                "reserved command for one adapter execution attempt",
            )
        )
        try:
            executed = await workflow.execute_activity(
                "execute_command",
                request,
                result_type=ActivityResult,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=1),
            )
        except ActivityError as exc:
            if request.target == TARGET and request.command_type == ORIGINATE:
                recovered = await _activity("recover_call_execution", request)
                if recovered.status == "cancelled":
                    return WorkflowOutcome(
                        request.command_id, "command_execution", "cancelled",
                        "committed no-send cancellation recovered after activity failure",
                    )
            await _command_transition(
                CommandTransitionRequest(
                    request.command_id,
                    request.tenant_id,
                    "reconciliation_required",
                    actor,
                    f"adapter outcome is unknown and requires read-back: {exc}",
                )
            )
            return WorkflowOutcome(
                operation_id=request.command_id,
                workflow_type="command_execution",
                status="reconciliation_required",
                detail="adapter execution did not produce a confirmed outcome",
            )

        if (request.target == TARGET and request.command_type == ORIGINATE
                and executed.status == "cancelled"):
            return WorkflowOutcome(
                operation_id=request.command_id,
                workflow_type="command_execution",
                status=executed.status,
                detail=executed.detail,
            )

        if (request.target == TARGET and request.command_type in {ORIGINATE, HANGUP}
                and executed.status == "dispatch_unknown"):
            await _command_transition(
                CommandTransitionRequest(
                    request.command_id,
                    request.tenant_id,
                    "reconciliation_required",
                    actor,
                    "calling dispatch outcome is unknown; reconcile without redispatch",
                    executed.provider_operation_id,
                )
            )
            return WorkflowOutcome(
                operation_id=request.command_id,
                workflow_type="command_execution",
                status="reconciliation_required",
                detail="calling dispatch outcome requires authoritative read-back",
            )

        await _command_transition(
            CommandTransitionRequest(
                request.command_id,
                request.tenant_id,
                "accepted",
                actor,
                "adapter accepted the idempotent command",
                executed.provider_operation_id,
            )
        )
        await _command_transition(
            CommandTransitionRequest(
                request.command_id,
                request.tenant_id,
                "readback_pending",
                actor,
                "provider read-back required before completion",
                executed.provider_operation_id,
            )
        )
        try:
            readback = await _activity("readback_command", request)
        except ActivityError as exc:
            await _command_transition(
                CommandTransitionRequest(
                    request.command_id,
                    request.tenant_id,
                    "reconciliation_required",
                    actor,
                    f"provider read-back did not confirm the outcome: {exc}",
                    executed.provider_operation_id,
                )
            )
            return WorkflowOutcome(
                operation_id=request.command_id,
                workflow_type="command_execution",
                status="reconciliation_required",
                detail="provider read-back failed",
            )
        calling_observation = None
        if (request.target == TARGET and request.command_type in {ORIGINATE, HANGUP}
                and readback.status != "matched"):
            try:
                original = (request.command_id if request.command_type == ORIGINATE
                            else str(request.payload["origin_operation_id"]))
                calling_observation = validate_call_evidence(
                    readback.readback_evidence, operation_id=original,
                    correlation_id=request.correlation_id, tenant_id=request.tenant_id,
                    actor=request.payload["actor"],
                    authorization_reference=request.payload["authorization_reference"],
                    provider_operation_id=executed.provider_operation_id,
                    require_terminal=False,
                )
            except (KeyError, TypeError, ValueError):
                calling_observation = None
        if readback.status != "matched":
            await _command_transition(
                CommandTransitionRequest(
                    request.command_id,
                    request.tenant_id,
                    "reconciliation_required",
                    actor,
                    "provider read-back did not match durable command intent",
                    executed.provider_operation_id,
                    calling_observation,
                )
            )
            return WorkflowOutcome(
                operation_id=request.command_id,
                workflow_type="command_execution",
                status="reconciliation_required",
                detail=readback.detail,
            )

        canary = request.payload.get("canary")
        if request.target == TARGET and request.command_type in {ORIGINATE, HANGUP}:
            try:
                original_operation_id = (
                    request.command_id if request.command_type == ORIGINATE
                    else str(request.payload["origin_operation_id"])
                )
                readback_evidence = validate_terminal_call_evidence(
                    readback.readback_evidence,
                    operation_id=original_operation_id,
                    correlation_id=request.correlation_id,
                    tenant_id=request.tenant_id,
                    actor=request.payload["actor"],
                    authorization_reference=request.payload["authorization_reference"],
                    provider_operation_id=executed.provider_operation_id,
                )
            except (KeyError, TypeError, ValueError) as exc:
                await _command_transition(CommandTransitionRequest(
                    request.command_id, request.tenant_id, "reconciliation_required",
                    actor, f"terminal calling evidence was missing or invalid: {exc}",
                    executed.provider_operation_id,
                ))
                return WorkflowOutcome(
                    request.command_id, "command_execution", "reconciliation_required",
                    "terminal calling evidence did not satisfy the bounded contract",
                )
            if request.command_type == HANGUP:
                await _activity(
                    "complete_originating_call",
                    OriginalCallCompletionRequest(
                        request.command_id, request.tenant_id, readback_evidence,
                    ),
                )
        elif request.target in TARGET_CHANNELS and isinstance(canary, dict):
            try:
                if canary.get("schema_version") != "1.0":
                    raise ValueError("canary schema_version must be 1.0")
                destination_fingerprint = str(canary["destination_fingerprint"])
                payload_fingerprint = str(canary["payload_fingerprint"])
                validated = validate_provider_canary_evidence(
                    readback.readback_evidence,
                    target=request.target,
                    destination_fingerprint=destination_fingerprint,
                    payload_fingerprint=payload_fingerprint,
                    require_success=True,
                )
                readback_evidence = validated.model_dump(mode="json")
            except (KeyError, TypeError, ValueError) as exc:
                await _command_transition(
                    CommandTransitionRequest(
                        request.command_id,
                        request.tenant_id,
                        "reconciliation_required",
                        actor,
                        "provider canary read-back evidence was missing or invalid: "
                        f"{exc}",
                        executed.provider_operation_id,
                    )
                )
                return WorkflowOutcome(
                    operation_id=request.command_id,
                    workflow_type="command_execution",
                    status="reconciliation_required",
                    detail="provider canary evidence did not satisfy the channel contract",
                )
        else:
            # Only the locked provider-canary contract is safe to persist here.
            # Other adapter results may contain provider payload fields that have
            # not passed the redaction and shape checks above.
            readback_evidence = None

        await _command_transition(
            CommandTransitionRequest(
                request.command_id,
                request.tenant_id,
                "completed",
                actor,
                "provider read-back matched durable command intent",
                executed.provider_operation_id,
                readback_evidence,
            )
        )
        return WorkflowOutcome(
            operation_id=request.command_id,
            workflow_type="command_execution",
            status="completed",
            detail=readback.detail,
        )


WORKFLOWS = (
    ReconciliationWorkflow,
    DelayedCallbackWorkflow,
    ProvisioningWorkflow,
    DeadLetterRecoveryWorkflow,
    CommandExecutionWorkflow,
)
