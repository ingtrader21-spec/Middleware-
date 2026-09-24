from __future__ import annotations

import os
from typing import Any

import pytest
from temporalio import activity
from temporalio.client import WorkflowHandle
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from app.temporal_workflows import (
    ActivityResult,
    CommandExecutionRequest,
    CommandExecutionWorkflow,
    CommandTransitionRequest,
    DeadLetterApproval,
    DeadLetterRecoveryRequest,
    DeadLetterRecoveryWorkflow,
    DeadLetterReplayRequest,
    DelayedCallbackRequest,
    DelayedCallbackWorkflow,
    ProvisioningRequest,
    ProvisioningStepRequest,
    ProvisioningWorkflow,
    ReconciliationRequest,
    ReconciliationWorkflow,
    WORKFLOWS,
)


RUN = os.getenv("TEMPORAL_INTEGRATION_TESTS") == "1"
TASK_QUEUE = "codestra-test-critical"

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set TEMPORAL_INTEGRATION_TESTS=1 for the Temporal test server",
)


class DeterministicActivities:
    def __init__(self) -> None:
        self.reconciliation_attempts_by_operation: dict[str, int] = {}
        self.reconciliation_requests: list[str] = []
        self.callbacks: list[str] = []
        self.provisioned: list[str] = []
        self.compensations: list[str] = []
        self.replays: list[str] = []
        self.command_transitions: list[str] = []
        self.readback_status = "matched"
        self.execute_attempts = 0
        self.readback_attempts = 0
        self.execute_outcome_unknown = False
        self.execute_status = "accepted"
        self.execute_provider_operation_id = "provider-op-1"
        self.readback_evidence: dict[str, Any] | None = None

    @activity.defn(name="reconcile_operation")
    async def reconcile_operation(
        self,
        request: ReconciliationRequest,
    ) -> ActivityResult:
        attempts = self.reconciliation_attempts_by_operation.get(
            request.operation_id,
            0,
        ) + 1
        self.reconciliation_attempts_by_operation[request.operation_id] = attempts
        self.reconciliation_requests.append(request.operation_id)
        if attempts < 3:
            raise ApplicationError("transient read-back failure")
        return ActivityResult("completed", "provider read-back matched")

    @activity.defn(name="dispatch_delayed_callback")
    async def dispatch_delayed_callback(
        self,
        request: DelayedCallbackRequest,
    ) -> ActivityResult:
        self.callbacks.append(request.callback_id)
        return ActivityResult("completed", "callback dispatched")

    @activity.defn(name="provision_identity")
    async def provision_identity(
        self,
        request: ProvisioningStepRequest,
    ) -> ActivityResult:
        self.provisioned.append("identity")
        return ActivityResult("completed", "identity provisioned")

    @activity.defn(name="provision_product")
    async def provision_product(
        self,
        request: ProvisioningStepRequest,
    ) -> ActivityResult:
        assert request.product is not None
        if request.product == "email":
            raise ApplicationError("email provisioning rejected", non_retryable=True)
        self.provisioned.append(request.product)
        return ActivityResult("completed", f"{request.product} provisioned")

    @activity.defn(name="verify_provisioning")
    async def verify_provisioning(
        self,
        request: ProvisioningStepRequest,
    ) -> ActivityResult:
        return ActivityResult("completed", "provisioning read-back matched")

    @activity.defn(name="compensate_provisioning")
    async def compensate_provisioning(
        self,
        request: ProvisioningStepRequest,
    ) -> ActivityResult:
        self.compensations.append(request.product or "identity")
        return ActivityResult("completed", "provisioning compensated")

    @activity.defn(name="replay_dead_letter")
    async def replay_dead_letter(
        self,
        value: DeadLetterReplayRequest,
    ) -> ActivityResult:
        self.replays.append(value.dead_letter_id)
        return ActivityResult(
            "completed",
            f"approved by {value.operator_id}",
        )

    @activity.defn(name="record_command_transition")
    async def record_command_transition(
        self,
        request: CommandTransitionRequest,
    ) -> ActivityResult:
        self.command_transitions.append(request.new_state)
        return ActivityResult(
            request.new_state,
            request.reason,
            request.provider_operation_id,
        )

    @activity.defn(name="execute_command")
    async def execute_command(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        self.execute_attempts += 1
        if self.execute_outcome_unknown:
            raise ApplicationError(
                "provider timed out after possible acceptance",
                non_retryable=True,
                type="UncertainProviderOutcome",
            )
        return ActivityResult(
            self.execute_status, "provider result",
            self.execute_provider_operation_id,
        )

    @activity.defn(name="readback_command")
    async def readback_command(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        self.readback_attempts += 1
        return ActivityResult(
            self.readback_status, "provider state observed",
            self.execute_provider_operation_id, self.readback_evidence,
        )

    def registered(self) -> list[Any]:
        return [
            self.reconcile_operation,
            self.dispatch_delayed_callback,
            self.provision_identity,
            self.provision_product,
            self.verify_provisioning,
            self.compensate_provisioning,
            self.replay_dead_letter,
            self.record_command_transition,
            self.execute_command,
            self.readback_command,
        ]


@pytest.mark.asyncio
async def test_critical_workflows_retry_wait_compensate_and_require_approval() -> None:
    activities = DeterministicActivities()
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=list(WORKFLOWS),
            activities=activities.registered(),
        ):
            reconciliation = await environment.client.execute_workflow(
                ReconciliationWorkflow.run,
                ReconciliationRequest("op-reconcile", "tenant-test", "read-back"),
                id="test-reconciliation",
                task_queue=TASK_QUEUE,
            )
            assert reconciliation.status == "completed"
            assert activities.reconciliation_attempts_by_operation["op-reconcile"] == 3

            callback = await environment.client.execute_workflow(
                DelayedCallbackWorkflow.run,
                DelayedCallbackRequest(
                    "op-callback",
                    "tenant-test",
                    "callback-1",
                    86_400,
                ),
                id="test-delayed-callback",
                task_queue=TASK_QUEUE,
            )
            assert callback.status == "completed"
            assert activities.callbacks == ["callback-1"]

            provisioning = await environment.client.execute_workflow(
                ProvisioningWorkflow.run,
                ProvisioningRequest(
                    "op-provision",
                    "tenant-test",
                    "principal-1",
                    ("identity-profile", "email"),
                ),
                id="test-provisioning",
                task_queue=TASK_QUEUE,
            )
            assert provisioning.status == "failed_compensated"
            assert activities.provisioned == ["identity", "identity-profile"]
            assert activities.compensations == ["identity-profile"]

            recovery: WorkflowHandle = await environment.client.start_workflow(
                DeadLetterRecoveryWorkflow.run,
                DeadLetterRecoveryRequest(
                    "op-recovery",
                    "tenant-test",
                    "dead-letter-1",
                ),
                id="test-dead-letter-recovery",
                task_queue=TASK_QUEUE,
            )
            assert await recovery.query(
                DeadLetterRecoveryWorkflow.approval_status
            ) == "awaiting_approval"
            await recovery.signal(
                DeadLetterRecoveryWorkflow.approve,
                DeadLetterApproval(
                    operator_id="operator-1",
                    reason="verified provider outage is resolved",
                    approved=True,
                ),
            )
            recovered = await recovery.result()
            assert recovered.status == "completed"
            assert activities.replays == ["dead-letter-1"]

            command_request = CommandExecutionRequest(
                command_id="00000000-0000-4000-8000-000000000001",
                command_type="crm.contact.create.v1",
                command_version="1.0",
                target="odoo-19",
                tenant_id="tenant-test",
                requested_by="user-1",
                correlation_id="correlation-1",
                idempotency_key="idempotency-1",
                capability="ODOO_WRITE",
                payload={"contact_id": "contact-1"},
                authenticated_client_id="test-client",
            )
            command = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                command_request,
                id="test-command-execution",
                task_queue=TASK_QUEUE,
            )
            assert command.status == "completed"
            assert activities.command_transitions == [
                "queued",
                "dispatching",
                "accepted",
                "readback_pending",
                "completed",
            ]

            for action in ("originate", "hangup"):
                activities.command_transitions.clear()
                activities.execute_status = "dispatch_unknown"
                readbacks_before = activities.readback_attempts
                dispatch_unknown = await environment.client.execute_workflow(
                    CommandExecutionWorkflow.run,
                    CommandExecutionRequest(
                        command_id="00000000-0000-4000-8000-000000000099",
                        command_type=f"telephony-internal.calls.{action}",
                        command_version="1.0",
                        target="vicidial-restricted",
                        tenant_id="tenant-test",
                        requested_by="subject-appolon",
                        correlation_id="calling-correlation-unknown",
                        idempotency_key="calling-idempotency-unknown",
                        capability="INTERNAL_TELEPHONY_CALLS",
                        payload={},
                        authenticated_client_id="odoo-integration",
                    ),
                    id=f"test-calling-{action}-dispatch-unknown",
                    task_queue=TASK_QUEUE,
                )
                assert dispatch_unknown.status == "reconciliation_required"
                assert activities.command_transitions == [
                    "queued", "dispatching", "reconciliation_required",
                ]
                assert activities.readback_attempts == readbacks_before
            activities.execute_status = "accepted"

            activities.command_transitions.clear()
            activities.readback_status = "matched"
            activities.execute_provider_operation_id = "accepted-asterisk-id"
            activities.readback_evidence = {
                "operation_id": "00000000-0000-4000-8000-000000000098",
                "correlation_id": "calling-correlation-provider-mismatch",
                "dispatch_state": "accepted",
                "asterisk_uniqueid": "different-asterisk-id",
                "linkedid": "different-asterisk-id", "call_id": "call-98",
                "call_state": "completed", "answered_at": "2026-09-05T20:00:02Z",
                "ended_at": "2026-09-05T20:00:07Z", "terminal": True,
                "evidence": {"sequence": 3}, "tenant_id": "tenant-test",
                "subject": "subject-appolon", "employee_id": "employee-appolon",
                "username": "appolon", "extension": "6901", "campaign": "TEST_SYN",
                "authorization_reference": "AUTH-TEST-1",
                "created_at": "2026-09-05T20:00:00Z", "duration_seconds": 7,
                "talk_duration_seconds": 5, "hangup_cause": "normal",
                "hangup_cause_code": 16, "internal_only": True,
                "external_dialing": False, "recording": False,
            }
            provider_mismatch = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                CommandExecutionRequest(
                    command_id="00000000-0000-4000-8000-000000000098",
                    command_type="telephony-internal.calls.originate",
                    command_version="1.0", target="vicidial-restricted",
                    tenant_id="tenant-test", requested_by="subject-appolon",
                    correlation_id="calling-correlation-provider-mismatch",
                    idempotency_key="calling-idempotency-provider-mismatch",
                    capability="INTERNAL_TELEPHONY_CALLS",
                    payload={
                        "actor": {"subject": "subject-appolon",
                                  "employee_id": "employee-appolon",
                                  "extension": "6901", "campaign_id": "TEST_SYN"},
                        "authorization_reference": "AUTH-TEST-1",
                    },
                    authenticated_client_id="odoo-integration",
                ),
                id="test-calling-provider-identity-mismatch",
                task_queue=TASK_QUEUE,
            )
            assert provider_mismatch.status == "reconciliation_required"
            assert activities.command_transitions[-1] == "reconciliation_required"
            assert "completed" not in activities.command_transitions
            activities.execute_provider_operation_id = "provider-op-1"
            activities.readback_evidence = None

            activities.command_transitions.clear()
            activities.readback_status = "mismatch"
            mismatch = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                command_request,
                id="test-command-readback-mismatch",
                task_queue=TASK_QUEUE,
            )
            assert mismatch.status == "reconciliation_required"
            assert activities.command_transitions[-1] == "reconciliation_required"
            assert "completed" not in activities.command_transitions

            activities.command_transitions.clear()
            activities.execute_outcome_unknown = True
            execute_attempts_before = activities.execute_attempts
            readback_attempts_before = activities.readback_attempts
            email_command_id = "00000000-0000-4000-8000-000000000002"
            uncertain_email = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                CommandExecutionRequest(
                    command_id=email_command_id,
                    command_type="email.message.send.v1",
                    command_version="1.0",
                    target="klyrow-email",
                    tenant_id="tenant-test",
                    requested_by="user-1",
                    correlation_id="email-correlation-1",
                    idempotency_key="email-idempotency-1",
                    capability="EMAIL_DELIVERY",
                    payload={"message_id": "message-1"},
                    authenticated_client_id="test-client",
                ),
                id="test-email-command-unknown-outcome",
                task_queue=TASK_QUEUE,
            )
            assert uncertain_email.status == "reconciliation_required"
            assert activities.command_transitions == [
                "queued",
                "dispatching",
                "reconciliation_required",
            ]
            assert activities.execute_attempts == execute_attempts_before + 1
            assert activities.readback_attempts == readback_attempts_before

            provider_execution_attempts = activities.execute_attempts
            reconciled_email = await environment.client.execute_workflow(
                ReconciliationWorkflow.run,
                ReconciliationRequest(
                    email_command_id,
                    "tenant-test",
                    "provider timeout after possible acceptance",
                ),
                id="test-email-command-unknown-outcome-reconciliation",
                task_queue=TASK_QUEUE,
            )
            assert reconciled_email.status == "completed"
            assert reconciled_email.detail == "provider read-back matched"
            assert (
                activities.reconciliation_attempts_by_operation[email_command_id]
                == 3
            )
            assert activities.reconciliation_requests.count(email_command_id) == 3
            assert activities.execute_attempts == provider_execution_attempts
            assert activities.readback_attempts == readback_attempts_before


            activities.command_transitions.clear()
            execute_attempts_before = activities.execute_attempts
            readback_attempts_before = activities.readback_attempts
            uncertain_sms = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                CommandExecutionRequest(
                    command_id="00000000-0000-4000-8000-000000000003",
                    command_type="sms.message.submit.v1",
                    command_version="1.0",
                    target="telnexa-sms",
                    tenant_id="tenant-test",
                    requested_by="user-1",
                    correlation_id="sms-correlation-1",
                    idempotency_key="test-sms-2",
                    capability="SMS_DELIVERY",
                    payload={"message_id": "message-2"},
                    authenticated_client_id="test-client",
                ),
                id="test-sms-command-unknown-outcome",
                task_queue=TASK_QUEUE,
            )
            assert uncertain_sms.status == "reconciliation_required"
            assert activities.command_transitions == [
                "queued",
                "dispatching",
                "reconciliation_required",
            ]
            assert activities.execute_attempts == execute_attempts_before + 1
            assert activities.readback_attempts == readback_attempts_before
