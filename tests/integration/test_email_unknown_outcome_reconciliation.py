from __future__ import annotations

import os
from typing import Any

import pytest
from temporalio import activity
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from app.temporal_workflows import (
    ActivityResult,
    CommandExecutionRequest,
    CommandExecutionWorkflow,
    CommandTransitionRequest,
    ReconciliationRequest,
    ReconciliationWorkflow,
)


RUN = os.getenv("TEMPORAL_INTEGRATION_TESTS") == "1"
TASK_QUEUE = "codestra-test-email-reconciliation"

pytestmark = pytest.mark.skipif(
    not RUN,
    reason="set TEMPORAL_INTEGRATION_TESTS=1 for the Temporal test server",
)


class EmailReconciliationActivities:
    def __init__(self) -> None:
        self.transitions: list[str] = []
        self.execute_attempts = 0
        self.command_readback_attempts = 0
        self.reconciliation_readback_attempts = 0

    @activity.defn(name="record_command_transition")
    async def record_command_transition(
        self,
        request: CommandTransitionRequest,
    ) -> ActivityResult:
        self.transitions.append(request.new_state)
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
        raise ApplicationError(
            "provider timed out after possible acceptance",
            non_retryable=True,
            type="UncertainProviderOutcome",
        )

    @activity.defn(name="readback_command")
    async def readback_command(
        self,
        request: CommandExecutionRequest,
    ) -> ActivityResult:
        self.command_readback_attempts += 1
        return ActivityResult("matched", "provider command state observed")

    @activity.defn(name="reconcile_operation")
    async def reconcile_operation(
        self,
        request: ReconciliationRequest,
    ) -> ActivityResult:
        self.reconciliation_readback_attempts += 1
        if self.reconciliation_readback_attempts < 3:
            raise ApplicationError("transient provider read-back failure")
        return ActivityResult("completed", "provider read-back matched")

    def registered(self) -> list[Any]:
        return [
            self.record_command_transition,
            self.execute_command,
            self.readback_command,
            self.reconcile_operation,
        ]


@pytest.mark.asyncio
async def test_email_unknown_outcome_reconciles_without_resubmission() -> None:
    activities = EmailReconciliationActivities()
    email_command_id = "00000000-0000-4000-8000-000000000102"

    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=TASK_QUEUE,
            workflows=[CommandExecutionWorkflow, ReconciliationWorkflow],
            activities=activities.registered(),
        ):
            uncertain = await environment.client.execute_workflow(
                CommandExecutionWorkflow.run,
                CommandExecutionRequest(
                    command_id=email_command_id,
                    command_type="email.message.send.v1",
                    command_version="1.0",
                    target="klyrow-email",
                    tenant_id="tenant-test",
                    requested_by="user-1",
                    correlation_id="email-correlation-final",
                    idempotency_key="email-idempotency-final",
                    capability="EMAIL_DELIVERY",
                    payload={"message_id": "message-final"},
                    authenticated_client_id="test-client",
                ),
                id="test-final-email-command-unknown-outcome",
                task_queue=TASK_QUEUE,
            )

            assert uncertain.status == "reconciliation_required"
            assert activities.transitions == [
                "queued",
                "dispatching",
                "reconciliation_required",
            ]
            assert activities.execute_attempts == 1
            assert activities.command_readback_attempts == 0

            provider_execution_attempts = activities.execute_attempts
            reconciled = await environment.client.execute_workflow(
                ReconciliationWorkflow.run,
                ReconciliationRequest(
                    email_command_id,
                    "tenant-test",
                    "provider timeout after possible acceptance",
                ),
                id="test-final-email-command-reconciliation",
                task_queue=TASK_QUEUE,
            )

            assert reconciled.status == "completed"
            assert reconciled.detail == "provider read-back matched"
            assert activities.reconciliation_readback_attempts == 3
            assert activities.execute_attempts == provider_execution_attempts
            assert activities.command_readback_attempts == 0
