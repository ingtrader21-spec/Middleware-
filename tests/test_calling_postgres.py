"""Real PostgreSQL atomicity tests. Only an explicit disposable local DB is allowed."""
from __future__ import annotations

import asyncio
import os
import unittest
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import asyncpg

from app.calling_ledger import CallingLedger
from app.commands import (
    AUTHENTICATED_CLIENT_ID_KEY, CommandConflict, CommandNotFound, CommandPolicyRegistry,
    CommandService, PostgresCommandStore,
)
from app.temporal_activities import CommandLedgerWorkflowActivities
from app.vicidial_internal_call_adapter import VicidialInternalCallPreDispatchRejected
from app.temporal_workflows import (
    ActivityResult, CommandExecutionRequest, ReconciliationRequest,
)
from tests.test_calling_contract import grant, originate, principal

DATABASE = os.getenv("CALLING_TEST_DATABASE_URL", "")


@unittest.skipUnless(DATABASE, "disposable calling PostgreSQL URL was not supplied")
class CallingPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        parsed = urlparse(DATABASE)
        self.assertIn(parsed.hostname, {"127.0.0.1", "localhost"})
        self.assertEqual(parsed.path, "/middleware_test_calling")
        self.schema = "calling_test_" + uuid4().hex
        self.admin = await asyncpg.connect(DATABASE)
        await self.admin.execute(f'CREATE SCHEMA "{self.schema}"')
        self.pool = await asyncpg.create_pool(DATABASE, min_size=1, max_size=5,
                                             server_settings={"search_path": self.schema + ",public"})
        try:
            async with self.pool.acquire() as connection:
                for migration in sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")):
                    await connection.execute(migration.read_text())
        except Exception:
            await self.pool.close()
            await self.admin.execute(f'DROP SCHEMA "{self.schema}" CASCADE')
            await self.admin.close()
            raise
        self.store = PostgresCommandStore(self.pool)
        self.commands = CommandService(self.store, CommandPolicyRegistry.load())
        self.ledger = CallingLedger(self.commands)
        self.grant = grant()

    async def asyncTearDown(self):
        await self.pool.close()
        await self.admin.execute(f'DROP SCHEMA "{self.schema}" CASCADE')
        await self.admin.close()

    async def counts(self):
        return tuple([await self.pool.fetchval(f"SELECT count(*) FROM {table}")
                      for table in ["middleware_commands", "middleware_command_audit", "middleware_outbox"]])

    async def reserve(self, body=None, ledger=None):
        return await (ledger or self.ledger).originate(principal(), body or originate(), "test-correlation-0001", self.grant)

    async def execution_request(self, operation):
        import json
        payload = await self.pool.fetchval(
            "SELECT payload FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
            operation.tenant_id, str(operation.command_id),
        )
        payload = json.loads(payload) if isinstance(payload, str) else dict(payload)
        client_id = payload.pop(AUTHENTICATED_CLIENT_ID_KEY)
        return CommandExecutionRequest(**payload, authenticated_client_id=client_id)

    async def test_competing_dispatch_cannot_claim_no_send_before_winner_commits(self):
        operation = await self.reserve()
        for state in ("queued", "dispatching"):
            await self.store.transition(operation.tenant_id, operation.command_id,
                                        new_state=state, actor_id="test", reason="test")
        request = await self.execution_request(operation)
        entered, release = asyncio.Event(), asyncio.Event()

        class Adapter:
            executions = 0
            readbacks = 0
            async def execute(self, request):
                self.executions += 1
                entered.set()
                await release.wait()
                raise VicidialInternalCallPreDispatchRejected("synthetic no-send")
            async def readback(self, request):
                self.readbacks += 1
                return ActivityResult("mismatch", "no conclusive observation")

        adapter = Adapter()
        winner = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
        loser = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
        task = asyncio.create_task(winner.execute_command(request))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            self.assertEqual((await loser.execute_command(request)).status, "mismatch")
            self.assertEqual((await loser.recover_call_execution(request)).status,
                             "reconciliation_required")
        finally:
            release.set()
        self.assertEqual((await task).status, "cancelled")
        for _ in range(3):
            self.assertEqual((await loser.recover_call_execution(request)).status, "cancelled")
        self.assertEqual((adapter.executions, adapter.readbacks), (1, 1))
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE new_state='cancelled'"), 1)
        with self.assertRaises(CommandConflict):
            await self.reserve(originate(idempotency_key="test-no-replenishment"))

    async def temporal_activity_failure(self, committed):
        from temporalio import activity
        from temporalio.exceptions import ApplicationError
        from temporalio.testing import WorkflowEnvironment
        from temporalio.worker import Worker
        from app.temporal_workflows import CommandExecutionWorkflow
        operation = await self.reserve()
        request = await self.execution_request(operation)

        class Adapter:
            executions = 0
            async def execute(self, request):
                self.executions += 1
                raise VicidialInternalCallPreDispatchRejected("synthetic no-send")
            async def readback(self, request):
                raise AssertionError("no extra provider I/O on activity failure recovery")

        class LostAcknowledgement(CommandLedgerWorkflowActivities):
            @activity.defn(name="execute_command")
            async def execute_command(self, request: CommandExecutionRequest) -> ActivityResult:
                if committed:
                    result = await super().execute_command(request)
                    assert result.status == "cancelled"
                # Inject failure before Temporal can record activity completion.
                # The false case has no committed no-send proof and must remain uncertain.
                raise ApplicationError("injected activity acknowledgement failure",
                                       non_retryable=True, type="SyntheticLostAcknowledgement")

        adapter = Adapter()
        activities = LostAcknowledgement(self.store, vicidial_internal=adapter)
        queue = "calling-lost-ack-" + uuid4().hex
        async with await WorkflowEnvironment.start_time_skipping() as environment:
            async with Worker(environment.client, task_queue=queue,
                              workflows=[CommandExecutionWorkflow], activities=activities.registered()):
                result = await environment.client.execute_workflow(
                    CommandExecutionWorkflow.run, request,
                    id="lost-ack-" + uuid4().hex, task_queue=queue,
                )
        expected = "cancelled" if committed else "reconciliation_required"
        self.assertEqual(result.status, expected)
        fresh = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
        for _ in range(3):
            self.assertEqual((await fresh.recover_call_execution(request)).status, expected)
        self.assertEqual(adapter.executions, int(committed))
        self.assertEqual(await self.pool.fetchval(
            "SELECT state FROM middleware_commands WHERE command_id=$1", request.command_id), expected)
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE new_state='cancelled'"), int(committed))
        with self.assertRaises(CommandConflict):
            await self.reserve(originate(idempotency_key="test-no-replenishment"))

    @unittest.skipUnless(os.getenv("TEMPORAL_INTEGRATION_TESTS") == "1", "Temporal harness not enabled")
    async def test_temporal_recovers_post_commit_activity_failure(self):
        await self.temporal_activity_failure(True)

    @unittest.skipUnless(os.getenv("TEMPORAL_INTEGRATION_TESTS") == "1", "Temporal harness not enabled")
    async def test_temporal_pre_commit_failure_stays_uncertain(self):
        await self.temporal_activity_failure(False)

    async def test_command_audit_and_outbox_commit_together(self):
        command = await self.reserve()
        self.assertEqual(await self.counts(), (1, 1, 1))
        row = await self.pool.fetchrow("SELECT command_id,destination FROM middleware_outbox")
        self.assertEqual(str(row["command_id"]), str(command.command_id))
        self.assertEqual(row["destination"], "temporal-command")

    async def test_invalid_policy_files_commit_rejection_without_transport(self):
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from contextlib import nullcontext
        import httpx
        from app.vicidial_internal_call_adapter import VicidialInternalCallAdapter
        from tests.test_vicidial_internal_call_adapter import principal as appolon

        sends = 0
        async def transport(request):
            nonlocal sends
            sends += 1
            raise AssertionError("invalid policy must never reach transport")

        real_fstat = os.fstat
        def root_owned(fd):
            fields = list(real_fstat(fd))
            fields[4] = 0  # Only emulate the protected file's owner in non-root tests.
            return os.stat_result(fields)

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            for failure in ("missing", "unreadable", "malformed", "schema", "unsafe-mode"):
                with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                    actor = appolon()
                    policy = grant(principal=actor, authorization_reference="CHG-TEST-" + failure)
                    body = originate(employee_id=actor.employee_id, campaign=actor.campaign_id,
                                     business_unit=actor.business_unit,
                                     idempotency_key="test-policy-" + failure)
                    operation = await self.ledger.originate(actor, body, "policy-failure", policy)
                    for state in ("queued", "dispatching"):
                        await self.store.transition(operation.tenant_id, operation.command_id,
                                                    new_state=state, actor_id="test", reason="test")
                    request = await self.execution_request(operation)
                    path = Path(temporary) / "policy.json"
                    path.write_text(policy.model_dump_json())
                    path.chmod(0o600)
                    if failure == "missing":
                        path.unlink()
                    elif failure == "malformed":
                        path.write_text("{not-json")
                    elif failure == "schema":
                        path.write_text("{}")
                    elif failure == "unsafe-mode":
                        path.chmod(0o666)
                    blocked = (patch("app.calling_contract.os.open", side_effect=PermissionError("test"))
                               if failure == "unreadable" else nullcontext())
                    adapter = VicidialInternalCallAdapter(
                        SimpleNamespace(source_sha=policy.source_sha),
                        {"CODESTRA_INTERNAL_CALL_POLICY_FILE": str(path)}, client,
                    )
                    activities = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
                    with patch("app.calling_contract.os.fstat", side_effect=root_owned), blocked:
                        result = await activities.execute_command(request)
                    self.assertEqual(result.status, "cancelled")
                    self.assertEqual((await activities.recover_call_execution(request)).status, "cancelled")
                    self.assertEqual(await self.pool.fetchval(
                        "SELECT count(*) FROM middleware_command_audit "
                        "WHERE command_id=$1 AND new_state='cancelled'", request.command_id), 1)
        self.assertEqual(sends, 0)

    async def test_two_facades_serialize_distinct_keys(self):
        results = await asyncio.gather(self.reserve(), self.reserve(
            originate(idempotency_key="test-originate-0002"), CallingLedger(self.commands)), return_exceptions=True)
        self.assertEqual(sum(isinstance(result, CommandConflict) for result in results), 1)
        self.assertEqual(await self.counts(), (1, 1, 1))

    async def test_reconciliation_cannot_replace_the_accepted_asterisk_identity(self):
        from temporalio.exceptions import ApplicationError
        from tests.test_calling_contract import CallingContractTests
        from tests.test_vicidial_internal_call_adapter import principal as appolon
        actor = appolon()
        policy = grant(principal=actor)
        body = originate(employee_id=actor.employee_id, campaign=actor.campaign_id,
                         business_unit=actor.business_unit)
        operation = await self.ledger.originate(actor, body, "test-provider-binding", policy)
        for state in ("queued", "dispatching", "accepted", "readback_pending", "reconciliation_required"):
            await self.store.transition(operation.tenant_id, operation.command_id,
                                        new_state=state, actor_id="test", reason="test",
                                        provider_operation_id="accepted-call-A")
        evidence = CallingContractTests().lifecycle(
            operation_id=str(operation.command_id), correlation_id="test-provider-binding",
            tenant_id=actor.tenant_id, subject=actor.subject, employee_id=actor.employee_id,
            authorization_reference=policy.authorization_reference,
            asterisk_uniqueid="unrelated-call-B",
        )
        class Adapter:
            async def execute(self, request):
                raise AssertionError("reconciliation never dispatches")
            async def readback(self, request):
                return ActivityResult("matched", "terminal", "unrelated-call-B", evidence)
        activities = CommandLedgerWorkflowActivities(self.store, vicidial_internal=Adapter())
        with self.assertRaises(ApplicationError):
            await activities.reconcile_operation(ReconciliationRequest(
                str(operation.command_id), operation.tenant_id, "test identity mismatch"))
        self.assertEqual(tuple(await self.pool.fetchrow(
            "SELECT state,provider_operation_id FROM middleware_commands WHERE command_id=$1",
            str(operation.command_id))), ("reconciliation_required", "accepted-call-A"))
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE new_state='completed'"), 0)

    async def test_concurrent_retries_are_one_command_and_one_outbox(self):
        results = await asyncio.gather(*[self.reserve(ledger=CallingLedger(self.commands)) for _ in range(8)])
        self.assertEqual(len({result.command_id for result in results}), 1)
        self.assertEqual(await self.counts(), (1, 1, 1))

    async def test_restart_reconstructs_binding_and_replay(self):
        first = await self.reserve()
        fresh = CallingLedger(self.commands)
        _, observed = await fresh.get(principal(), first.command_id)
        self.assertEqual(observed.command_id, first.command_id)
        replay = await fresh.replay(principal(), originate(), "test-correlation-0001")
        self.assertTrue(replay.duplicate)
        with self.assertRaises(CommandConflict):
            await fresh.replay(principal(), originate(destination="internal:OTHER"), "test-correlation-0001")

    async def test_outbox_failure_rolls_back_and_does_not_consume_grant(self):
        await self.pool.execute("""
            CREATE FUNCTION reject_calling_test_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic outbox failure'; END $$;
            CREATE TRIGGER reject_calling_test_outbox BEFORE INSERT ON middleware_outbox
            FOR EACH ROW EXECUTE FUNCTION reject_calling_test_outbox();
        """)
        with self.assertRaises(asyncpg.PostgresError):
            await self.reserve()
        self.assertEqual(await self.counts(), (0, 0, 0))
        await self.pool.execute("DROP TRIGGER reject_calling_test_outbox ON middleware_outbox")
        await self.reserve()
        self.assertEqual(await self.counts(), (1, 1, 1))

    async def test_two_worker_activities_acquire_one_durable_dispatch_claim(self):
        operation = await self.reserve()
        for state in ("queued", "dispatching"):
            await self.store.transition(
                operation.tenant_id, operation.command_id, new_state=state,
                actor_id="test-worker", reason="synthetic dispatch setup",
            )
        row = await self.pool.fetchrow(
            "SELECT payload FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
            operation.tenant_id, str(operation.command_id),
        )
        payload = row["payload"] if isinstance(row["payload"], dict) else __import__("json").loads(row["payload"])
        client_id = payload.pop(AUTHENTICATED_CLIENT_ID_KEY)
        request = CommandExecutionRequest(**payload, authenticated_client_id=client_id)

        class Adapter:
            def __init__(self):
                self.executions = 0
                self.readbacks = 0
                self.claim_observed = asyncio.Event()
                self.loser_observed = asyncio.Event()
            async def execute(self, _request):
                self.executions += 1
                self.claim_observed.set()
                await asyncio.wait_for(self.loser_observed.wait(), timeout=5)
                return ActivityResult("accepted", "synthetic accepted", "provider-id")
            async def readback(self, _request):
                await asyncio.wait_for(self.claim_observed.wait(), timeout=5)
                self.readbacks += 1
                self.loser_observed.set()
                return ActivityResult("mismatch", "synthetic pending", "provider-id")

        adapter = Adapter()
        first = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)  # type: ignore[arg-type]
        second = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)  # type: ignore[arg-type]
        await asyncio.gather(
            first.execute_command(request), second.execute_command(request),
        )
        self.assertEqual(adapter.executions, 1)
        self.assertEqual(adapter.readbacks, 1)
        state, result_payload = await self.pool.fetchrow(
            "SELECT state,result_payload FROM middleware_command_attempts WHERE tenant_id=$1 AND command_id=$2",
            operation.tenant_id, str(operation.command_id),
        )
        self.assertEqual(state, "dispatching")
        value = result_payload if isinstance(result_payload, dict) else __import__("json").loads(result_payload)
        self.assertEqual(value, {"dispatch_claimed": True})

    async def test_pre_dispatch_rejection_is_committed_before_ack_and_restart_safe(self):
        operation = await self.reserve()
        for state in ("queued", "dispatching"):
            await self.store.transition(
                operation.tenant_id, operation.command_id, new_state=state,
                actor_id="test-worker", reason="synthetic dispatch setup",
            )
        row = await self.pool.fetchrow(
            "SELECT payload FROM middleware_commands WHERE tenant_id=$1 AND command_id=$2",
            operation.tenant_id, str(operation.command_id),
        )
        payload = row["payload"] if isinstance(row["payload"], dict) else __import__("json").loads(row["payload"])
        client_id = payload.pop(AUTHENTICATED_CLIENT_ID_KEY)
        request = CommandExecutionRequest(**payload, authenticated_client_id=client_id)

        class NoSendAdapter:
            executions = 0
            readbacks = 0
            async def execute(self, _request):
                self.executions += 1
                raise VicidialInternalCallPreDispatchRejected("synthetic no-send")
            async def readback(self, _request):
                self.readbacks += 1
                raise AssertionError("committed no-send cancellation needs no readback")

        adapter = NoSendAdapter()
        first = CommandLedgerWorkflowActivities(
            self.store, vicidial_internal=adapter,  # type: ignore[arg-type]
        )
        result = await first.execute_command(request)
        self.assertEqual(result.status, "cancelled")
        command_state, attempt_state, error_code = await self.pool.fetchrow(
            "SELECT c.state,a.state,a.error_code FROM middleware_commands c "
            "JOIN middleware_command_attempts a USING (tenant_id,command_id) "
            "WHERE c.tenant_id=$1 AND c.command_id=$2 ORDER BY a.attempt_number DESC LIMIT 1",
            operation.tenant_id, str(operation.command_id),
        )
        self.assertEqual(
            (command_state, attempt_state, error_code),
            ("cancelled", "failed", "pre_dispatch_rejected"),
        )

        restarted = CommandLedgerWorkflowActivities(
            self.store, vicidial_internal=adapter,  # type: ignore[arg-type]
        )
        replay = await restarted.execute_command(request)
        self.assertEqual(replay.status, "cancelled")
        self.assertEqual((adapter.executions, adapter.readbacks), (1, 0))

    async def persistence_retry_case(self, after_commit):
        from unittest.mock import patch
        operation = await self.reserve()
        for state in ("queued", "dispatching"):
            await self.store.transition(operation.tenant_id, operation.command_id,
                                        new_state=state, actor_id="test", reason="test")
        request = await self.execution_request(operation)
        class Adapter:
            executions = 0
            async def execute(self, request):
                self.executions += 1
                raise VicidialInternalCallPreDispatchRejected("synthetic rejection")
            async def readback(self, request):
                raise AssertionError("persistence retry cannot send/read a provider request")
        adapter = Adapter()
        activities = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
        original = activities.record_call_pre_dispatch_rejection
        attempts = 0
        async def transient(request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                if after_commit:
                    await original(request)
                raise asyncpg.ConnectionDoesNotExistError("synthetic dropped DB connection")
            return await original(request)
        with patch.object(activities, "record_call_pre_dispatch_rejection", new=transient):
            result = await activities.execute_command(request)
        self.assertEqual(result.status, "cancelled")
        self.assertEqual((attempts, adapter.executions), (2, 1))
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE new_state='cancelled'"), 1)
        self.assertEqual((await activities.recover_call_execution(request)).status, "cancelled")
        with self.assertRaises(CommandConflict):
            await self.reserve(originate(idempotency_key="test-no-replenishment"))

    async def test_transient_no_send_persistence_failure_retries_without_dispatch(self):
        await self.persistence_retry_case(False)

    async def test_ambiguous_database_commit_ack_reloads_without_duplicate_audit(self):
        await self.persistence_retry_case(True)

    async def test_exhausted_persistence_retries_do_not_manufacture_cancellation(self):
        from unittest.mock import AsyncMock, patch
        operation = await self.reserve()
        for state in ("queued", "dispatching"):
            await self.store.transition(operation.tenant_id, operation.command_id,
                                        new_state=state, actor_id="test", reason="test")
        request = await self.execution_request(operation)
        class Adapter:
            executions = 0
            async def execute(self, request):
                self.executions += 1
                raise VicidialInternalCallPreDispatchRejected("synthetic rejection")
        adapter = Adapter()
        activities = CommandLedgerWorkflowActivities(self.store, vicidial_internal=adapter)
        with patch.object(activities, "record_call_pre_dispatch_rejection",
                          new=AsyncMock(side_effect=TimeoutError("synthetic database timeout"))) as persist:
            with self.assertRaises(TimeoutError):
                await activities.execute_command(request)
        self.assertEqual((persist.await_count, adapter.executions), (3, 1))
        self.assertEqual((await activities.recover_call_execution(request)).status,
                         "reconciliation_required")
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE new_state='cancelled'"), 0)
        with self.assertRaises(CommandConflict):
            await self.reserve(originate(idempotency_key="test-no-replenishment"))

    async def test_completed_hangup_restart_repairs_origin_without_new_mutation(self):
        appolon = principal().model_copy(update={
            "tenant_id": "tenant-test", "subject": "subject-appolon",
            "employee_id": "employee-appolon", "campaign_id": "TEST_SYN",
            "business_unit": "business-test", "extension": "6901",
        })
        body = originate().model_copy(update={
            "employee_id": appolon.employee_id, "campaign": appolon.campaign_id,
            "business_unit": appolon.business_unit,
        })
        appolon_grant = self.grant.model_copy(update={"principal": appolon})
        original = await self.ledger.originate(
            appolon, body, "test-correlation-0001", appolon_grant,
        )
        for state in ("queued", "dispatching", "accepted", "readback_pending",
                      "reconciliation_required"):
            original = await self.store.transition(
                original.tenant_id, original.command_id, new_state=state,
                actor_id="test-worker", reason="synthetic restart boundary",
                provider_operation_id=("codestra-" + "a" * 32)
                if state == "accepted" else None,
            )
        hangup = await self.ledger.hangup(
            appolon, original.command_id, key="hangup-restart-0001",
            expected_version=original.resource_version, reason="Agent hangup",
        )
        fresh_ledger = CallingLedger(self.commands)
        document, observed = await fresh_ledger.get(appolon, hangup.command_id)
        self.assertEqual(document.payload["origin_operation_id"], str(original.command_id))
        self.assertEqual(observed.command_id, hangup.command_id)
        wrong = appolon.model_copy(update={"subject": "subject-other"})
        with self.assertRaises(CommandNotFound):
            await fresh_ledger.get(wrong, hangup.command_id)

        for state in ("queued", "dispatching", "accepted", "readback_pending",
                      "reconciliation_required"):
            hangup = await self.store.transition(
                hangup.tenant_id, hangup.command_id, new_state=state,
                actor_id="test-worker", reason="synthetic interrupted hangup",
                provider_operation_id=("codestra-" + "a" * 32)
                if state == "accepted" else None,
            )
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        evidence = {
            "operation_id": str(original.command_id),
            "correlation_id": "test-correlation-0001", "dispatch_state": "accepted",
            "asterisk_uniqueid": "codestra-" + "a" * 32,
            "linkedid": "codestra-" + "a" * 32, "call_id": "call-test-1",
            "call_state": "completed", "answered_at": now, "ended_at": now,
            "terminal": True,
            "evidence": {"event_sequence": [{"sequence": 1}],
                         "evidence_source": "ami-lifecycle-gateway"},
            "tenant_id": appolon.tenant_id, "subject": appolon.subject,
            "employee_id": appolon.employee_id, "username": "appolon",
            "extension": appolon.extension, "campaign": appolon.campaign_id,
            "authorization_reference": appolon_grant.authorization_reference,
            "created_at": now, "duration_seconds": 0,
            "talk_duration_seconds": 0, "hangup_cause": "Normal Clearing",
            "hangup_cause_code": 16, "internal_only": True,
            "external_dialing": False, "recording": False,
        }

        class NoMutationAdapter:
            executions = 0
            readbacks = 0
            async def execute(self, _request):
                self.executions += 1
                raise AssertionError("restart recovery must not mutate Server B")
            async def readback(self, _request):
                self.readbacks += 1
                raise AssertionError("completed hangup recovery uses persisted evidence")

        adapter = NoMutationAdapter()
        interrupted = CommandLedgerWorkflowActivities(
            self.store, vicidial_internal=adapter,  # type: ignore[arg-type]
        )
        request = ReconciliationRequest(
            str(hangup.command_id), hangup.tenant_id, "synthetic crash boundary",
        )
        command, _, digest = await interrupted._load_reconciliation_command(request)
        self.assertIsNotNone(command)
        self.assertIsNotNone(digest)
        await interrupted._persist_reconciliation_result(
            request, ActivityResult("matched", "terminal hangup", evidence["asterisk_uniqueid"], evidence),
            digest,  # type: ignore[arg-type]
        )
        self.assertEqual((await self.store.get(original.tenant_id, original.command_id)).state,
                         "reconciliation_required")

        restarted = CommandLedgerWorkflowActivities(
            self.store, vicidial_internal=adapter,  # type: ignore[arg-type]
        )
        await restarted.reconcile_operation(request)
        audit_count = await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE tenant_id=$1",
            original.tenant_id,
        )
        await restarted.reconcile_operation(request)
        self.assertEqual(await self.pool.fetchval(
            "SELECT count(*) FROM middleware_command_audit WHERE tenant_id=$1",
            original.tenant_id,
        ), audit_count)
        self.assertEqual((await self.store.get(original.tenant_id, original.command_id)).state,
                         "completed")
        self.assertEqual((await self.store.get(hangup.tenant_id, hangup.command_id)).state,
                         "completed")
        self.assertEqual((adapter.executions, adapter.readbacks), (0, 0))
        with self.assertRaises(CommandConflict):
            await self.ledger.originate(
                appolon, body.model_copy(update={
                    "idempotency_key": "test-originate-after-hangup",
                }), "test-correlation-0001", appolon_grant,
            )


if __name__ == "__main__":
    unittest.main()
