from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import ValidationError

from app.automation_policy import AutomationPolicy
from app.automation_v2 import (
    AutomationCommandRequest,
    AutomationConflict,
    AutomationService,
    FailureResult,
    JobClaimRequest,
    MemoryAutomationStore,
    StepRecord,
    WorkflowRoute,
    WorkflowRouter,
)
from app.commands import CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.main import create_app
from app.models import EventEnvelope
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


class V2TokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        payload = _jwt_payload(authorization)
        if payload.get("azp") != expected_client_id:
            raise AssertionError("route selected the wrong machine client")
        return {
            "iss": "https://auth.codestra.co/realms/codestra",
            "aud": "middleware-api",
            "azp": expected_client_id,
            "scope": required_scope,
            "sub": f"service-account-{expected_client_id}",
        }

    async def ready(self) -> bool:
        return True


def _b64(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()


def _authorization(client_id: str) -> str:
    return f"Bearer {_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64({'azp': client_id})}.signature"


def _jwt_payload(authorization: str) -> dict[str, Any]:
    token = authorization.removeprefix("Bearer ")
    encoded = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _event(*, event_id: str = "event-automation-0001") -> EventEnvelope:
    return EventEnvelope.model_construct(
        event_id=event_id,
        event_type="codestra.email.message.delivered",
        event_version="1.0",
        occurred_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
        received_at=datetime(2026, 9, 4, 12, 0, 1, tzinfo=UTC),
        source="klyrow-gateway",
        tenant_id="tenant-1",
        customer_id=None,
        correlation_id="corr-automation-0001",
        causation_id="cause-automation-0001",
        idempotency_key=event_id,
        payload={"message_id": "message-1", "status": "delivered"},
        metadata={},
    )


def _route(
    *,
    client_id: str = "n8n-messaging-automation",
    workflow_family: str = "messaging.email",
    workflow_key: str = "klyrow.email.delivery-reconcile.v1",
) -> WorkflowRoute:
    return WorkflowRoute(
        event_type="codestra.email.message.delivered",
        workflow_key=workflow_key,
        workflow_family=workflow_family,
        workflow_version=1,
        client_id=client_id,
        max_attempts=3,
        external_effect=False,
    )


async def _seed(
    store: MemoryAutomationStore,
    *,
    route: WorkflowRoute | None = None,
    event_id: str = "event-automation-0001",
) -> tuple[UUID, str, EventEnvelope, WorkflowRoute]:
    selected = route or _route()
    envelope = _event(event_id=event_id)
    await store.enqueue_event(envelope, selected, source_client_id=envelope.source)
    [(tenant_id, job_id)] = list(store.jobs)
    assert tenant_id == envelope.tenant_id
    return job_id, store.dispatches[(tenant_id, job_id)]["delivery_token"], envelope, selected


def _runtime(test_settings) -> tuple[Runtime, MemoryAutomationStore, CommandService]:
    commands = CommandService(
        store=MemoryCommandStore(),
        policies=CommandPolicyRegistry.load(),
    )
    store = MemoryAutomationStore()
    automation = AutomationService(
        store=store,
        policy=AutomationPolicy.from_path(),
        workflow_router=WorkflowRouter.load(),
        commands=commands,
        umbrella_controls=test_settings.umbrella_controls,
    )
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=V2TokenVerifier(),
        commands=commands,
        automation=automation,
    )
    return runtime, store, commands


def _headers(client_id: str, correlation_id: str, idempotency_key: str, tenant_id: str = "tenant-1") -> dict[str, str]:
    return {
        "Authorization": _authorization(client_id),
        "X-Tenant-ID": tenant_id,
        "X-Correlation-ID": correlation_id,
        "X-Request-ID": f"request-{idempotency_key}",
        "Idempotency-Key": idempotency_key,
    }


@pytest.mark.asyncio
async def test_all_thirteen_v2_routes_are_mounted(test_settings) -> None:
    runtime, _, _ = _runtime(test_settings)
    app = create_app(settings=test_settings, runtime=runtime)
    schema = app.openapi()
    observed = {
        f"{method.upper()} {path}"
        for path, item in schema["paths"].items()
        if path.startswith("/v2/automation")
        for method in item
        if method in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    }
    assert observed == {
        "POST /v2/automation/jobs/claim",
        "GET /v2/automation/jobs/{job_id}",
        "POST /v2/automation/jobs/{job_id}/heartbeat",
        "POST /v2/automation/jobs/{job_id}/steps",
        "POST /v2/automation/jobs/{job_id}/complete",
        "POST /v2/automation/jobs/{job_id}/fail",
        "POST /v2/automation/commands",
        "GET /v2/automation/commands/{command_id}",
        "POST /v2/automation/approvals",
        "GET /v2/automation/approvals/{approval_id}",
        "POST /v2/automation/dead-letters/{dead_letter_id}/replay",
        "POST /v2/automation/jobs/reconcile",
        "GET /v2/automation/capabilities/{capability}",
        "GET /v2/automation/executions/{job_id}",
        "GET /v2/automation/executions/{job_id}/result",
        "POST /v2/automation/executions/{job_id}/cancel",
    }


@pytest.mark.asyncio
async def test_claim_step_heartbeat_and_completion_are_lease_bound(test_settings) -> None:
    runtime, store, _ = _runtime(test_settings)
    job_id, delivery_token, envelope, route = await _seed(store)
    execution_id = uuid4()
    app = create_app(settings=test_settings, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            claim_idem = "idem-claim-automation-0001"
            claim_body = {
                "tenant_id": envelope.tenant_id,
                "correlation_id": envelope.correlation_id,
                "idempotency_key": claim_idem,
                "job_id": str(job_id),
                "delivery_token": delivery_token,
                "workflow_key": route.workflow_key,
                "workflow_version": route.workflow_version,
                "execution_id": str(execution_id),
            }
            claimed = await client.post(
                "/v2/automation/jobs/claim",
                json=claim_body,
                headers=_headers(route.client_id, envelope.correlation_id, claim_idem),
            )
            assert claimed.status_code == 200, claimed.text
            lease_token = claimed.json()["lease_token"]
            duplicate = await client.post(
                "/v2/automation/jobs/claim",
                json=claim_body,
                headers=_headers(route.client_id, envelope.correlation_id, claim_idem),
            )
            assert duplicate.status_code == 200
            assert duplicate.json()["duplicate"] is True
            assert duplicate.json()["lease_token"] == lease_token

            heartbeat_idem = "idem-heartbeat-automation-0001"
            heartbeat = await client.post(
                f"/v2/automation/jobs/{job_id}/heartbeat",
                json={
                    "tenant_id": envelope.tenant_id,
                    "correlation_id": envelope.correlation_id,
                    "idempotency_key": heartbeat_idem,
                    "lease_token": lease_token,
                    "execution_id": str(execution_id),
                },
                headers=_headers(route.client_id, envelope.correlation_id, heartbeat_idem),
            )
            assert heartbeat.status_code == 200, heartbeat.text
            assert heartbeat.json()["state"] == "RUNNING"

            step_idem = "idem-step-automation-0001"
            step_body = {
                "tenant_id": envelope.tenant_id,
                "correlation_id": envelope.correlation_id,
                "idempotency_key": step_idem,
                "lease_token": lease_token,
                "execution_id": str(execution_id),
                "step_key": "normalize-delivery-event",
                "step_state": "COMPLETED",
                "recorded_at": datetime.now(UTC).isoformat(),
                "safe_metadata": {"message_id": "message-1"},
            }
            step = await client.post(
                f"/v2/automation/jobs/{job_id}/steps",
                json=step_body,
                headers=_headers(route.client_id, envelope.correlation_id, step_idem),
            )
            assert step.status_code == 202, step.text
            replay = await client.post(
                f"/v2/automation/jobs/{job_id}/steps",
                json=step_body,
                headers=_headers(route.client_id, envelope.correlation_id, step_idem),
            )
            assert replay.status_code == 200
            assert replay.json()["duplicate"] is True

            complete_idem = "idem-complete-automation-0001"
            complete_body = {
                "tenant_id": envelope.tenant_id,
                "correlation_id": envelope.correlation_id,
                "idempotency_key": complete_idem,
                "lease_token": lease_token,
                "execution_id": str(execution_id),
                "result_code": "DELIVERY_RECONCILED",
                "safe_result": {"message_id": "message-1"},
            }
            completed = await client.post(
                f"/v2/automation/jobs/{job_id}/complete",
                json=complete_body,
                headers=_headers(route.client_id, envelope.correlation_id, complete_idem),
            )
            assert completed.status_code == 200, completed.text
            assert completed.json()["state"] == "COMPLETED"
            terminal_replay = await client.post(
                f"/v2/automation/jobs/{job_id}/complete",
                json=complete_body,
                headers=_headers(route.client_id, envelope.correlation_id, complete_idem),
            )
            assert terminal_replay.status_code == 200
            assert terminal_replay.json()["duplicate"] is True


@pytest.mark.asyncio
async def test_one_use_delivery_token_has_one_concurrent_winner() -> None:
    store = MemoryAutomationStore()
    job_id, delivery_token, envelope, route = await _seed(store)

    async def attempt(execution_id: UUID):
        return await store.claim(
            JobClaimRequest(
                tenant_id=envelope.tenant_id,
                correlation_id=envelope.correlation_id,
                idempotency_key=f"claim-{execution_id}",
                job_id=job_id,
                delivery_token=delivery_token,
                workflow_key=route.workflow_key,
                workflow_version=route.workflow_version,
                execution_id=execution_id,
            ),
            client_id=route.client_id,
        )

    outcomes = await asyncio.gather(attempt(uuid4()), attempt(uuid4()), return_exceptions=True)
    assert sum(not isinstance(item, Exception) for item in outcomes) == 1
    assert sum(isinstance(item, AutomationConflict) for item in outcomes) == 1


@pytest.mark.asyncio
async def test_header_body_disagreement_is_rejected(test_settings) -> None:
    runtime, store, _ = _runtime(test_settings)
    job_id, delivery_token, envelope, route = await _seed(store)
    idem = "idem-header-mismatch-0001"
    body = {
        "tenant_id": envelope.tenant_id,
        "correlation_id": envelope.correlation_id,
        "idempotency_key": idem,
        "job_id": str(job_id),
        "delivery_token": delivery_token,
        "workflow_key": route.workflow_key,
        "workflow_version": route.workflow_version,
        "execution_id": str(uuid4()),
    }
    app = create_app(settings=test_settings, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v2/automation/jobs/claim",
                json=body,
                headers=_headers(route.client_id, "different-correlation", idem),
            )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "automation_conflict"


@pytest.mark.asyncio
async def test_client_cannot_claim_another_family(test_settings) -> None:
    runtime, store, _ = _runtime(test_settings)
    job_id, delivery_token, envelope, route = await _seed(store)
    idem = "idem-cross-family-claim-0001"
    app = create_app(settings=test_settings, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/v2/automation/jobs/claim",
                json={
                    "tenant_id": envelope.tenant_id,
                    "correlation_id": envelope.correlation_id,
                    "idempotency_key": idem,
                    "job_id": str(job_id),
                    "delivery_token": delivery_token,
                    "workflow_key": route.workflow_key,
                    "workflow_version": route.workflow_version,
                    "execution_id": str(uuid4()),
                },
                headers=_headers("n8n-crm-automation", envelope.correlation_id, idem),
            )
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_odoo_command_is_authenticated_but_blocked_with_zero_effect(test_settings) -> None:
    runtime, store, commands = _runtime(test_settings)
    route = _route(
        client_id="n8n-crm-automation",
        workflow_family="crm",
        workflow_key="codestra.crm.lead-intake.v1",
    )
    job_id, delivery_token, envelope, _ = await _seed(
        store,
        route=route,
        event_id="event-crm-no-effect-0001",
    )
    execution_id = uuid4()
    app = create_app(settings=test_settings, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            claim_idem = "idem-crm-claim-0001"
            claimed = await client.post(
                "/v2/automation/jobs/claim",
                json={
                    "tenant_id": envelope.tenant_id,
                    "correlation_id": envelope.correlation_id,
                    "idempotency_key": claim_idem,
                    "job_id": str(job_id),
                    "delivery_token": delivery_token,
                    "workflow_key": route.workflow_key,
                    "workflow_version": 1,
                    "execution_id": str(execution_id),
                },
                headers=_headers(route.client_id, envelope.correlation_id, claim_idem),
            )
            assert claimed.status_code == 200, claimed.text
            lease_token = claimed.json()["lease_token"]
            command_idem = "idem-crm-command-0001"
            command = await client.post(
                "/v2/automation/commands",
                json={
                    "tenant_id": envelope.tenant_id,
                    "correlation_id": envelope.correlation_id,
                    "idempotency_key": command_idem,
                    "job_id": str(job_id),
                    "lease_token": lease_token,
                    "execution_id": str(execution_id),
                    "workflow_key": route.workflow_key,
                    "workflow_version": 1,
                    "step_key": "odoo-upsert",
                    "event_id": envelope.event_id,
                    "causation_id": envelope.causation_id,
                    "command_type": "crm.lead.upsert",
                    "command_version": "1.0",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "payload": {
                        "lead_source": "synthetic-staging",
                        "source_record_id": "source-no-effect-1",
                        "initial_stage": "review_pending",
                        "review_required": True,
                        "allow_external_contact": False,
                        "provenance": {
                            "method": "submitted_by_person",
                            "captured_by": "synthetic-staging",
                            "source_reference": "test://automation-v2/no-effect",
                            "legal_basis": "unknown_review_required"
                        },
                        "consent": {
                            "status": "unknown",
                            "channels": {"email": False, "sms": False, "phone": False}
                        },
                        "lead": {
                            "name": "Synthetic No Effect",
                            "description": "No-effect contract proof",
                            "contact": None,
                            "company": None,
                            "tags": ["synthetic", "no-effect"]
                        }
                    },
                },
                headers=_headers(route.client_id, envelope.correlation_id, command_idem),
            )
    assert command.status_code == 403, command.text
    assert command.json()["error"]["code"] == "capability_disabled"
    assert isinstance(commands.store, MemoryCommandStore)
    assert commands.store._commands == {}


def test_n4_rejects_versioned_command_type_and_blind_unknown_outcome_retry() -> None:
    base = {
        "tenant_id": "tenant-1",
        "correlation_id": "correlation-1",
        "idempotency_key": "idempotency-1",  #gitleaks:allow
        "job_id": str(uuid4()),
        "lease_token": "l" * 32,
        "execution_id": str(uuid4()),
        "workflow_key": "klyrow.email.delivery-reconcile.v1",
        "workflow_version": 1,
        "step_key": "send",
        "event_id": "event-1",
        "causation_id": "cause-1",
        "command_type": "email.message.send.v1",
        "command_version": "1.0",
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {},
    }
    with pytest.raises(ValidationError, match="unversioned"):
        AutomationCommandRequest.model_validate(base)

    with pytest.raises(ValidationError, match="reconciliation"):
        FailureResult.model_validate(
            {
                "tenant_id": "tenant-1",
                "correlation_id": "correlation-1",
                "idempotency_key": "idempotency-2",  #gitleaks:allow
                "lease_token": "l" * 32,
                "execution_id": str(uuid4()),
                "error_code": "PROVIDER_TIMEOUT",
                "retryable": True,
                "unknown_outcome": True,
                "safe_error": {},
            }
        )

    with pytest.raises(ValidationError, match="sensitive"):
        StepRecord.model_validate(
            {
                "tenant_id": "tenant-1",
                "correlation_id": "correlation-1",
                "idempotency_key": "idempotency-3",  #gitleaks:allow
                "lease_token": "l" * 32,
                "execution_id": str(uuid4()),
                "step_key": "safe-evidence",
                "step_state": "COMPLETED",
                "recorded_at": datetime.now(UTC).isoformat(),
                "safe_metadata": {"access_token": "forbidden"},
            }
        )


@pytest.mark.asyncio
async def test_replay_approval_is_bound_to_its_job() -> None:
    from datetime import timedelta
    from app.automation_v2 import (
        ApprovalRecord,
        AutomationAuthorizationDenied,
        DeadLetterRecord,
        DeadLetterReplayRequest,
    )

    store = MemoryAutomationStore()
    job_id, _, event, route = await _seed(store)
    now = datetime.now(UTC)
    dead_id, approval_id = uuid4(), uuid4()
    dead = DeadLetterRecord(
        dead_letter_id=dead_id, tenant_id=event.tenant_id, job_id=job_id,
        workflow_key=route.workflow_key, workflow_family=route.workflow_family,
        original_effect_fingerprint='a' * 64, safe_payload={}, state='OPEN',
        resource_version=1, created_at=now, updated_at=now,
    )
    approval = ApprovalRecord(
        approval_id=approval_id, tenant_id=event.tenant_id, job_id=uuid4(),
        approval_type='REPLAY', summary='Replay a different job', state='APPROVED',
        requested_by='operator', decided_by='reviewer',
        expires_at=now + timedelta(hours=1), created_at=now, updated_at=now,
    )
    store.dead_letters[(event.tenant_id, dead_id)] = dead
    store.approvals[(event.tenant_id, approval_id)] = ('digest', approval)
    body = DeadLetterReplayRequest(
        tenant_id=event.tenant_id, correlation_id=event.correlation_id,
        idempotency_key='replay-job-binding', approval_id=approval_id,
        expected_version=1, original_effect_fingerprint='a' * 64,
        safe_replay_classification='NO_EFFECT', replay_reason='Isolated test',
    )
    before = await store.get_job(event.tenant_id, job_id)
    dispatch = dict(store.dispatches[(event.tenant_id, job_id)])
    with pytest.raises(AutomationAuthorizationDenied):
        await store.replay_dead_letter(dead_id, body, client_id='n8n-operations-automation')
    assert await store.get_job(event.tenant_id, job_id) == before
    assert store.dispatches[(event.tenant_id, job_id)] == dispatch
    assert store.dead_letters[(event.tenant_id, dead_id)] == dead
    store.approvals[(event.tenant_id, approval_id)] = (
        'digest', approval.model_copy(update={'job_id': job_id, 'approval_type': 'EXECUTE'}),
    )
    with pytest.raises(AutomationAuthorizationDenied):
        await store.replay_dead_letter(dead_id, body, client_id='n8n-operations-automation')
    assert await store.get_job(event.tenant_id, job_id) == before
    assert store.dispatches[(event.tenant_id, job_id)] == dispatch
    assert store.dead_letters[(event.tenant_id, dead_id)] == dead
    store.approvals[(event.tenant_id, approval_id)] = (
        'digest', approval.model_copy(update={'job_id': job_id}),
    )
    result = await store.replay_dead_letter(dead_id, body, client_id='n8n-operations-automation')
    assert result.state == 'RETRY_SCHEDULED'


@pytest.mark.asyncio
@pytest.mark.parametrize('state', ['COMPLETED', 'CANCELLED', 'FAILED_TERMINAL', 'DEAD_LETTER'])
async def test_approval_preserves_terminal_job_state(state: str) -> None:
    from datetime import timedelta
    from app.automation_v2 import ApprovalRequest

    store = MemoryAutomationStore()
    job_id, _, event, route = await _seed(store)
    store.jobs[(event.tenant_id, job_id)]['state'] = state
    before = await store.get_job(event.tenant_id, job_id)
    body = ApprovalRequest(
        tenant_id=event.tenant_id, correlation_id=event.correlation_id,
        idempotency_key='terminal-approval-test', job_id=job_id,
        approval_type='REPLAY', summary='Review terminal outcome',
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approval = await store.request_approval(body, client_id=route.client_id, requested_by='operator')
    assert approval.state == 'PENDING'
    assert await store.get_job(event.tenant_id, job_id) == before
    duplicate = await store.request_approval(body, client_id=route.client_id, requested_by='operator')
    assert duplicate.duplicate is True
    assert duplicate.approval_id == approval.approval_id
    assert await store.get_job(event.tenant_id, job_id) == before
