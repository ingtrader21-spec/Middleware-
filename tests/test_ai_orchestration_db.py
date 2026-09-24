from __future__ import annotations

import os
import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import ai_jobs, ai_orchestration
from app.core.ai_contracts import AICommand, AIResult
from app.core.config import settings

pytestmark = pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required")


def make_command(kind="ai.chat.v1", profile="fast-chat", approval=False, *, tenant=None,
                 command_id=None, key=None):
    now = datetime.now(timezone.utc)
    return AICommand.model_validate({
        "command_id": command_id or uuid4(), "command_type": kind, "schema_version": "1.0",
        "tenant_id": tenant or uuid4(), "actor_id": "synthetic-user", "actor_type": "user",
        "correlation_id": f"corr-{uuid4()}", "idempotency_key": key or f"fixture-{uuid4()}",
        "priority": 5, "requested_at": now, "deadline_at": now + timedelta(minutes=5),
        "input": {"text": "synthetic example.invalid"},
        "model_policy": {"profile": profile}, "resource_limits": {"retry_count": 1},
        "data_classification": "synthetic",
        "approval_policy": {"required": approval, "action_types": ["proposal"] if approval else []},
        "callback_policy": {"mode": "poll"}, "metadata": {"fixture": "true"},
    })


@pytest.mark.asyncio
async def test_durable_command_idempotency_claim_result_approval_isolation_and_recovery():
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    workspace, other_workspace, tenant = uuid4(), uuid4(), uuid4()
    old_claims = settings.ai_worker_claims_enabled
    settings.ai_worker_claims_enabled = True
    try:
        async with sessions() as db:
            await db.execute(text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
              ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
              ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
              ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE"""))
            await db.commit()
            command = make_command(tenant=tenant)
            created = await ai_orchestration.submit(db, command, workspace)
            replay = await ai_orchestration.submit(db, command, workspace)
            assert created["job_id"] == replay["job_id"] and replay["idempotent_replay"]
            with pytest.raises(LookupError):
                await ai_orchestration.get(db, command.command_id, tenant, other_workspace)
            claimed = await ai_jobs.claim(db, "fixture-worker", 30, "corr-claim")
            assert claimed and claimed["id"] == command.command_id
            result = AIResult.model_validate({
                "command_id": command.command_id, "job_id": command.command_id,
                "status": "SUCCEEDED", "result_schema_version": "1.0",
                "model_used": "fixture-model", "provider_used": "mock",
                "started_at": datetime.now(timezone.utc), "completed_at": datetime.now(timezone.utc),
                "latency_ms": 1, "token_usage": {"total": 3}, "resource_usage": {},
                "output": {"text": "synthetic result"}, "structured_artifacts": [],
                "warnings": [], "policy_decisions": ["fixture"], "error": None,
                "retryability": "none", "audit_reference": f"audit-{uuid4()}",
            })
            state = await ai_orchestration.store_result(db, dict(claimed), result)
            assert state == "completed"
            assert await ai_jobs.finish(db, command.command_id, "fixture-worker",
                claimed["fencing_token"], failed=False, error_code=None, retryable=False,
                correlation_id="corr-finish", completion_state=state) == "completed"
            stored = await ai_orchestration.result(db, command.command_id, tenant, workspace)
            assert stored["output"] == {"text": "synthetic result"}

            proposal = make_command("ai.crm.v1", "crm-analysis", True, tenant=tenant)
            await ai_orchestration.submit(db, proposal, workspace)
            proposal_claim = await ai_jobs.claim(db, "fixture-worker", 30, "corr-proposal")
            proposal_result = result.model_copy(update={
                "command_id": proposal.command_id, "job_id": proposal.command_id,
                "output": {"proposal": "synthetic CRM note"},
            })
            state = await ai_orchestration.store_result(db, dict(proposal_claim), proposal_result)
            assert state == "approval_required"
            assert await ai_jobs.finish(db, proposal.command_id, "fixture-worker",
                proposal_claim["fencing_token"], failed=False, error_code=None,
                retryable=False, correlation_id="corr-proposal-finish",
                completion_state=state) == "approval_required"
            approved = await ai_orchestration.decide(db, proposal.command_id, tenant, workspace,
                "synthetic-approver", "corr-approval", True, "fixture approval")
            assert approved == "APPROVED"
            assert (await db.execute(text("SELECT count(*) FROM ai_job_approvals WHERE state='approved'"))).scalar_one() == 1

            retry = make_command(tenant=tenant)
            await ai_orchestration.submit(db, retry, workspace)
            retry_claim = await ai_jobs.claim(db, "fixture-worker", 30, "corr-retry")
            await db.execute(text("UPDATE ai_generation_jobs SET lease_expires_at=now()-interval '1 second' WHERE id=:id"),
                             {"id": retry.command_id})
            await db.commit()
            recovered = await ai_jobs.recover_expired(db)
            assert recovered == {"retried": 1, "dead_lettered": 0}
            assert retry_claim["attempt_count"] == 1
            await db.execute(text("UPDATE ai_generation_jobs SET state='cancelled' WHERE id=:id"),
                             {"id": retry.command_id})
            await db.commit()

            dead = make_command(tenant=tenant)
            dead.resource_limits.retry_count = 0
            await ai_orchestration.submit(db, dead, workspace)
            dead_claim = await ai_jobs.claim(db, "fixture-worker", 30, "corr-dead")
            await db.execute(text("UPDATE ai_generation_jobs SET lease_expires_at=now()-interval '1 second' WHERE id=:id"),
                             {"id": dead.command_id})
            await db.commit()
            recovered = await ai_jobs.recover_expired(db)
            assert recovered == {"retried": 0, "dead_lettered": 1}
            assert dead_claim["attempt_count"] == 1
            assert (await db.execute(text("SELECT count(*) FROM ai_job_dead_letters WHERE job_id=:id"),
                                     {"id": dead.command_id})).scalar_one() == 1

            cancellation = make_command(tenant=tenant)
            await ai_orchestration.submit(db, cancellation, workspace)
            state = await ai_orchestration.cancel(db, cancellation.command_id, tenant, workspace,
                                                  "synthetic-user", "corr-cancel")
            assert state == "CANCELLED"
            await db.execute(text("""INSERT INTO ai_tenant_quotas
              (organization_id,workspace_id,max_queued,max_running,daily_tokens,daily_compute_units)
              VALUES(:tenant,:workspace,0,1,10000,10000)
              ON CONFLICT(organization_id,workspace_id) DO UPDATE SET max_queued=0"""),
              {"tenant": tenant, "workspace": workspace})
            await db.commit()
            with pytest.raises(OverflowError, match="tenant_queue_quota_exceeded"):
                await ai_orchestration.submit(db, make_command(tenant=tenant), workspace)
    finally:
        settings.ai_worker_claims_enabled = old_claims
        await engine.dispose()


@pytest.mark.asyncio
async def test_atomic_claim_concurrency_has_no_duplicate_jobs():
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    try:
        async with sessions() as db:
            await db.execute(text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
              ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
              ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
              ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE"""))
            await db.commit()
            for _ in range(12):
                await ai_orchestration.submit(db, make_command(tenant=tenant), workspace)

        async def one_claim(number: int):
            async with sessions() as db:
                return await ai_jobs.claim(db, f"worker-{number}", 30, f"corr-claim-{number}")

        claims = await asyncio.gather(*(one_claim(number) for number in range(12)))
        ids = [item["id"] for item in claims if item]
        assert len(ids) == 12
        assert len(set(ids)) == 12
    finally:
        await engine.dispose()
