from __future__ import annotations

import asyncio
import hashlib
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.internal import ai_jobs as worker_api
from app.core import ai_jobs, ai_orchestration
from app.core.ai_contracts import AIResult
from app.qwen_auth_verifier import canonical_signing_string_v2
from tests.test_ai_orchestration_db import make_command
from worker import qwen_polling_worker as polling_worker


def test_compatible_pair_is_allowed() -> None:
    assert ai_jobs.compatible_profiles(["fast-chat"]) == {
        "fast-chat",
        "crm-analysis",
    }
    assert ai_jobs.compatible_profiles(["coding-default"]) == {"coding-default"}


def test_unknown_profile_fails_closed_without_database() -> None:
    assert ai_jobs.compatible_profiles(["future-unknown"]) == set()
    assert ai_jobs.compatible_profiles([None]) == set()


def test_worker_filter_cannot_expand_server_policy() -> None:
    assert ai_jobs.effective_compatible_profiles(
        ["coding-default"], ["fast-chat", "coding-default"]
    ) == {"coding-default"}
    assert (
        ai_jobs.effective_compatible_profiles(["coding-default"], ["fast-chat"])
        == set()
    )


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_controller_rejects_incompatible_second_profile() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
                  ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
                  ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
                  ai_messages,ai_conversations,ai_service_nonces CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
                  VALUES(:worker,'qwen-polling-worker',:digest,'{}'::jsonb,2,true)"""),
                {"worker": worker_id, "digest": "a" * 64},
            )
            coding = make_command(tenant=tenant)
            compatible_coding = make_command(tenant=tenant)
            chat = make_command(tenant=tenant)
            await ai_orchestration.submit(db, coding, workspace)
            await ai_orchestration.submit(db, compatible_coding, workspace)
            await ai_orchestration.submit(db, chat, workspace)
            await db.execute(
                text("""UPDATE ai_generation_jobs
                  SET model_profile=CASE id
                    WHEN :coding THEN 'coding-default'
                    WHEN :compatible_coding THEN 'coding-default'
                    WHEN :chat THEN 'fast-chat' END
                  WHERE id IN (:coding,:compatible_coding,:chat)"""),
                {
                    "coding": coding.command_id,
                    "compatible_coding": compatible_coding.command_id,
                    "chat": chat.command_id,
                },
            )
            await db.commit()

            first = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-coding",
                organization_id=tenant,
                workspace_id=workspace,
                service_id="qwen-polling-worker",
                allowed_model_profiles=["coding-default"],
            )
            assert first is not None
            assert first["id"] == coding.command_id
            assert (
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-malicious-fast-filter",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id="qwen-polling-worker",
                    allowed_model_profiles=["fast-chat"],
                )
                is None
            )
            second = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-compatible-coding",
                organization_id=tenant,
                workspace_id=workspace,
                service_id="qwen-polling-worker",
            )
            assert second is not None
            assert second["id"] == compatible_coding.command_id
            chat_state = (
                await db.execute(
                    text("SELECT state FROM ai_generation_jobs WHERE id=:job"),
                    {"job": chat.command_id},
                )
            ).scalar_one()
            assert chat_state == "queued"
            audit_details = (
                await db.execute(
                    text("""SELECT safe_details FROM ai_audit_events
                      WHERE event_type='job.claimed' AND job_id=:job"""),
                    {"job": compatible_coding.command_id},
                )
            ).scalar_one()
            assert audit_details["claimed_model_profile"] == "coding-default"
            assert audit_details["active_model_profiles"] == ["coding-default"]
            assert audit_details["effective_compatibility_class"] == ("coding-fallback")
            assert audit_details["effective_allowed_profile_count"] == 1
            assert audit_details["concurrency_slot"] == 2
    finally:
        await engine.dispose()


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_unknown_profile_fails_closed() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
                  ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
                  ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
                  ai_messages,ai_conversations,ai_service_nonces CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
                  VALUES(:worker,'qwen-polling-worker',:digest,'{}'::jsonb,2,true)"""),
                {"worker": worker_id, "digest": "a" * 64},
            )
            active = make_command(tenant=tenant)
            queued = make_command(tenant=tenant)
            await ai_orchestration.submit(db, active, workspace)
            await ai_orchestration.submit(db, queued, workspace)
            await db.execute(
                text("""UPDATE ai_generation_jobs SET
                  state=CASE id WHEN :active THEN 'leased' ELSE state END,
                  lease_owner=CASE id WHEN :active THEN :worker ELSE lease_owner END,
                  lease_expires_at=CASE id WHEN :active THEN now()+interval '30 seconds'
                    ELSE lease_expires_at END,
                  model_profile=CASE id WHEN :active THEN 'future-unknown'
                    ELSE 'fast-chat' END
                  WHERE id IN (:active,:queued)"""),
                {
                    "active": active.command_id,
                    "queued": queued.command_id,
                    "worker": worker_id,
                },
            )
            await db.commit()
            assert (
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-unknown-active",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id="qwen-polling-worker",
                )
                is None
            )
    finally:
        await engine.dispose()


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_incompatible_pair_race_is_blocked() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
                  ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
                  ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
                  ai_messages,ai_conversations,ai_service_nonces CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
                  VALUES(:worker,'qwen-polling-worker',:digest,'{}'::jsonb,2,true)"""),
                {"worker": worker_id, "digest": "a" * 64},
            )
            coding = make_command(tenant=tenant)
            chat = make_command(tenant=tenant)
            await ai_orchestration.submit(db, coding, workspace)
            await ai_orchestration.submit(db, chat, workspace)
            await db.execute(
                text("""UPDATE ai_generation_jobs SET model_profile=CASE id
                  WHEN :coding THEN 'coding-default' ELSE 'fast-chat' END
                  WHERE id IN (:coding,:chat)"""),
                {"coding": coding.command_id, "chat": chat.command_id},
            )
            await db.commit()

        async def concurrent_claim(correlation: str):
            async with sessions() as claim_db:
                return await ai_jobs.claim(
                    claim_db,
                    worker_id,
                    30,
                    correlation,
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id="qwen-polling-worker",
                )

        results = await asyncio.gather(
            concurrent_claim("corr-race-a"), concurrent_claim("corr-race-b")
        )
        assert sum(item is not None for item in results) == 1
        async with sessions() as db:
            leased = (
                await db.execute(
                    text("""SELECT count(*) FROM ai_generation_jobs
                      WHERE lease_owner=:worker AND state='leased'"""),
                    {"worker": worker_id},
                )
            ).scalar_one()
            assert leased == 1
    finally:
        await engine.dispose()


def test_exact_private_queue_route_and_auth_contract() -> None:
    paths = {
        (route.path, method)
        for route in worker_api.router.routes
        if isinstance(route, APIRoute)
        for method in (route.methods or set())
    }
    expected = {
        ("/internal/api/v1/ai/worker/jobs/claim", "POST"),
        ("/internal/api/v1/ai/worker/jobs/{job_id}/heartbeat", "POST"),
        ("/internal/api/v1/ai/worker/jobs/{job_id}/complete", "POST"),
        ("/internal/api/v1/ai/worker/jobs/{job_id}/fail", "POST"),
        ("/internal/api/v1/ai/worker/jobs/{job_id}/cancel", "POST"),
        ("/internal/api/v1/ai/worker/jobs/{job_id}", "GET"),
        ("/internal/api/v1/ai/worker/dead-letters", "GET"),
        ("/internal/api/v1/ai/worker/dead-letters/{job_id}/retry", "POST"),
    }
    assert expected <= paths
    source = Path(worker_api.__file__).read_text()
    for required in (
        'signature_version != "v2"',
        "canonical_signing_string_v2(",
        "X-Tenant-ID",
        "X-Workspace-ID",
        "ai_service_nonces",
        "settings.ai_worker_id",
        "FOR UPDATE SKIP LOCKED",
    ):
        if required == "FOR UPDATE SKIP LOCKED":
            assert required in Path(ai_jobs.__file__).read_text()
        else:
            assert required in source


def test_hmac_v2_binds_tenant_and_workspace() -> None:
    common = (
        "POST",
        "/internal/api/v1/ai/worker/jobs/claim",
        "1770000000",
        "nonce-0123456789abcdef",
        "a" * 64,
        "request-01234567",
        "correlation-01234567",
        "qwen-ai-01-worker",
    )
    first = canonical_signing_string_v2(
        *common,
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
    )
    other_tenant = canonical_signing_string_v2(
        *common,
        "00000000-0000-4000-8000-000000000003",
        "00000000-0000-4000-8000-000000000002",
    )
    other_workspace = canonical_signing_string_v2(
        *common,
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000004",
    )
    assert len({first, other_tenant, other_workspace}) == 3


def test_lease_maintenance_fails_closed_on_transport_error() -> None:
    class BrokenMiddleware:
        def request(self, *_: object) -> tuple[int, dict[str, object]]:
            raise polling_worker.WorkerError("transport unavailable")

    stop = threading.Event()
    cancellation = threading.Event()
    lease_lost = threading.Event()
    polling_worker.maintain_lease(
        BrokenMiddleware(),  # type: ignore[arg-type]
        "00000000-0000-4000-8000-000000000010",
        {"worker_id": "qwen-ai-01-worker", "fencing_token": 1},
        stop,
        cancellation,
        lease_lost,
        interval_seconds=0,
    )
    assert lease_lost.is_set()
    assert not cancellation.is_set()


def test_lease_maintenance_observes_cancellation_after_heartbeat() -> None:
    class CancellingMiddleware:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def request(
            self, method: str, path: str, body: object
        ) -> tuple[int, dict[str, object]]:
            assert method == "POST"
            self.paths.append(path)
            if path.endswith("/heartbeat"):
                return 200, {"accepted": True}
            return 200, {"cancel_requested": True}

    middleware = CancellingMiddleware()
    stop = threading.Event()
    cancellation = threading.Event()
    lease_lost = threading.Event()
    polling_worker.maintain_lease(
        middleware,  # type: ignore[arg-type]
        "00000000-0000-4000-8000-000000000010",
        {"worker_id": "qwen-ai-01-worker", "fencing_token": 1},
        stop,
        cancellation,
        lease_lost,
        interval_seconds=0,
    )
    assert cancellation.is_set()
    assert not lease_lost.is_set()
    assert middleware.paths == [
        "/internal/api/v1/ai/worker/jobs/00000000-0000-4000-8000-000000000010/heartbeat",
        "/internal/api/v1/ai/worker/jobs/00000000-0000-4000-8000-000000000010/cancellation-check",
    ]


def test_error_details_use_an_allowlist_and_reject_raw_messages() -> None:
    assert ai_jobs.sanitize_error_details(
        {
            "component": "litellm",
            "http_status": 503,
            "message": "Authorization: Bearer leaked-token",
            "secret_token": "leaked-token",
        }
    ) == {"component": "litellm", "http_status": 503}


@pytest.mark.asyncio
async def test_release_and_recovery_forward_authenticated_tenant(monkeypatch) -> None:
    tenant, workspace, job_id = uuid4(), uuid4(), uuid4()
    principal = worker_api.WorkerPrincipal(
        service_id="qwen-polling-worker",
        worker_id="qwen-ai-01-worker",
        tenant_id=tenant,
        workspace_id=workspace,
        request_id="request-01234567",
        correlation_id="correlation-01234567",
        scopes=worker_api.SERVER_SCOPES,
    )
    observed: dict[str, object] = {}

    async def fake_finish(*args, **kwargs):
        observed["finish_principal"] = kwargs["principal"]
        return {"state": "retry_wait"}

    async def fake_recover(db, organization_id, workspace_id):
        observed["recover"] = (organization_id, workspace_id)
        return {"retried": 0, "dead_lettered": 0}

    monkeypatch.setattr(worker_api, "_finish", fake_finish)
    monkeypatch.setattr(ai_jobs, "recover_expired", fake_recover)
    mutation = worker_api.LeaseMutation(worker_id="qwen-ai-01-worker", fencing_token=1)
    fake_db = cast(AsyncSession, object())
    assert await worker_api.release_job(job_id, mutation, principal, fake_db) == {
        "state": "retry_wait"
    }
    assert await worker_api.recover(principal, fake_db) == {
        "retried": 0,
        "dead_lettered": 0,
    }
    assert observed == {
        "finish_principal": principal,
        "recover": (tenant, workspace),
    }


@pytest.mark.asyncio
async def test_worker_config_exposes_authenticated_registration_limit() -> None:
    principal = worker_api.WorkerPrincipal(
        service_id="qwen-polling-worker",
        worker_id="qwen-ai-01-worker",
        tenant_id=uuid4(),
        workspace_id=uuid4(),
        request_id="request-01234567",
        correlation_id="correlation-01234567",
        scopes=worker_api.SERVER_SCOPES,
    )

    class Result:
        def scalar_one_or_none(self):
            return 2

    class DB:
        async def execute(self, _statement, parameters):
            assert parameters == {
                "worker": principal.worker_id,
                "service": principal.service_id,
            }
            return Result()

    response = await worker_api.worker_config(principal, cast(AsyncSession, DB()))
    assert response["registration_max_concurrency"] == 2
    assert response["hard_safety_cap"] == 2
    classes = cast(dict[str, str], response["model_runtime_classes"])
    compatibility = cast(dict[str, list[str]], response["runtime_class_compatibility"])
    assert classes["coding-default"] == "coding-fallback"
    assert compatibility["coding-fallback"] == ["coding-fallback"]


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_dead_letter_evidence_duplicate_result_and_approved_manual_retry() -> (
    None
):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
              ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
              ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
              ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE""")
            )
            await db.commit()

            command = make_command(tenant=tenant)
            command.resource_limits.retry_count = 0
            await ai_orchestration.submit(db, command, workspace)
            claimed = await ai_jobs.claim(
                db,
                "qwen-ai-01-worker",
                30,
                "corr-dead-letter",
                organization_id=tenant,
                workspace_id=workspace,
            )
            assert claimed is not None
            state = await ai_jobs.finish(
                db,
                command.command_id,
                "qwen-ai-01-worker",
                claimed["fencing_token"],
                failed=True,
                error_code="model_timeout",
                retryable=True,
                correlation_id="corr-dead-letter",
                safe_error_details={
                    "component": "litellm",
                    "secret_token": "must-redact",
                },
            )
            assert state == "dead_letter"
            dead = (
                (
                    await db.execute(
                        text("""SELECT * FROM ai_job_dead_letters
              WHERE job_id=:job AND tenant_id=:tenant AND workspace_id=:workspace"""),
                        {
                            "job": command.command_id,
                            "tenant": tenant,
                            "workspace": workspace,
                        },
                    )
                )
                .mappings()
                .one()
            )
            assert dead["final_error_code"] == "model_timeout"
            assert dead["attempt_count"] == dead["max_attempts"] == 1
            assert dead["safe_error_details"] == {"component": "litellm"}
            assert dead["manual_retry_requires_new_approval"] is True
            assert len(dead["evidence_hash"]) == 64
            with pytest.raises(PermissionError, match="new_approval_required"):
                await ai_jobs.retry_dead_letter(
                    db,
                    command.command_id,
                    uuid4(),
                    tenant,
                    workspace,
                    "qwen-ai-01-worker",
                    "corr-denied-retry",
                )

            approval_id = uuid4()
            await db.execute(
                text("""INSERT INTO ai_job_approvals
              (id,job_id,organization_id,workspace_id,action_type,proposal,
               proposal_sha256,state,requested_by,decided_by_fingerprint,
               decision_reason,decided_at)
              VALUES(:id,:job,:tenant,:workspace,'dead_letter.retry','{}'::jsonb,
               :hash,'approved','operator',:actor,'bounded retry',now())"""),
                {
                    "id": approval_id,
                    "job": command.command_id,
                    "tenant": tenant,
                    "workspace": workspace,
                    "hash": hashlib.sha256(b"{}").hexdigest(),
                    "actor": hashlib.sha256(b"approver").hexdigest(),
                },
            )
            await db.commit()
            assert await ai_jobs.retry_dead_letter(
                db,
                command.command_id,
                approval_id,
                tenant,
                workspace,
                "qwen-ai-01-worker",
                "corr-approved-retry",
            ) == {"state": "retry_wait"}
            await db.execute(
                text("""UPDATE ai_generation_jobs SET state='cancelled'
              WHERE id=:job"""),
                {"job": command.command_id},
            )
            await db.commit()

            result_command = make_command(tenant=tenant)
            await ai_orchestration.submit(db, result_command, workspace)
            result_claim = await ai_jobs.claim(
                db,
                "qwen-ai-01-worker",
                30,
                "corr-result",
                organization_id=tenant,
                workspace_id=workspace,
            )
            assert result_claim is not None
            now = datetime.now(timezone.utc)
            result = AIResult.model_validate(
                {
                    "command_id": result_command.command_id,
                    "job_id": result_command.command_id,
                    "status": "SUCCEEDED",
                    "result_schema_version": "1.0",
                    "model_used": "fixture",
                    "provider_used": "mock",
                    "started_at": now,
                    "completed_at": now,
                    "latency_ms": 1,
                    "token_usage": {},
                    "resource_usage": {},
                    "output": {"proposal": "safe"},
                    "structured_artifacts": [],
                    "warnings": [],
                    "policy_decisions": [],
                    "error": None,
                    "retryability": "none",
                    "audit_reference": "audit-fixture",
                }
            )
            completion_state = await ai_orchestration.store_result(
                db, dict(result_claim), result
            )
            await ai_jobs.finish(
                db,
                result_command.command_id,
                "qwen-ai-01-worker",
                result_claim["fencing_token"],
                failed=False,
                error_code=None,
                retryable=False,
                correlation_id="corr-result",
                completion_state=completion_state,
            )
            assert await ai_jobs.completed_result_status(
                db, result_command.command_id, tenant, workspace, result
            ) == {"state": "completed", "duplicate": "true"}
            changed = result.model_copy(update={"output": {"proposal": "different"}})
            with pytest.raises(PermissionError, match="duplicate_result_rejected"):
                await ai_jobs.completed_result_status(
                    db, result_command.command_id, tenant, workspace, changed
                )
    finally:
        await engine.dispose()


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_registered_worker_concurrency_and_tenant_scoped_recovery() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    other_tenant, other_workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    service_id = "qwen-polling-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
              ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
              ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
              ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
              (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
              VALUES(:worker,:service,:digest,'{}'::jsonb,1,true)"""),
                {"worker": worker_id, "service": service_id, "digest": "a" * 64},
            )
            await db.commit()

            first = make_command(tenant=tenant)
            second = make_command(tenant=tenant)
            foreign = make_command(tenant=other_tenant)
            await ai_orchestration.submit(db, first, workspace)
            await ai_orchestration.submit(db, second, workspace)
            await ai_orchestration.submit(db, foreign, other_workspace)
            claimed = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-registered-claim",
                organization_id=tenant,
                workspace_id=workspace,
                service_id=service_id,
            )
            assert claimed is not None
            retry_job_id = (
                second.command_id
                if claimed["id"] == first.command_id
                else first.command_id
            )
            with pytest.raises(OverflowError, match="worker_concurrency_limit"):
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-concurrency-denied",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id=service_id,
                )
            await db.rollback()

            await db.execute(
                text("""UPDATE ai_generation_jobs SET state='leased',lease_owner=:worker,
                  lease_expires_at=now()-interval '1 second',attempt_count=1,max_attempts=2
                  WHERE id=:job"""),
                {"worker": worker_id, "job": foreign.command_id},
            )
            await db.commit()
            assert await ai_jobs.recover_expired(db, tenant, workspace) == {
                "retried": 0,
                "dead_lettered": 0,
            }
            foreign_state = (
                await db.execute(
                    text("SELECT state FROM ai_generation_jobs WHERE id=:job"),
                    {"job": foreign.command_id},
                )
            ).scalar_one()
            assert foreign_state == "leased"
            assert await ai_jobs.recover_expired(db, other_tenant, other_workspace) == {
                "retried": 1,
                "dead_lettered": 0,
            }

            await db.execute(text("UPDATE ai_worker_registrations SET enabled=false"))
            await db.execute(
                text("""UPDATE ai_generation_jobs SET state='cancelled',lease_owner=NULL,
                  lease_expires_at=NULL WHERE id=:job"""),
                {"job": first.command_id},
            )
            await db.commit()
            with pytest.raises(PermissionError, match="worker_not_enabled"):
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-disabled-worker",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id=service_id,
                )

            approval_id = uuid4()
            await db.rollback()
            await db.execute(
                text("""UPDATE ai_generation_jobs SET state='dead_letter',
                  attempt_count=10,max_attempts=10 WHERE id=:job"""),
                {"job": retry_job_id},
            )
            await db.execute(
                text("""INSERT INTO ai_job_dead_letters
                  (job_id,organization_id,workspace_id,safe_error_code,attempt_count,
                   payload_sha256,final_error_code,max_attempts,safe_error_details,
                   failed_at,task_id,tenant_id,correlation_id,evidence_hash,
                   manual_retry_requires_new_approval)
                  SELECT id,organization_id,workspace_id,'attempts_exhausted',10,
                   request_sha256,'attempts_exhausted',10,'{}'::jsonb,
                   now()-interval '1 minute',id,organization_id,correlation_id,
                   :evidence,true FROM ai_generation_jobs WHERE id=:job"""),
                {"job": retry_job_id, "evidence": "b" * 64},
            )
            await db.execute(
                text("""INSERT INTO ai_job_approvals
                  (id,job_id,organization_id,workspace_id,action_type,proposal,
                   proposal_sha256,state,requested_by,decided_by_fingerprint,
                   decision_reason,decided_at)
                  VALUES(:id,:job,:tenant,:workspace,'dead_letter.retry','{}'::jsonb,
                   :hash,'approved','operator',:actor,'bounded retry',now())"""),
                {
                    "id": approval_id,
                    "job": retry_job_id,
                    "tenant": tenant,
                    "workspace": workspace,
                    "hash": hashlib.sha256(b"{}").hexdigest(),
                    "actor": hashlib.sha256(b"approver").hexdigest(),
                },
            )
            await db.commit()
            with pytest.raises(LookupError, match="dead_letter_not_retryable"):
                await ai_jobs.retry_dead_letter(
                    db,
                    retry_job_id,
                    approval_id,
                    tenant,
                    workspace,
                    worker_id,
                    "corr-retry-limit",
                )
    finally:
        await engine.dispose()


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_registered_worker_allows_two_fenced_leases_and_rejects_third() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    service_id = "qwen-polling-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
                  ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
                  ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
                  ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
                  VALUES(:worker,:service,:digest,'{}'::jsonb,2,true)"""),
                {"worker": worker_id, "service": service_id, "digest": "b" * 64},
            )
            commands = [make_command(tenant=tenant) for _ in range(3)]
            for command in commands:
                await ai_orchestration.submit(db, command, workspace)
            first = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-parallel-first",
                organization_id=tenant,
                workspace_id=workspace,
                service_id=service_id,
            )
            second = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-parallel-second",
                organization_id=tenant,
                workspace_id=workspace,
                service_id=service_id,
            )
            assert first is not None and second is not None
            assert first["id"] != second["id"]
            with pytest.raises(OverflowError, match="worker_concurrency_limit"):
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-parallel-third",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id=service_id,
                )
            await db.rollback()

            for lease in (first, second):
                expires = await ai_jobs.heartbeat(
                    db,
                    lease["id"],
                    worker_id,
                    lease["fencing_token"],
                    30,
                    service_id=service_id,
                    certificate_serial="3008",
                    spiffe_id="spiffe://codestra.internal/worker/qwen",
                    organization_id=tenant,
                    workspace_id=workspace,
                )
                assert expires > datetime.now(timezone.utc)

            await ai_jobs.finish(
                db,
                first["id"],
                worker_id,
                first["fencing_token"],
                failed=False,
                error_code=None,
                retryable=False,
                correlation_id="corr-parallel-finish-first",
            )
            healthy_second = await ai_jobs.assert_lease(
                db,
                second["id"],
                worker_id,
                second["fencing_token"],
                organization_id=tenant,
                workspace_id=workspace,
            )
            assert healthy_second["state"] == "leased"
    finally:
        await engine.dispose()


@pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)
@pytest.mark.asyncio
async def test_cancel_requested_lease_is_fenced_idempotent_and_recoverable() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    other_tenant, other_workspace = uuid4(), uuid4()
    worker_id = "qwen-ai-01-worker"
    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
              ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
              ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
              ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE""")
            )
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,max_concurrency,enabled)
                  VALUES(:worker,'qwen-polling-worker',:digest,'{}'::jsonb,1,true)"""),
                {"worker": worker_id, "digest": "a" * 64},
            )
            await db.commit()

            command = make_command(tenant=tenant)
            await ai_orchestration.submit(db, command, workspace)
            claim = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-cancel-claim",
                organization_id=tenant,
                workspace_id=workspace,
                service_id="qwen-polling-worker",
            )
            assert claim is not None
            token = claim["fencing_token"]
            assert (
                await ai_orchestration.cancel(
                    db,
                    command.command_id,
                    tenant,
                    workspace,
                    "synthetic-user",
                    "corr-cancel-request",
                )
                == "CANCEL_REQUESTED"
            )

            expires = await ai_jobs.heartbeat(
                db,
                command.command_id,
                worker_id,
                token,
                30,
                service_id="qwen-polling-worker",
                certificate_serial="12296",
                spiffe_id="spiffe://codestra.internal/worker/qwen",
                organization_id=tenant,
                workspace_id=workspace,
            )
            assert expires > datetime.now(timezone.utc)
            cancellable = await ai_jobs.assert_lease(
                db,
                command.command_id,
                worker_id,
                token,
                organization_id=tenant,
                workspace_id=workspace,
                allow_cancel_requested=True,
            )
            assert cancellable["state"] == "cancel_requested"
            with pytest.raises(PermissionError, match="stale_or_invalid_lease"):
                await ai_jobs.assert_lease(
                    db,
                    command.command_id,
                    "wrong-worker",
                    token,
                    organization_id=tenant,
                    workspace_id=workspace,
                    allow_cancel_requested=True,
                )
            await db.rollback()
            with pytest.raises(PermissionError, match="stale_or_invalid_lease"):
                await ai_jobs.assert_lease(
                    db,
                    command.command_id,
                    worker_id,
                    token,
                    organization_id=other_tenant,
                    workspace_id=other_workspace,
                    allow_cancel_requested=True,
                )
            await db.rollback()

            queued_while_cancelling = make_command(tenant=tenant)
            await ai_orchestration.submit(db, queued_while_cancelling, workspace)
            with pytest.raises(OverflowError, match="worker_concurrency_limit"):
                await ai_jobs.claim(
                    db,
                    worker_id,
                    30,
                    "corr-cancel-concurrency",
                    organization_id=tenant,
                    workspace_id=workspace,
                    service_id="qwen-polling-worker",
                )
            await db.rollback()

            expected = {"cancel_requested": True, "state": "cancelled"}
            assert (
                await ai_jobs.worker_cancel(
                    db,
                    command.command_id,
                    worker_id,
                    token,
                    tenant,
                    workspace,
                    "corr-cancel-finalize",
                )
                == expected
            )
            assert (
                await ai_jobs.worker_cancel(
                    db,
                    command.command_id,
                    worker_id,
                    token,
                    tenant,
                    workspace,
                    "corr-cancel-finalize-replay",
                )
                == expected
            )
            attempt_state = (
                await db.execute(
                    text("""SELECT state FROM ai_job_attempts
                      WHERE job_id=:job AND fencing_token=:token"""),
                    {"job": command.command_id, "token": token},
                )
            ).scalar_one()
            assert attempt_state == "cancelled"

            recovery = queued_while_cancelling
            recovery_claim = await ai_jobs.claim(
                db,
                worker_id,
                30,
                "corr-cancel-recovery-claim",
                organization_id=tenant,
                workspace_id=workspace,
                service_id="qwen-polling-worker",
            )
            assert recovery_claim is not None
            assert (
                await ai_orchestration.cancel(
                    db,
                    recovery.command_id,
                    tenant,
                    workspace,
                    "synthetic-user",
                    "corr-cancel-recovery-request",
                )
                == "CANCEL_REQUESTED"
            )
            await db.execute(
                text("""UPDATE ai_generation_jobs SET lease_expires_at=now()-interval '1 second'
                  WHERE id=:job"""),
                {"job": recovery.command_id},
            )
            await db.commit()
            assert await ai_jobs.recover_expired(db, tenant, workspace) == {
                "retried": 0,
                "dead_lettered": 0,
            }
            recovered = (
                (
                    await db.execute(
                        text("""SELECT state,lease_owner,lease_expires_at
                      FROM ai_generation_jobs WHERE id=:job"""),
                        {"job": recovery.command_id},
                    )
                )
                .mappings()
                .one()
            )
            assert dict(recovered) == {
                "state": "cancelled",
                "lease_owner": None,
                "lease_expires_at": None,
            }
            assert (
                await db.execute(
                    text("SELECT count(*) FROM ai_job_results WHERE job_id=:job"),
                    {"job": recovery.command_id},
                )
            ).scalar_one() == 0
    finally:
        await engine.dispose()
