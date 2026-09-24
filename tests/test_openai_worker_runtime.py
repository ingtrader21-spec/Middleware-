from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import ai_orchestration
from app.core.ai_contracts import AICommand, CommandType, ModelPolicy, ResourceLimits
from app.workers import openai_jobs


pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ,
    reason="disposable PostgreSQL required",
)


@pytest.mark.asyncio
async def test_registration_validation_and_post_claim_failure_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    tenant, workspace, command_id = uuid4(), uuid4(), uuid4()
    command = AICommand(
        command_id=command_id,
        command_type=CommandType.CHAT,
        schema_version="1.0",
        tenant_id=tenant,
        actor_id="synthetic-openai-runtime-test",
        actor_type="user",
        correlation_id="corr-openai-runtime-test",
        idempotency_key="openai-runtime-test-idempotency",
        requested_at=now,
        deadline_at=now + timedelta(minutes=5),
        input={"text": "synthetic"},
        model_policy=ModelPolicy(profile="fast-chat", max_tokens=16),
        resource_limits=ResourceLimits(retry_count=0, token_budget=32),
        data_classification="synthetic",
    )
    monkeypatch.setattr(openai_jobs.settings, "openai_provider_enabled", True)
    monkeypatch.setattr(openai_jobs.settings, "openai_worker_max_concurrency", 1)
    monkeypatch.setattr(openai_jobs.settings, "openai_worker_id", "codestra-openai-01")
    monkeypatch.setattr(
        openai_jobs.settings,
        "openai_worker_service_id",
        "openai-responses-provider",
    )

    try:
        async with sessions() as db:
            await db.execute(
                text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
                  ai_job_approvals,ai_usage_ledger,ai_worker_registrations,
                  ai_audit_events,ai_worker_heartbeats,ai_job_attempts,
                  ai_job_chunks,ai_generation_jobs,ai_messages,
                  ai_conversations CASCADE""")
            )
            await db.commit()
            with pytest.raises(RuntimeError, match="registration_invalid"):
                await openai_jobs.validate_worker_registration(db)
            await db.execute(
                text("""INSERT INTO ai_worker_registrations
                  (worker_id,service_id,capability_digest,capabilities,
                   max_concurrency,enabled)
                  VALUES('codestra-openai-01','openai-responses-provider',
                  :digest,'{}'::jsonb,2,true)"""),
                {"digest": "a" * 64},
            )
            await db.commit()
            with pytest.raises(RuntimeError, match="registration_invalid"):
                await openai_jobs.validate_worker_registration(db)
            await db.execute(
                text("""UPDATE ai_worker_registrations
                  SET max_concurrency=1 WHERE worker_id='codestra-openai-01'""")
            )
            await db.commit()
            await openai_jobs.validate_worker_registration(db)
            await ai_orchestration.submit(db, command, workspace)

        async def fail_after_claim(*_args: object, **_kwargs: object) -> str:
            raise ValueError("synthetic post-claim failure")

        monkeypatch.setattr(openai_jobs, "process_job", fail_after_claim)
        result = await openai_jobs.cycle(object(), sessions)  # type: ignore[arg-type]
        assert result == "dead_letter"
        async with sessions() as db:
            row = (
                await db.execute(
                    text("""SELECT state,lease_owner,lease_expires_at,failure_code,
                      (SELECT count(*) FROM ai_job_attempts WHERE job_id=:job) attempts,
                      (SELECT count(*) FROM ai_job_chunks WHERE job_id=:job) chunks
                      FROM ai_generation_jobs WHERE id=:job"""),
                    {"job": command_id},
                )
            ).mappings().one()
            assert row["state"] == "dead_letter"
            assert row["lease_owner"] is None and row["lease_expires_at"] is None
            assert row["failure_code"] == "provider_worker_error"
            assert row["attempts"] == 1
            assert row["chunks"] == 0
        assert await openai_jobs.cycle(object(), sessions) == "empty"  # type: ignore[arg-type]
    finally:
        await engine.dispose()
