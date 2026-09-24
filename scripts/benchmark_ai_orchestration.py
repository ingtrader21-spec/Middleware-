#!/usr/bin/env python3
"""Bounded disposable-database benchmark for the AI job authority."""

from __future__ import annotations

import asyncio
import os
import statistics
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import ai_jobs, ai_orchestration
from app.core.ai_contracts import AICommand


async def main() -> None:
    url = os.environ.get("DATABASE_URL", "")
    if "fixture" not in url and "test" not in url:
        raise SystemExit("disposable test database is required")
    engine = create_async_engine(url, poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant, workspace = uuid4(), uuid4()
    enqueue_latencies: list[float] = []
    async with sessions() as db:
        await db.execute(text("""TRUNCATE ai_job_results,ai_job_events,ai_job_dead_letters,
          ai_job_approvals,ai_usage_ledger,ai_worker_registrations,ai_audit_events,
          ai_worker_heartbeats,ai_job_attempts,ai_job_chunks,ai_generation_jobs,
          ai_messages,ai_conversations,ai_service_nonces,ai_tenant_quotas CASCADE"""))
        await db.execute(text("""INSERT INTO ai_tenant_quotas
          (organization_id,workspace_id,max_queued,max_running,daily_tokens,daily_compute_units)
          VALUES(:tenant,:workspace,500,30,1000000,1000000)"""),
          {"tenant": tenant, "workspace": workspace})
        await db.commit()
        for number in range(200):
            now = datetime.now(timezone.utc)
            command = AICommand.model_validate({
                "command_id": uuid4(), "command_type": "ai.chat.v1", "schema_version": "1.0",
                "tenant_id": tenant, "actor_id": "benchmark-fixture", "actor_type": "service",
                "correlation_id": f"benchmark-{number:08d}",
                "idempotency_key": f"benchmark-fixture-key-{number:08d}", "priority": 5,
                "requested_at": now, "deadline_at": now + timedelta(minutes=5),
                "input": {"text": "synthetic example.invalid benchmark"},
                "model_policy": {"profile": "fast-chat"},
                "resource_limits": {"token_budget": 100}, "data_classification": "synthetic",
                "approval_policy": {"required": False}, "callback_policy": {"mode": "poll"},
                "metadata": {"fixture": "benchmark"},
            })
            started = time.monotonic()
            await ai_orchestration.submit(db, command, workspace)
            enqueue_latencies.append((time.monotonic() - started) * 1000)

    semaphore = asyncio.Semaphore(20)

    async def claim(number: int):
        async with semaphore:
            async with sessions() as db:
                started = time.monotonic()
                item = await ai_jobs.claim(db, f"benchmark-worker-{number}", 30, f"claim-{number:08d}")
                return item, (time.monotonic() - started) * 1000

    started = time.monotonic()
    claimed = await asyncio.gather(*(claim(number) for number in range(200)))
    duration = time.monotonic() - started
    ids = [item[0]["id"] for item in claimed if item[0]]
    claim_latencies = [item[1] for item in claimed]
    print(f"ENQUEUE_P50_MS={statistics.median(enqueue_latencies):.3f}")
    print(f"ENQUEUE_P95_MS={sorted(enqueue_latencies)[189]:.3f}")
    print(f"CLAIM_P50_MS={statistics.median(claim_latencies):.3f}")
    print(f"CLAIM_P95_MS={sorted(claim_latencies)[189]:.3f}")
    print(f"CLAIM_THROUGHPUT_PER_SECOND={len(ids) / duration:.3f}")
    print(f"CLAIMED={len(ids)}")
    print(f"DUPLICATE_CLAIMS={len(ids) - len(set(ids))}")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
