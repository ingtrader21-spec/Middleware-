from __future__ import annotations

import asyncio
import hashlib
import os
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core import tts_jobs

pytestmark = pytest.mark.skipif(
    "DATABASE_URL" not in os.environ, reason="disposable PostgreSQL required"
)


@pytest.mark.asyncio
async def test_durable_tts_claim_idempotency_recovery_and_isolation() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    org, workspace, other_org = uuid4(), uuid4(), uuid4()
    digest = hashlib.sha256(b"synthetic request without content").hexdigest()

    async def submit(
        db: AsyncSession,
        *,
        organization_id: UUID = org,
        request_sha256: str = digest,
    ) -> dict[str, Any]:
        return await tts_jobs.submit(
            db,
            organization_id=organization_id,
            workspace_id=workspace,
            requested_by="synthetic-user",
            project_key="codestra-ai-console",
            voice_alias="browser_preview",
            model_alias="flash",
            output_profile="browser_preview",
            idempotency_key="synthetic-idempotency-key",
            correlation_id="synthetic-correlation",
            request_sha256=request_sha256,
            character_count=32,
        )

    try:
        async with sessions() as db:
            await db.execute(text("TRUNCATE tts_generation_jobs"))
            await db.commit()
            first = await submit(db)
            replay = await submit(db)
            assert (
                first["id"] == replay["id"]
                and first["created"]
                and not replay["created"]
            )
            with pytest.raises(ValueError, match="tts_idempotency_conflict"):
                await submit(
                    db, request_sha256=hashlib.sha256(b"different").hexdigest()
                )
        async with sessions() as one, sessions() as two:
            claimed = await asyncio.gather(
                tts_jobs.claim(one, "worker-one", 60),
                tts_jobs.claim(two, "worker-two", 60),
            )
            assert sum(item is not None for item in claimed) == 1
            original = next(item for item in claimed if item)
        async with sessions() as db:
            await tts_jobs.mark_provider_started(
                db, original["id"], original["lease_owner"], original["fencing_token"]
            )
            await tts_jobs.record_chunk(
                db,
                original["id"],
                original["lease_owner"],
                original["fencing_token"],
                128,
            )
            assert await tts_jobs.complete(
                db, original["id"], original["lease_owner"], original["fencing_token"]
            )
            assert not await tts_jobs.complete(
                db, original["id"], original["lease_owner"], original["fencing_token"]
            )
            with pytest.raises(LookupError):
                await tts_jobs.status(
                    db, original["id"], other_org, workspace, "synthetic-user"
                )
            state = await tts_jobs.status(
                db, original["id"], org, workspace, "synthetic-user"
            )
            assert (
                state["state"] == "completed"
                and state["chunk_count"] == 1
                and state["audio_bytes"] == 128
            )
            distinct = await submit(db, organization_id=other_org)
            assert distinct["id"] != first["id"]
            assert (
                await tts_jobs.cancel(
                    db, distinct["id"], other_org, workspace, "synthetic-user"
                )
                == "cancelled"
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_tts_leases_requeue_only_before_provider_start() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    org, workspace = uuid4(), uuid4()
    try:
        async with sessions() as db:
            await db.execute(text("TRUNCATE tts_generation_jobs"))
            await db.commit()
            job = await tts_jobs.submit(
                db,
                organization_id=org,
                workspace_id=workspace,
                requested_by="synthetic-user",
                project_key="codestra-ai-console",
                voice_alias="browser_preview",
                model_alias="flash",
                output_profile="browser_preview",
                idempotency_key="lease-recovery",
                correlation_id="lease-recovery",
                request_sha256=hashlib.sha256(b"lease-recovery").hexdigest(),
                character_count=10,
            )
            before = await tts_jobs.claim(db, "worker", 60)
            assert before
            await db.execute(
                text(
                    "UPDATE tts_generation_jobs SET lease_expires_at=now()-interval '1 second' WHERE id=:id"
                ),
                {"id": before["id"]},
            )
            await db.commit()
            assert (await tts_jobs.recover_expired(db))["requeued"] == 1
            after = await tts_jobs.claim_exact(db, job["id"], "worker", 60)
            assert after
            await tts_jobs.mark_provider_started(
                db, after["id"], "worker", after["fencing_token"]
            )
            await db.execute(
                text(
                    "UPDATE tts_generation_jobs SET lease_expires_at=now()-interval '1 second' WHERE id=:id"
                ),
                {"id": after["id"]},
            )
            await db.commit()
            assert (await tts_jobs.recover_expired(db))["ambiguous"] == 1
            state = await tts_jobs.status(
                db, after["id"], org, workspace, "synthetic-user"
            )
            assert state["state"] == "ambiguous_provider_outcome"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_cancellation_ambiguity_and_committed_queue_metrics() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    org, workspace, wrong_org = uuid4(), uuid4(), uuid4()

    async def submit(db, suffix: str):
        return await tts_jobs.submit(
            db,
            organization_id=org,
            workspace_id=workspace,
            requested_by="synthetic-user",
            project_key="codestra-ai-console",
            voice_alias="browser_preview",
            model_alias="flash",
            output_profile="browser_preview",
            idempotency_key=f"cancel-{suffix}",
            correlation_id=f"cancel-{suffix}",
            request_sha256=hashlib.sha256(suffix.encode()).hexdigest(),
            character_count=10,
        )

    try:
        async with sessions() as db:
            await db.execute(text("TRUNCATE tts_generation_jobs"))
            await db.commit()
            before_claim = await submit(db, "before-claim")
            assert (
                await tts_jobs.cancel(
                    db, before_claim["id"], org, workspace, "synthetic-user"
                )
                == "cancelled"
            )
            assert (
                await tts_jobs.claim_exact(db, before_claim["id"], "worker", 60) is None
            )

            before_provider = await submit(db, "before-provider")
            claimed = await tts_jobs.claim_exact(
                db, before_provider["id"], "worker", 60
            )
            assert claimed
            with pytest.raises(LookupError):
                await tts_jobs.cancel(
                    db,
                    before_provider["id"],
                    wrong_org,
                    workspace,
                    "synthetic-user",
                )
            assert (
                await tts_jobs.cancel(
                    db, before_provider["id"], org, workspace, "synthetic-user"
                )
                == "cancelled"
            )

            during_stream = await submit(db, "during-stream")
            claimed = await tts_jobs.claim_exact(db, during_stream["id"], "worker", 60)
            assert claimed
            await tts_jobs.mark_provider_started(
                db, claimed["id"], "worker", claimed["fencing_token"]
            )
            await tts_jobs.record_chunk(
                db, claimed["id"], "worker", claimed["fencing_token"], 64
            )
            assert await tts_jobs.mark_cancelled_streaming(
                db, claimed["id"], "worker", claimed["fencing_token"]
            )

            zero_chunk = await submit(db, "zero-chunk")
            claimed = await tts_jobs.claim_exact(db, zero_chunk["id"], "worker", 60)
            assert claimed
            await tts_jobs.mark_provider_started(
                db, claimed["id"], "worker", claimed["fencing_token"]
            )
            assert await tts_jobs.mark_ambiguous(
                db,
                claimed["id"],
                "worker",
                claimed["fencing_token"],
                "tts_empty_stream",
            )

            counts = (
                (
                    await db.execute(
                        text(
                            """SELECT
                        count(*) FILTER (WHERE state='queued') AS queued,
                        count(*) FILTER (WHERE state IN
                          ('claimed','provider_starting','streaming')) AS active
                        FROM tts_generation_jobs
                        WHERE organization_id=:org AND workspace_id=:workspace"""
                        ),
                        {"org": org, "workspace": workspace},
                    )
                )
                .mappings()
                .one()
            )
            assert counts["queued"] == 0
            assert counts["active"] == 0
    finally:
        await engine.dispose()
