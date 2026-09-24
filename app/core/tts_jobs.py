"""PostgreSQL-fenced, content-free durable TTS job state."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def submit(
    db: AsyncSession,
    *,
    organization_id: UUID,
    workspace_id: UUID,
    requested_by: str,
    project_key: str,
    voice_alias: str,
    model_alias: str,
    output_profile: str,
    idempotency_key: str,
    correlation_id: str,
    request_sha256: str,
    character_count: int,
) -> dict[str, Any]:
    job_id = uuid4()
    row = (
        (
            await db.execute(
                text("""INSERT INTO tts_generation_jobs
      (id,organization_id,workspace_id,requested_by,project_key,voice_alias,model_alias,
       output_profile,idempotency_key,correlation_id,request_sha256,character_count)
      VALUES(:id,:org,:workspace,:user,:project,:voice,:model,:profile,:key,:correlation,:digest,:characters)
      ON CONFLICT(organization_id,workspace_id,project_key,requested_by,idempotency_key)
      DO UPDATE SET updated_at=tts_generation_jobs.updated_at
      RETURNING id,state,request_sha256,(id=:id) created"""),
                {
                    "id": job_id,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "user": requested_by,
                    "project": project_key,
                    "voice": voice_alias,
                    "model": model_alias,
                    "profile": output_profile,
                    "key": idempotency_key,
                    "correlation": correlation_id,
                    "digest": request_sha256,
                    "characters": character_count,
                },
            )
        )
        .mappings()
        .one()
    )
    await db.commit()
    if row["request_sha256"] != request_sha256:
        raise ValueError("tts_idempotency_conflict")
    return dict(row)


async def claim(
    db: AsyncSession, worker_id: str, lease_seconds: int
) -> dict[str, Any] | None:
    row = (
        (
            await db.execute(
                text("""WITH candidate AS (
      SELECT id FROM tts_generation_jobs WHERE state='queued' AND cancellation_at IS NULL
      ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
      UPDATE tts_generation_jobs j SET state='claimed',lease_owner=:worker,
        lease_expires_at=now()+make_interval(secs=>:lease),attempt_count=attempt_count+1,
        fencing_token=fencing_token+1,updated_at=now()
      FROM candidate WHERE j.id=candidate.id RETURNING j.*"""),
                {"worker": worker_id, "lease": lease_seconds},
            )
        )
        .mappings()
        .first()
    )
    await db.commit()
    return dict(row) if row else None


async def claim_exact(
    db: AsyncSession, job_id: UUID, worker_id: str, lease_seconds: int
) -> dict[str, Any] | None:
    row = (
        (
            await db.execute(
                text("""UPDATE tts_generation_jobs SET state='claimed',
      lease_owner=:worker,lease_expires_at=now()+make_interval(secs=>:lease),
      attempt_count=attempt_count+1,fencing_token=fencing_token+1,updated_at=now()
      WHERE id=:job AND state='queued' AND cancellation_at IS NULL RETURNING *"""),
                {"job": job_id, "worker": worker_id, "lease": lease_seconds},
            )
        )
        .mappings()
        .first()
    )
    await db.commit()
    return dict(row) if row else None


async def mark_provider_started(
    db: AsyncSession, job_id: UUID, worker_id: str, fencing_token: int
) -> None:
    row = (
        await db.execute(
            text("""UPDATE tts_generation_jobs
      SET state='provider_starting',provider_request_started_at=now(),updated_at=now()
      WHERE id=:job AND state='claimed' AND lease_owner=:worker AND fencing_token=:token
        AND lease_expires_at>now() AND cancellation_at IS NULL RETURNING id"""),
            {"job": job_id, "worker": worker_id, "token": fencing_token},
        )
    ).scalar_one_or_none()
    await db.commit()
    if row is None:
        raise PermissionError("tts_stale_or_cancelled_lease")


async def record_chunk(
    db: AsyncSession, job_id: UUID, worker_id: str, fencing_token: int, size: int
) -> None:
    row = (
        await db.execute(
            text("""UPDATE tts_generation_jobs SET state='streaming',
      first_chunk_at=COALESCE(first_chunk_at,now()),chunk_count=chunk_count+1,
      audio_bytes=audio_bytes+:size,lease_expires_at=now()+interval '60 seconds',updated_at=now()
      WHERE id=:job AND state IN ('provider_starting','streaming') AND lease_owner=:worker
        AND fencing_token=:token AND lease_expires_at>now() AND cancellation_at IS NULL RETURNING id"""),
            {"job": job_id, "worker": worker_id, "token": fencing_token, "size": size},
        )
    ).scalar_one_or_none()
    await db.commit()
    if row is None:
        raise PermissionError("tts_stale_or_cancelled_lease")


async def complete(
    db: AsyncSession, job_id: UUID, worker_id: str, fencing_token: int
) -> bool:
    row = (
        await db.execute(
            text("""UPDATE tts_generation_jobs SET state='completed',
      completed_at=now(),lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
      WHERE id=:job AND state='streaming' AND lease_owner=:worker AND fencing_token=:token
        AND first_chunk_at IS NOT NULL AND cancellation_at IS NULL RETURNING id"""),
            {"job": job_id, "worker": worker_id, "token": fencing_token},
        )
    ).scalar_one_or_none()
    await db.commit()
    return row is not None


async def mark_ambiguous(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    failure_class: str,
) -> bool:
    row = (
        await db.execute(
            text(
                """UPDATE tts_generation_jobs
      SET state='ambiguous_provider_outcome', failure_class=:failure,
        lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
      WHERE id=:job AND state IN ('provider_starting','streaming')
        AND lease_owner=:worker AND fencing_token=:token RETURNING id"""
            ),
            {
                "job": job_id,
                "worker": worker_id,
                "token": fencing_token,
                "failure": failure_class[:128],
            },
        )
    ).scalar_one_or_none()
    await db.commit()
    return row is not None


async def mark_cancelled_streaming(
    db: AsyncSession, job_id: UUID, worker_id: str, fencing_token: int
) -> bool:
    row = (
        await db.execute(
            text(
                """UPDATE tts_generation_jobs
      SET state='cancelled', cancellation_at=COALESCE(cancellation_at,now()),
        lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
      WHERE id=:job AND state IN ('provider_starting','streaming')
        AND lease_owner=:worker AND fencing_token=:token RETURNING id"""
            ),
            {"job": job_id, "worker": worker_id, "token": fencing_token},
        )
    ).scalar_one_or_none()
    await db.commit()
    return row is not None


async def cancel(
    db: AsyncSession,
    job_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
    requested_by: str,
) -> str:
    row = (
        await db.execute(
            text("""UPDATE tts_generation_jobs SET cancellation_at=now(),
      state='cancelled', lease_owner=NULL, lease_expires_at=NULL,
      updated_at=now() WHERE id=:job AND organization_id=:org AND workspace_id=:workspace
      AND requested_by=:user
      AND state NOT IN ('completed','failed','cancelled','ambiguous_provider_outcome') RETURNING state"""),
            {
                "job": job_id,
                "org": organization_id,
                "workspace": workspace_id,
                "user": requested_by,
            },
        )
    ).scalar_one_or_none()
    await db.commit()
    if row is None:
        raise LookupError("tts_job_not_found_or_terminal")
    return str(row)


async def recover_expired(db: AsyncSession) -> dict[str, int]:
    safe = await db.execute(
        text("""UPDATE tts_generation_jobs SET state='queued',
      lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
      WHERE state='claimed' AND lease_expires_at<=now() AND provider_request_started_at IS NULL
        AND cancellation_at IS NULL RETURNING id""")
    )
    ambiguous = await db.execute(
        text("""UPDATE tts_generation_jobs
      SET state='ambiguous_provider_outcome',lease_owner=NULL,lease_expires_at=NULL,
        failure_class='TTS_AMBIGUOUS_PROVIDER_OUTCOME',updated_at=now()
      WHERE state IN ('provider_starting','streaming') AND lease_expires_at<=now()
      RETURNING id""")
    )
    await db.commit()
    return {"requeued": len(safe.fetchall()), "ambiguous": len(ambiguous.fetchall())}


async def status(
    db: AsyncSession,
    job_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
    requested_by: str,
) -> dict[str, Any]:
    row = (
        (
            await db.execute(
                text("""SELECT id,state,attempt_count,chunk_count,audio_bytes,
      failure_class,created_at,provider_request_started_at,first_chunk_at,completed_at,cancellation_at
      FROM tts_generation_jobs WHERE id=:job AND organization_id=:org
        AND workspace_id=:workspace AND requested_by=:user"""),
                {
                    "job": job_id,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "user": requested_by,
                },
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise LookupError("tts_job_not_found")
    return dict(row)
