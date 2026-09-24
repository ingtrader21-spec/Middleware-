"""Transactional AI job repository with leases and fencing tokens."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai_contracts import AICommand, ApprovalPolicy, CommandType, ModelPolicy
from app.core.ai_contracts import ResourceLimits

SAFE_ERROR_DETAIL_FIELDS = frozenset(
    {
        "category",
        "component",
        "http_status",
        "model_profile",
        "operation",
        "provider",
        "timeout_seconds",
    }
)

WORKER_HARD_SAFETY_CAP = 2
MODEL_RUNTIME_CLASSES = {
    "fast-chat": "chat-light",
    "crm-analysis": "chat-light",
    "coding-default": "coding-fallback",
    "quality-chat": "single-admission",
    "coding-large": "single-admission",
    "voice-summary": "single-admission",
    "embedding-default": "unavailable",
}

BROWSER_CAPABILITY_PROFILES = {
    "chat": "fast-chat",
    "coding": "coding-default",
}

BROWSER_CAPABILITY_COMMAND_TYPES = {
    "chat": CommandType.CHAT,
    "coding": CommandType.CODING,
}

BROWSER_CAPABILITY_MAX_TOKENS = {
    "chat": 2048,
    "coding": 4096,
}


def resolve_browser_model_profile(task_type: str) -> str:
    """Resolve an unprivileged browser capability to a governed worker profile."""
    model_profile = BROWSER_CAPABILITY_PROFILES.get(task_type)
    if model_profile is None or model_profile not in MODEL_RUNTIME_CLASSES:
        raise ValueError("unsupported_browser_capability")
    return model_profile


def build_browser_worker_contract(
    *,
    job_id: UUID,
    conversation_id: UUID,
    organization_id: UUID,
    user_id: str,
    content: str,
    task_type: str,
    project_key: str | None,
    idempotency_key: str,
    correlation_id: str,
    max_attempts: int,
) -> AICommand:
    """Build the complete worker contract from server-authoritative policy."""
    model_profile = resolve_browser_model_profile(task_type)
    command_type = BROWSER_CAPABILITY_COMMAND_TYPES.get(task_type)
    max_tokens = BROWSER_CAPABILITY_MAX_TOKENS.get(task_type)
    if command_type is None or max_tokens is None:
        raise ValueError("unsupported_browser_capability")
    requested_at = datetime.now(timezone.utc)
    command_input = {"text": content}
    if project_key is not None:
        command_input["project_key"] = project_key
    return AICommand(
        command_id=job_id,
        command_type=command_type,
        schema_version="1.0",
        tenant_id=organization_id,
        actor_id=user_id,
        actor_type="user",
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        priority=5,
        requested_at=requested_at,
        deadline_at=requested_at + timedelta(minutes=10),
        input=command_input,
        model_policy=ModelPolicy.model_validate(
            {"profile": model_profile, "max_tokens": max_tokens}
        ),
        resource_limits=ResourceLimits(
            runtime_seconds=300,
            output_bytes=262_144,
            retry_count=max_attempts - 1,
            token_budget=max_tokens * 2,
        ),
        data_classification="internal",
        approval_policy=ApprovalPolicy(required=False),
        metadata={
            "source": "ai-console",
            "conversation_id": str(conversation_id),
            "capability": task_type,
        },
    )


RUNTIME_CLASS_COMPATIBILITY = {
    "chat-light": frozenset({"chat-light"}),
    "coding-fallback": frozenset({"coding-fallback"}),
    "single-admission": frozenset(),
    "unavailable": frozenset(),
}


def compatible_profiles(active_profiles: list[str | None]) -> frozenset[str]:
    """Return the server-authoritative profiles permitted beside active leases."""
    if not active_profiles:
        return frozenset(MODEL_RUNTIME_CLASSES)
    active_classes = {
        MODEL_RUNTIME_CLASSES.get(profile or "") for profile in active_profiles
    }
    if None in active_classes or len(active_classes) != 1:
        return frozenset()
    active_class = next(iter(active_classes))
    if active_class is None:
        return frozenset()
    compatible_classes = RUNTIME_CLASS_COMPATIBILITY.get(active_class, frozenset())
    return frozenset(
        profile
        for profile, runtime_class in MODEL_RUNTIME_CLASSES.items()
        if runtime_class in compatible_classes
    )


def effective_compatible_profiles(
    active_profiles: list[str | None], requested_profiles: list[str] | None
) -> frozenset[str]:
    """Intersect the server policy with an optional client restriction."""
    server_allowed = compatible_profiles(active_profiles)
    if requested_profiles is None:
        return server_allowed
    return server_allowed & frozenset(requested_profiles)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def audit(
    db: AsyncSession,
    event_type: str,
    correlation_id: str,
    actor: str,
    *,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
    job_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    await db.execute(
        text("""
        INSERT INTO ai_audit_events
          (id, organization_id, workspace_id, job_id, actor_fingerprint,
           event_type, correlation_id, safe_details)
        VALUES (:id, :org, :workspace, :job, :actor, :event, :correlation,
                CAST(:details AS jsonb))
    """),
        {
            "id": uuid4(),
            "org": organization_id,
            "workspace": workspace_id,
            "job": job_id,
            "actor": fingerprint(actor),
            "event": event_type,
            "correlation": correlation_id,
            "details": __import__("json").dumps(details or {}),
        },
    )


async def create_conversation(
    db: AsyncSession,
    organization_id: UUID,
    workspace_id: UUID,
    user_id: str,
    title: str,
    correlation_id: str,
) -> dict[str, Any]:
    conversation_id = uuid4()
    await db.execute(
        text("""
        INSERT INTO ai_conversations
          (id, organization_id, workspace_id, created_by, title)
        VALUES (:id, :org, :workspace, :user, :title)
    """),
        {
            "id": conversation_id,
            "org": organization_id,
            "workspace": workspace_id,
            "user": user_id,
            "title": title,
        },
    )
    await audit(
        db,
        "conversation.created",
        correlation_id,
        user_id,
        organization_id=organization_id,
        workspace_id=workspace_id,
        details={"conversation_id": str(conversation_id)},
    )
    await db.commit()
    return {"conversation_id": conversation_id, "status": "active"}


async def create_message_job(
    db: AsyncSession,
    *,
    conversation_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
    user_id: str,
    content: str,
    task_type: str,
    project_key: str | None,
    idempotency_key: str,
    correlation_id: str,
    max_attempts: int,
) -> dict[str, Any]:
    model_profile = resolve_browser_model_profile(task_type)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": (f"ai-job:{organization_id}:{workspace_id}:{idempotency_key}")},
    )
    request_hash = hashlib.sha256(
        f"{conversation_id}\0{task_type}\0{project_key or ''}\0{content}".encode()
    ).hexdigest()
    existing = (
        (
            await db.execute(
                text("""
        SELECT id, request_message_id, request_sha256, state
        FROM ai_generation_jobs
        WHERE organization_id=:org AND workspace_id=:workspace
          AND idempotency_key=:key
    """),
                {
                    "org": organization_id,
                    "workspace": workspace_id,
                    "key": idempotency_key,
                },
            )
        )
        .mappings()
        .first()
    )
    if existing:
        if existing["request_sha256"] != request_hash:
            raise ValueError("idempotency_conflict")
        return {
            "job_id": existing["id"],
            "message_id": existing["request_message_id"],
            "state": existing["state"],
            "idempotent_replay": True,
        }
    owns = (
        await db.execute(
            text("""
        SELECT 1 FROM ai_conversations WHERE id=:conversation AND organization_id=:org
          AND workspace_id=:workspace AND status='active'
    """),
            {
                "conversation": conversation_id,
                "org": organization_id,
                "workspace": workspace_id,
            },
        )
    ).scalar_one_or_none()
    if not owns:
        raise LookupError("conversation_not_found")
    message_id, job_id = uuid4(), uuid4()
    command = build_browser_worker_contract(
        job_id=job_id,
        conversation_id=conversation_id,
        organization_id=organization_id,
        user_id=user_id,
        content=content,
        task_type=task_type,
        project_key=project_key,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        max_attempts=max_attempts,
    )
    command_payload = command.model_dump(mode="json")
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    await db.execute(
        text("""
        INSERT INTO ai_messages
          (id, conversation_id, organization_id, workspace_id, role, content, content_sha256)
        VALUES (:id, :conversation, :org, :workspace, 'user', :content, :hash)
    """),
        {
            "id": message_id,
            "conversation": conversation_id,
            "org": organization_id,
            "workspace": workspace_id,
            "content": content,
            "hash": content_hash,
        },
    )
    await db.execute(
        text("""
        INSERT INTO ai_generation_jobs
          (id, conversation_id, request_message_id, organization_id, workspace_id,
           requested_by, task_type, model_profile, project_key, idempotency_key,
           request_sha256, max_attempts, command_type, schema_version, actor_id,
           actor_type, correlation_id, priority, deadline_at, command_payload,
           resource_limits, data_classification, approval_policy, callback_policy,
           command_metadata)
        VALUES (:id, :conversation, :message, :org, :workspace, :user, :task,
                :model_profile, :project, :key, :hash, :max_attempts,
                :command_type, :schema_version, :actor_id, :actor_type,
                :correlation_id, :priority, :deadline_at, CAST(:command_payload AS jsonb),
                CAST(:resource_limits AS jsonb), :data_classification,
                CAST(:approval_policy AS jsonb), CAST(:callback_policy AS jsonb),
                CAST(:command_metadata AS jsonb))
    """),
        {
            "id": job_id,
            "conversation": conversation_id,
            "message": message_id,
            "org": organization_id,
            "workspace": workspace_id,
            "user": user_id,
            "task": task_type,
            "model_profile": model_profile,
            "project": project_key,
            "key": idempotency_key,
            "hash": request_hash,
            "max_attempts": max_attempts,
            "command_type": command.command_type.value,
            "schema_version": command.schema_version,
            "actor_id": command.actor_id,
            "actor_type": command.actor_type,
            "correlation_id": command.correlation_id,
            "priority": command.priority,
            "deadline_at": command.deadline_at,
            "command_payload": json.dumps(command_payload),
            "resource_limits": json.dumps(
                command.resource_limits.model_dump(mode="json")
            ),
            "data_classification": command.data_classification,
            "approval_policy": json.dumps(
                command.approval_policy.model_dump(mode="json")
            ),
            "callback_policy": json.dumps(
                command.callback_policy.model_dump(mode="json")
            ),
            "command_metadata": json.dumps(command.metadata),
        },
    )
    await audit(
        db,
        "job.queued",
        correlation_id,
        user_id,
        organization_id=organization_id,
        workspace_id=workspace_id,
        job_id=job_id,
        details={"task_type": task_type, "model_profile": model_profile},
    )
    await db.commit()
    return {
        "job_id": job_id,
        "message_id": message_id,
        "state": "queued",
        "idempotent_replay": False,
    }


async def claim(
    db: AsyncSession,
    worker_id: str,
    lease_seconds: int,
    correlation_id: str,
    *,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
    service_id: str | None = None,
    allowed_model_profiles: list[str] | None = None,
) -> dict[str, Any] | None:
    if allowed_model_profiles is not None:
        if not allowed_model_profiles or not set(allowed_model_profiles).issubset(
            MODEL_RUNTIME_CLASSES
        ):
            raise ValueError("invalid_model_profile_filter")
    active_profiles: list[str | None] = []
    if service_id is not None:
        registration = (
            (
                await db.execute(
                    text("""
        SELECT max_concurrency FROM ai_worker_registrations
        WHERE worker_id=:worker AND service_id=:service AND enabled=true
        FOR UPDATE
    """),
                    {"worker": worker_id, "service": service_id},
                )
            )
            .mappings()
            .first()
        )
        if registration is None:
            raise PermissionError("worker_not_enabled")
        active_result = await db.execute(
            text("""
        SELECT model_profile FROM ai_generation_jobs
        WHERE state IN ('leased','cancel_requested') AND lease_owner=:worker
          AND lease_expires_at > now()
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
        ORDER BY created_at,id
    """),
            {
                "worker": worker_id,
                "org": organization_id,
                "workspace": workspace_id,
            },
        )
        active_profiles = list(active_result.scalars())
        effective_limit = min(registration["max_concurrency"], WORKER_HARD_SAFETY_CAP)
        if len(active_profiles) >= effective_limit:
            raise OverflowError("worker_concurrency_limit")
    effective_allowed_profiles = effective_compatible_profiles(
        active_profiles, allowed_model_profiles
    )
    if not effective_allowed_profiles:
        await audit(
            db,
            "job.claim.admission_rejected",
            correlation_id,
            worker_id,
            organization_id=organization_id,
            workspace_id=workspace_id,
            details={
                "active_model_profiles": sorted(
                    profile or "unknown" for profile in active_profiles
                ),
                "effective_allowed_profile_count": 0,
                "profile_filter_applied": allowed_model_profiles is not None,
                "concurrency_slot": len(active_profiles) + 1,
                "worker_id": worker_id,
            },
        )
        await db.commit()
        return None
    # Legacy/internal callers predate model profiles and may claim NULL-profile
    # jobs. Authenticated workers always provide service_id, so only they are
    # constrained by the runtime-admission profile set.
    profile_filter = (
        sorted(effective_allowed_profiles)
        if service_id is not None or allowed_model_profiles is not None
        else None
    )
    row = (
        (
            await db.execute(
                text("""
        WITH candidate AS (
          SELECT id FROM ai_generation_jobs
          WHERE state IN ('queued','retry_wait') AND next_attempt_at <= now()
            AND (model_profile IS NULL OR model_profile IN
              ('fast-chat','quality-chat','coding-default','coding-large',
               'crm-analysis','voice-summary','embedding-default'))
            AND (CAST(:profiles AS text[]) IS NULL OR model_profile = ANY(:profiles))
            AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
            AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
            AND cancel_requested_at IS NULL
            AND (deadline_at IS NULL OR deadline_at > now())
          ORDER BY priority,created_at FOR UPDATE SKIP LOCKED LIMIT 1
        )
        UPDATE ai_generation_jobs j SET state='leased', lease_owner=:worker,
          lease_expires_at=now() + make_interval(secs => :lease_seconds),
          fencing_token=fencing_token+1, attempt_count=attempt_count+1, updated_at=now()
        FROM candidate WHERE j.id=candidate.id
        RETURNING j.*
    """),
                {
                    "worker": worker_id,
                    "lease_seconds": lease_seconds,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "profiles": profile_filter,
                },
            )
        )
        .mappings()
        .first()
    )
    if not row:
        await db.commit()
        return None
    await db.execute(
        text("""
        INSERT INTO ai_job_attempts
          (id, job_id, attempt_number, fencing_token, worker_id, state)
        VALUES (:id,:job,:attempt,:token,:worker,'leased')
    """),
        {
            "id": uuid4(),
            "job": row["id"],
            "attempt": row["attempt_count"],
            "token": row["fencing_token"],
            "worker": worker_id,
        },
    )
    await audit(
        db,
        "job.claimed",
        correlation_id,
        worker_id,
        organization_id=row["organization_id"],
        workspace_id=row["workspace_id"],
        job_id=row["id"],
        details={
            "attempt": row["attempt_count"],
            "fencing_token": row["fencing_token"],
            "claimed_model_profile": row["model_profile"],
            "active_model_profiles": sorted(
                profile or "unknown" for profile in active_profiles
            ),
            "effective_compatibility_class": MODEL_RUNTIME_CLASSES.get(
                row["model_profile"], "unknown"
            ),
            "profile_filter_applied": allowed_model_profiles is not None,
            "effective_allowed_profile_count": len(effective_allowed_profiles),
            "concurrency_slot": len(active_profiles) + 1,
            "worker_id": worker_id,
        },
    )
    await db.commit()
    allowed = (
        "id",
        "conversation_id",
        "organization_id",
        "workspace_id",
        "task_type",
        "command_type",
        "schema_version",
        "project_key",
        "attempt_count",
        "fencing_token",
        "lease_expires_at",
        "deadline_at",
        "command_payload",
        "model_profile",
        "resource_limits",
        "data_classification",
        "approval_policy",
    )
    return {key: row[key] for key in allowed}


async def assert_lease(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    *,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
    allow_cancel_requested: bool = False,
) -> dict[str, Any]:
    row = (
        (
            await db.execute(
                text("""
        SELECT * FROM ai_generation_jobs WHERE id=:job
          AND (state='leased' OR (:allow_cancel_requested AND state='cancel_requested'))
          AND lease_owner=:worker AND fencing_token=:token AND lease_expires_at > now()
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
        FOR UPDATE
    """),
                {
                    "job": job_id,
                    "worker": worker_id,
                    "token": fencing_token,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "allow_cancel_requested": allow_cancel_requested,
                },
            )
        )
        .mappings()
        .first()
    )
    if not row:
        raise PermissionError("stale_or_invalid_lease")
    return dict(row)


async def heartbeat(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    lease_seconds: int,
    *,
    service_id: str,
    certificate_serial: str,
    spiffe_id: str,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
) -> datetime:
    await assert_lease(
        db,
        job_id,
        worker_id,
        fencing_token,
        organization_id=organization_id,
        workspace_id=workspace_id,
        allow_cancel_requested=True,
    )
    expires = datetime.now(timezone.utc)
    row = (
        (
            await db.execute(
                text("""
        UPDATE ai_generation_jobs SET lease_expires_at=now()+make_interval(secs=>:seconds),
          updated_at=now() WHERE id=:job RETURNING lease_expires_at
    """),
                {"seconds": lease_seconds, "job": job_id},
            )
        )
        .mappings()
        .one()
    )
    await db.execute(
        text("""
        INSERT INTO ai_worker_heartbeats(worker_id,service_id,certificate_serial,spiffe_id,last_seen_at,current_job_id)
        VALUES (:worker,:service,:serial,:spiffe,now(),:job)
        ON CONFLICT(worker_id) DO UPDATE SET service_id=:service,
          certificate_serial=:serial,spiffe_id=:spiffe,last_seen_at=now(),
          current_job_id=:job
    """),
        {
            "worker": worker_id,
            "service": service_id,
            "serial": certificate_serial,
            "spiffe": spiffe_id,
            "job": job_id,
        },
    )
    await db.commit()
    return row["lease_expires_at"] or expires


async def append_chunk(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    sequence: int,
    content: str,
    max_output_bytes: int,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
) -> bool:
    row = await assert_lease(
        db,
        job_id,
        worker_id,
        fencing_token,
        organization_id=organization_id,
        workspace_id=workspace_id,
    )
    size = len(content.encode())
    if row["output_bytes"] + size > max_output_bytes:
        raise OverflowError("output_limit_exceeded")
    result = await db.execute(
        text("""
        INSERT INTO ai_job_chunks(id,job_id,organization_id,workspace_id,sequence,
          fencing_token,content,content_sha256)
        VALUES (:id,:job,:org,:workspace,:sequence,:token,:content,:hash)
        ON CONFLICT(job_id,sequence) DO NOTHING
    """),
        {
            "id": uuid4(),
            "job": job_id,
            "org": row["organization_id"],
            "workspace": row["workspace_id"],
            "sequence": sequence,
            "token": fencing_token,
            "content": content,
            "hash": hashlib.sha256(content.encode()).hexdigest(),
        },
    )
    inserted = int(getattr(result, "rowcount", 0)) == 1
    if inserted:
        await db.execute(
            text(
                "UPDATE ai_generation_jobs SET output_bytes=output_bytes+:size,updated_at=now() WHERE id=:job"
            ),
            {"size": size, "job": job_id},
        )
    await db.commit()
    return inserted


async def finish(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    *,
    failed: bool,
    error_code: str | None,
    retryable: bool,
    correlation_id: str,
    completion_state: str = "completed",
    safe_error_details: Mapping[str, object] | None = None,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
) -> str:
    row = await assert_lease(
        db,
        job_id,
        worker_id,
        fencing_token,
        organization_id=organization_id,
        workspace_id=workspace_id,
        allow_cancel_requested=True,
    )
    if row["cancel_requested_at"] is not None:
        state = "cancelled"
    elif not failed:
        state = completion_state
    elif retryable and row["attempt_count"] < row["max_attempts"]:
        state = "retry_wait"
    elif failed:
        state = "dead_letter"
    else:
        state = "failed"
    delay = min(300, 2 ** min(row["attempt_count"], 8))
    await db.execute(
        text("""
        UPDATE ai_generation_jobs SET state=:state, lease_owner=NULL, lease_expires_at=NULL,
          next_attempt_at=CASE WHEN :state='retry_wait' THEN now()+make_interval(secs=>:delay) ELSE next_attempt_at END,
          failure_code=:error, completed_at=CASE WHEN :state IN ('completed','approval_required','cancelled','dead_letter','failed') THEN now() END,
          updated_at=now() WHERE id=:job
    """),
        {"state": state, "delay": delay, "error": error_code, "job": job_id},
    )
    await db.execute(
        text("""
        UPDATE ai_job_attempts SET state=:state,safe_error_code=:error,finished_at=now()
        WHERE job_id=:job AND fencing_token=:token
    """),
        {"state": state, "error": error_code, "job": job_id, "token": fencing_token},
    )
    if state == "dead_letter":
        details = json.dumps(sanitize_error_details(safe_error_details or {}))
        evidence_hash = hashlib.sha256(
            f"{job_id}\0{error_code or 'attempts_exhausted'}\0{row['attempt_count']}\0{details}".encode()
        ).hexdigest()
        await db.execute(
            text("""INSERT INTO ai_job_dead_letters
          (job_id,organization_id,workspace_id,safe_error_code,attempt_count,payload_sha256,
           final_error_code,max_attempts,safe_error_details,failed_at,task_id,tenant_id,
           correlation_id,evidence_hash,manual_retry_requires_new_approval)
          VALUES(:job,:org,:workspace,:error,:attempts,:hash,:error,:max_attempts,
          CAST(:details AS jsonb),now(),:job,:org,:correlation,:evidence,true)
          ON CONFLICT(job_id) DO UPDATE SET safe_error_code=:error,
          final_error_code=:error,attempt_count=:attempts,max_attempts=:max_attempts,
          safe_error_details=CAST(:details AS jsonb),failed_at=now(),
          correlation_id=:correlation,evidence_hash=:evidence,
          manual_retry_requires_new_approval=true,updated_at=now()"""),
            {
                "job": job_id,
                "org": row["organization_id"],
                "workspace": row["workspace_id"],
                "error": error_code or "attempts_exhausted",
                "attempts": row["attempt_count"],
                "max_attempts": row["max_attempts"],
                "hash": row["request_sha256"],
                "details": details,
                "correlation": correlation_id,
                "evidence": evidence_hash,
            },
        )
    await audit(
        db,
        f"job.{state}",
        correlation_id,
        worker_id,
        organization_id=row["organization_id"],
        workspace_id=row["workspace_id"],
        job_id=job_id,
        details={"safe_error_code": error_code or ""},
    )
    await db.commit()
    return state


def sanitize_error_details(details: Mapping[str, object]) -> dict[str, object]:
    """Retain only bounded, structured diagnostics that cannot carry raw errors."""
    safe: dict[str, object] = {}
    for key, value in details.items():
        normalized = key.lower()
        if normalized not in SAFE_ERROR_DETAIL_FIELDS:
            continue
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:/ -]{1,128}", value):
            safe[normalized] = value
        elif isinstance(value, (int, bool)):
            safe[normalized] = value
    return safe


async def completed_result_status(
    db: AsyncSession,
    job_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
    result: Any | None,
) -> dict[str, str] | None:
    row = (
        (
            await db.execute(
                text("""
      SELECT j.state,r.output_sha256 FROM ai_generation_jobs j
      LEFT JOIN ai_job_results r ON r.job_id=j.id
      WHERE j.id=:job AND j.organization_id=:org AND j.workspace_id=:workspace
    """),
                {"job": job_id, "org": organization_id, "workspace": workspace_id},
            )
        )
        .mappings()
        .first()
    )
    if not row or row["state"] not in ("completed", "approval_required"):
        return None
    if result is None or row["output_sha256"] is None:
        raise PermissionError("duplicate_result_rejected")
    submitted = hashlib.sha256(
        json.dumps(result.output, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if not hmac_compare(row["output_sha256"], submitted):
        raise PermissionError("duplicate_result_rejected")
    return {"state": row["state"], "duplicate": "true"}


def hmac_compare(left: str, right: str) -> bool:
    return __import__("hmac").compare_digest(left, right)


async def get_worker_job(
    db: AsyncSession,
    job_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
) -> dict[str, object]:
    row = (
        (
            await db.execute(
                text("""
      SELECT id,state,attempt_count,max_attempts,lease_expires_at,cancel_requested_at,
             correlation_id,model_profile,updated_at
      FROM ai_generation_jobs WHERE id=:job AND organization_id=:org
      AND workspace_id=:workspace
    """),
                {"job": job_id, "org": organization_id, "workspace": workspace_id},
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise LookupError("job_not_found")
    return dict(row)


async def worker_cancel(
    db: AsyncSession,
    job_id: UUID,
    worker_id: str,
    fencing_token: int,
    organization_id: UUID,
    workspace_id: UUID,
    correlation_id: str,
) -> dict[str, object]:
    try:
        row = await assert_lease(
            db,
            job_id,
            worker_id,
            fencing_token,
            organization_id=organization_id,
            workspace_id=workspace_id,
            allow_cancel_requested=True,
        )
    except PermissionError:
        already_cancelled = (
            await db.execute(
                text("""
          SELECT 1 FROM ai_generation_jobs j
          WHERE j.id=:job AND j.organization_id=:org AND j.workspace_id=:workspace
            AND j.state='cancelled' AND j.fencing_token=:token
            AND EXISTS (
              SELECT 1 FROM ai_job_attempts a
              WHERE a.job_id=j.id AND a.fencing_token=:token AND a.worker_id=:worker
            )
        """),
                {
                    "job": job_id,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "token": fencing_token,
                    "worker": worker_id,
                },
            )
        ).scalar_one_or_none()
        if already_cancelled:
            return {"cancel_requested": True, "state": "cancelled"}
        raise
    requested = row["cancel_requested_at"] is not None
    if requested:
        await db.execute(
            text("""UPDATE ai_generation_jobs SET state='cancelled',
          lease_owner=NULL,lease_expires_at=NULL,completed_at=now(),updated_at=now()
          WHERE id=:job"""),
            {"job": job_id},
        )
        await db.execute(
            text("""UPDATE ai_job_attempts SET state='cancelled',finished_at=now()
          WHERE job_id=:job AND fencing_token=:token AND worker_id=:worker"""),
            {"job": job_id, "token": fencing_token, "worker": worker_id},
        )
        await audit(
            db,
            "job.cancelled",
            correlation_id,
            worker_id,
            organization_id=organization_id,
            workspace_id=workspace_id,
            job_id=job_id,
        )
        await db.commit()
    return {
        "cancel_requested": requested,
        "state": "cancelled" if requested else row["state"],
    }


async def list_dead_letters(
    db: AsyncSession,
    organization_id: UUID,
    workspace_id: UUID,
) -> list[dict[str, object]]:
    rows = (
        (
            await db.execute(
                text("""
      SELECT job_id,task_id,tenant_id,workspace_id,final_error_code,attempt_count,
        max_attempts,safe_error_details,failed_at,correlation_id,evidence_hash,
        manual_retry_requires_new_approval,recovery_status
      FROM ai_job_dead_letters WHERE tenant_id=:org AND workspace_id=:workspace
      ORDER BY failed_at DESC LIMIT 100
    """),
                {"org": organization_id, "workspace": workspace_id},
            )
        )
        .mappings()
        .all()
    )
    return [dict(row) for row in rows]


async def retry_dead_letter(
    db: AsyncSession,
    job_id: UUID,
    approval_id: UUID,
    organization_id: UUID,
    workspace_id: UUID,
    actor: str,
    correlation_id: str,
) -> dict[str, str]:
    row = (
        (
            await db.execute(
                text("""
      SELECT d.failed_at,a.id AS approval_id,a.decided_at
      FROM ai_job_dead_letters d JOIN ai_job_approvals a ON a.job_id=d.job_id
      WHERE d.job_id=:job AND d.tenant_id=:org AND d.workspace_id=:workspace
        AND d.manual_retry_requires_new_approval=true AND a.id=:approval
        AND a.state='approved' AND a.decided_at>d.failed_at FOR UPDATE OF d
    """),
                {
                    "job": job_id,
                    "org": organization_id,
                    "workspace": workspace_id,
                    "approval": approval_id,
                },
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise PermissionError("new_approval_required")
    updated = await db.execute(
        text("""UPDATE ai_generation_jobs SET state='retry_wait',
      max_attempts=max_attempts+1,next_attempt_at=now(),failure_code=NULL,completed_at=NULL,
      updated_at=now(),version=version+1 WHERE id=:job AND state='dead_letter'
      AND max_attempts < 10
      RETURNING id"""),
        {"job": job_id},
    )
    if updated.scalar_one_or_none() is None:
        raise LookupError("dead_letter_not_retryable")
    await db.execute(
        text("""UPDATE ai_job_dead_letters SET recovery_status='approved_retry',
      manual_retry_requires_new_approval=false,updated_at=now() WHERE job_id=:job"""),
        {"job": job_id},
    )
    await audit(
        db,
        "job.dead_letter.retry",
        correlation_id,
        actor,
        organization_id=organization_id,
        workspace_id=workspace_id,
        job_id=job_id,
        details={"approval_id": str(approval_id)},
    )
    await db.commit()
    return {"state": "retry_wait"}


async def recover_expired(
    db: AsyncSession,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
) -> dict[str, int]:
    cancelled_rows = (
        (
            await db.execute(
                text("""
        UPDATE ai_generation_jobs SET state='cancelled',lease_owner=NULL,
          lease_expires_at=NULL,completed_at=now(),updated_at=now()
        WHERE state='cancel_requested' AND lease_expires_at <= now()
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
        RETURNING id,organization_id,workspace_id,fencing_token,correlation_id
    """),
                {"org": organization_id, "workspace": workspace_id},
            )
        )
        .mappings()
        .all()
    )
    for row in cancelled_rows:
        await db.execute(
            text("""UPDATE ai_job_attempts SET state='cancelled',finished_at=now()
          WHERE job_id=:job AND fencing_token=:token"""),
            {"job": row["id"], "token": row["fencing_token"]},
        )
        await audit(
            db,
            "job.cancelled",
            row["correlation_id"] or "lease-recovery",
            "lease-recovery",
            organization_id=row["organization_id"],
            workspace_id=row["workspace_id"],
            job_id=row["id"],
            details={"reason": "cancel_lease_expired"},
        )
    retried_result = await db.execute(
        text("""
        UPDATE ai_generation_jobs SET state='retry_wait',lease_owner=NULL,lease_expires_at=NULL,
          next_attempt_at=now(),updated_at=now()
        WHERE state='leased' AND lease_expires_at <= now() AND attempt_count < max_attempts
          AND (deadline_at IS NULL OR deadline_at > now())
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
    """),
        {"org": organization_id, "workspace": workspace_id},
    )
    retried = int(getattr(retried_result, "rowcount", 0))
    dead_rows = (
        (
            await db.execute(
                text("""
        UPDATE ai_generation_jobs SET state='dead_letter',lease_owner=NULL,lease_expires_at=NULL,
          failure_code='lease_expired',completed_at=now(),updated_at=now()
        WHERE state='leased' AND lease_expires_at <= now() AND attempt_count >= max_attempts
          AND (deadline_at IS NULL OR deadline_at > now())
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
        RETURNING id,organization_id,workspace_id,attempt_count,max_attempts,
          request_sha256,correlation_id
    """),
                {"org": organization_id, "workspace": workspace_id},
            )
        )
        .mappings()
        .all()
    )
    dead = len(dead_rows)
    for row in dead_rows:
        evidence_hash = hashlib.sha256(
            f"{row['id']}:lease_expired:{row['attempt_count']}".encode()
        ).hexdigest()
        await db.execute(
            text("""
          INSERT INTO ai_job_dead_letters
          (job_id,organization_id,workspace_id,safe_error_code,attempt_count,payload_sha256,
           final_error_code,max_attempts,safe_error_details,failed_at,task_id,tenant_id,
           correlation_id,evidence_hash,manual_retry_requires_new_approval)
          VALUES(:job,:org,:workspace,'lease_expired',:attempts,:request_hash,
          'lease_expired',:max_attempts,'{}'::jsonb,now(),:job,:org,
          :correlation,:evidence,true)
          ON CONFLICT(job_id) DO NOTHING"""),
            {
                "job": row["id"],
                "org": row["organization_id"],
                "workspace": row["workspace_id"],
                "attempts": row["attempt_count"],
                "request_hash": row["request_sha256"],
                "max_attempts": row["max_attempts"],
                "correlation": row["correlation_id"] or "lease-recovery",
                "evidence": evidence_hash,
            },
        )
    await db.commit()
    return {"retried": retried, "dead_lettered": dead}


async def expire_deadlines(
    db: AsyncSession,
    organization_id: UUID | None = None,
    workspace_id: UUID | None = None,
) -> int:
    result = await db.execute(
        text("""
        UPDATE ai_generation_jobs SET state='expired',lease_owner=NULL,lease_expires_at=NULL,
          failure_code='deadline_expired',completed_at=now(),updated_at=now()
        WHERE state IN ('queued','retry_wait','leased') AND deadline_at <= now()
          AND (CAST(:org AS uuid) IS NULL OR organization_id=:org)
          AND (CAST(:workspace AS uuid) IS NULL OR workspace_id=:workspace)
    """),
        {"org": organization_id, "workspace": workspace_id},
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0))
