"""Transactional orchestration repository built on the durable AI job tables."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai_contracts import AICommand, AIResult, PUBLIC_STATES
from app.core.config import settings


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


async def submit(
    db: AsyncSession, command: AICommand, workspace_id: UUID
) -> dict[str, Any]:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
        {"key": f"ai-command:{command.tenant_id}:{workspace_id}:{command.idempotency_key}"},
    )
    payload = command.model_dump(mode="json")
    request_hash = hashlib.sha256(_json(payload).encode()).hexdigest()
    existing = (
        await db.execute(
            text("""SELECT id,request_sha256,state FROM ai_generation_jobs
            WHERE organization_id=:tenant AND workspace_id=:workspace
              AND idempotency_key=:key"""),
            {"tenant": command.tenant_id, "workspace": workspace_id, "key": command.idempotency_key},
        )
    ).mappings().first()
    if existing:
        if existing["request_sha256"] != request_hash:
            raise ValueError("idempotency_conflict")
        return {"command_id": existing["id"], "job_id": existing["id"],
                "status": PUBLIC_STATES[existing["state"]], "idempotent_replay": True}
    identifier_exists = (await db.execute(
        text("SELECT 1 FROM ai_generation_jobs WHERE id=:id"),
        {"id": command.command_id},
    )).scalar_one_or_none()
    if identifier_exists:
        raise ValueError("command_id_conflict")

    quota = (
        await db.execute(
            text("""SELECT max_queued,max_running,daily_tokens,max_payload_bytes
            FROM ai_tenant_quotas WHERE organization_id=:tenant AND workspace_id=:workspace"""),
            {"tenant": command.tenant_id, "workspace": workspace_id},
        )
    ).mappings().first()
    max_queued = quota["max_queued"] if quota else settings.ai_default_max_queued_per_tenant
    queued = (
        await db.execute(
            text("""SELECT count(*) FROM ai_generation_jobs
            WHERE organization_id=:tenant AND workspace_id=:workspace
              AND state IN ('queued','available','retry_wait','approval_required')"""),
            {"tenant": command.tenant_id, "workspace": workspace_id},
        )
    ).scalar_one()
    if queued >= max_queued:
        raise OverflowError("tenant_queue_quota_exceeded")
    if quota and len(_json(payload).encode()) > quota["max_payload_bytes"]:
        raise OverflowError("tenant_payload_quota_exceeded")
    used_tokens = (
        await db.execute(
            text("""SELECT COALESCE(sum(tokens),0) FROM ai_usage_ledger
            WHERE organization_id=:tenant AND workspace_id=:workspace AND usage_date=:today"""),
            {"tenant": command.tenant_id, "workspace": workspace_id, "today": date.today()},
        )
    ).scalar_one()
    daily = quota["daily_tokens"] if quota else settings.ai_daily_token_quota
    if used_tokens + command.resource_limits.token_budget > daily:
        raise OverflowError("daily_token_quota_exceeded")
    if settings.ai_global_emergency_limit > 0:
        active = (await db.execute(text("""SELECT count(*) FROM ai_generation_jobs
            WHERE state IN ('queued','available','leased','running','retry_wait')"""))).scalar_one()
        if active >= settings.ai_global_emergency_limit:
            raise OverflowError("global_emergency_limit")

    await db.execute(
        text("""INSERT INTO ai_generation_jobs(
          id,organization_id,workspace_id,requested_by,task_type,state,
          idempotency_key,request_sha256,max_attempts,command_type,schema_version,
          actor_id,actor_type,correlation_id,priority,deadline_at,command_payload,
          model_profile,resource_limits,data_classification,approval_policy,
          callback_policy,command_metadata)
        VALUES(:id,:tenant,:workspace,:actor,:task,'queued',:key,:hash,:attempts,
          :command_type,:schema_version,:actor,:actor_type,:correlation,:priority,
          :deadline,CAST(:payload AS jsonb),:profile,CAST(:limits AS jsonb),
          :classification,CAST(:approval AS jsonb),CAST(:callback AS jsonb),CAST(:metadata AS jsonb))"""),
        {
            "id": command.command_id, "tenant": command.tenant_id, "workspace": workspace_id,
            "actor": command.actor_id, "task": command.command_type.value,
            "key": command.idempotency_key, "hash": request_hash,
            "attempts": command.resource_limits.retry_count + 1,
            "command_type": command.command_type.value, "schema_version": command.schema_version,
            "actor_type": command.actor_type, "correlation": command.correlation_id,
            "priority": command.priority, "deadline": command.deadline_at,
            "payload": _json(payload), "profile": command.model_policy.profile,
            "limits": _json(command.resource_limits.model_dump(mode="json")),
            "classification": command.data_classification,
            "approval": _json(command.approval_policy.model_dump(mode="json")),
            "callback": _json(command.callback_policy.model_dump(mode="json")),
            "metadata": _json(command.metadata),
        },
    )
    await _event(db, command.command_id, command.tenant_id, workspace_id,
                 "command.submitted", "queued", command.correlation_id)
    await db.commit()
    return {"command_id": command.command_id, "job_id": command.command_id,
            "status": "PENDING", "idempotent_replay": False}


async def _event(db: AsyncSession, job_id: UUID, tenant_id: UUID, workspace_id: UUID,
                 event_type: str, state: str, correlation_id: str,
                 details: dict[str, Any] | None = None) -> None:
    sequence = (await db.execute(text(
        "SELECT COALESCE(max(sequence),0)+1 FROM ai_job_events WHERE job_id=:job"),
        {"job": job_id})).scalar_one()
    await db.execute(text("""INSERT INTO ai_job_events
      (id,job_id,organization_id,workspace_id,event_type,state,sequence,safe_details,correlation_id)
      VALUES(:id,:job,:tenant,:workspace,:event,:state,:sequence,CAST(:details AS jsonb),:correlation)"""),
      {"id": uuid4(), "job": job_id, "tenant": tenant_id, "workspace": workspace_id,
       "event": event_type, "state": state, "sequence": sequence,
       "details": _json(details or {}), "correlation": correlation_id})


async def get(db: AsyncSession, job_id: UUID, tenant_id: UUID, workspace_id: UUID) -> dict[str, Any]:
    row = (await db.execute(text("""SELECT id,state,command_type,created_at,updated_at,
      deadline_at,attempt_count,max_attempts,correlation_id,model_profile
      FROM ai_generation_jobs WHERE id=:job AND organization_id=:tenant AND workspace_id=:workspace"""),
      {"job": job_id, "tenant": tenant_id, "workspace": workspace_id})).mappings().first()
    if not row:
        raise LookupError("command_not_found")
    return {"command_id": row["id"], "job_id": row["id"],
            "command_type": row["command_type"], "status": PUBLIC_STATES[row["state"]],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "deadline_at": row["deadline_at"], "attempt_count": row["attempt_count"],
            "max_attempts": row["max_attempts"], "correlation_id": row["correlation_id"],
            "model_profile": row["model_profile"]}


async def result(db: AsyncSession, job_id: UUID, tenant_id: UUID, workspace_id: UUID) -> dict[str, Any]:
    row = (await db.execute(text("""SELECT r.* FROM ai_job_results r
      WHERE r.job_id=:job AND r.organization_id=:tenant AND r.workspace_id=:workspace"""),
      {"job": job_id, "tenant": tenant_id, "workspace": workspace_id})).mappings().first()
    if not row:
        await get(db, job_id, tenant_id, workspace_id)
        raise LookupError("result_not_ready")
    return dict(row)


async def cancel(db: AsyncSession, job_id: UUID, tenant_id: UUID, workspace_id: UUID,
                 actor_id: str, correlation_id: str) -> str:
    row = (await db.execute(text("""UPDATE ai_generation_jobs SET
      cancel_requested_at=COALESCE(cancel_requested_at,now()),
      state=CASE WHEN state IN ('queued','available','retry_wait','approval_required') THEN 'cancelled'
                 ELSE 'cancel_requested' END,
      completed_at=CASE WHEN state IN ('queued','available','retry_wait','approval_required') THEN now()
                        ELSE completed_at END, updated_at=now(),version=version+1
      WHERE id=:job AND organization_id=:tenant AND workspace_id=:workspace
        AND state NOT IN ('completed','failed','cancelled','expired','dead_letter','rejected')
      RETURNING state"""), {"job": job_id, "tenant": tenant_id, "workspace": workspace_id})).scalar_one_or_none()
    if row is None:
        raise LookupError("active_command_not_found")
    await _event(db, job_id, tenant_id, workspace_id, "command.cancellation_requested", row, correlation_id)
    await db.commit()
    return PUBLIC_STATES[row]


async def decide(db: AsyncSession, job_id: UUID, tenant_id: UUID, workspace_id: UUID,
                 actor_id: str, correlation_id: str, approved: bool, reason: str) -> str:
    fingerprint = hashlib.sha256(actor_id.encode()).hexdigest()
    state = "approved" if approved else "rejected"
    updated = await db.execute(text("""UPDATE ai_job_approvals SET state=:state,
      decided_by_fingerprint=:actor,decision_reason=:reason,decided_at=now(),updated_at=now()
      WHERE job_id=:job AND organization_id=:tenant AND workspace_id=:workspace
        AND state='pending' RETURNING id"""),
      {"state": state, "actor": fingerprint, "reason": reason, "job": job_id,
       "tenant": tenant_id, "workspace": workspace_id})
    if updated.scalar_one_or_none() is None:
        raise LookupError("pending_approval_not_found")
    await db.execute(text("UPDATE ai_generation_jobs SET state=:state,updated_at=now(),version=version+1 WHERE id=:job"),
                     {"state": state, "job": job_id})
    await _event(db, job_id, tenant_id, workspace_id, f"approval.{state}", state, correlation_id,
                 {"reason_present": bool(reason)})
    await db.commit()
    return PUBLIC_STATES[state]


async def store_result(db: AsyncSession, job: dict[str, Any], result: AIResult) -> str:
    output_hash = hashlib.sha256(_json(result.output).encode()).hexdigest()
    await db.execute(text("""INSERT INTO ai_job_results(job_id,organization_id,workspace_id,
      result_schema_version,model_used,provider_used,started_at,completed_at,latency_ms,
      token_usage,resource_usage,output,structured_artifacts,warnings,policy_decisions,error,
      retryability,audit_reference,output_sha256)
      VALUES(:job,:tenant,:workspace,:version,:model,:provider,:started,:completed,:latency,
      CAST(:tokens AS jsonb),CAST(:resources AS jsonb),CAST(:output AS jsonb),CAST(:artifacts AS jsonb),
      CAST(:warnings AS jsonb),CAST(:decisions AS jsonb),CAST(:error AS jsonb),:retry,:audit,:hash)
      ON CONFLICT(job_id) DO NOTHING"""), {
        "job": job["id"], "tenant": job["organization_id"], "workspace": job["workspace_id"],
        "version": result.result_schema_version, "model": result.model_used,
        "provider": result.provider_used, "started": result.started_at,
        "completed": result.completed_at, "latency": result.latency_ms,
        "tokens": _json(result.token_usage), "resources": _json(result.resource_usage),
        "output": _json(result.output), "artifacts": _json(result.structured_artifacts),
        "warnings": _json(result.warnings), "decisions": _json(result.policy_decisions),
        "error": _json(result.error) if result.error else None, "retry": result.retryability,
        "audit": result.audit_reference, "hash": output_hash,
    })
    total_tokens = sum(result.token_usage.values())
    await db.execute(text("""INSERT INTO ai_usage_ledger
      (id,job_id,organization_id,workspace_id,tokens,compute_units,model_profile)
      VALUES(:id,:job,:tenant,:workspace,:tokens,:compute,:profile) ON CONFLICT(job_id) DO NOTHING"""),
      {"id": uuid4(), "job": job["id"], "tenant": job["organization_id"],
       "workspace": job["workspace_id"], "tokens": total_tokens,
       "compute": max(1, result.latency_ms // 1000), "profile": job["model_profile"]})
    approval = bool((job.get("approval_policy") or {}).get("required"))
    state = "approval_required" if approval else "completed"
    if approval:
        proposal = {"output": result.output, "structured_artifacts": result.structured_artifacts}
        await db.execute(text("""INSERT INTO ai_job_approvals
          (id,job_id,organization_id,workspace_id,action_type,proposal,proposal_sha256,requested_by)
          VALUES(:id,:job,:tenant,:workspace,:action,CAST(:proposal AS jsonb),:hash,:actor)
          ON CONFLICT DO NOTHING"""), {"id": uuid4(), "job": job["id"],
          "tenant": job["organization_id"], "workspace": job["workspace_id"],
          "action": job["command_type"], "proposal": _json(proposal),
          "hash": hashlib.sha256(_json(proposal).encode()).hexdigest(),
          "actor": job.get("actor_id") or "system"})
    return state
