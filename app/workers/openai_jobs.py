"""Disabled-by-default Server A worker for governed OpenAI inference."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import ai_jobs, ai_orchestration
from app.core.ai_contracts import AICommand, AIResult
from app.core.ai_provider import AIProvider, AIProviderError, ProviderRequest
from app.core.ai_provider import redact_provider_input, safety_identifier
from app.core.config import settings

logger = logging.getLogger(__name__)
OPENAI_PROFILES = ["fast-chat", "quality-chat", "coding-default", "coding-large"]
PRICE_MICRO_USD_PER_TOKEN = {
    "gpt-5.6-terra": (2, 12),
    "gpt-5.6-sol": (5, 30),
}


def validated_worker_concurrency() -> int:
    """Return the sole approved concurrency or fail before registration/claim."""
    value = settings.openai_worker_max_concurrency
    if value != 1:
        raise RuntimeError("openai_worker_concurrency_invalid")
    return value


async def validate_worker_registration(db: AsyncSession) -> None:
    expected = validated_worker_concurrency()
    row = (
        await db.execute(
            text("""
        SELECT max_concurrency,enabled FROM ai_worker_registrations
        WHERE worker_id=:worker AND service_id=:service
    """),
            {
                "worker": settings.openai_worker_id,
                "service": settings.openai_worker_service_id,
            },
        )
    ).mappings().first()
    if row is None or not row["enabled"] or int(row["max_concurrency"]) != expected:
        raise RuntimeError("openai_worker_registration_invalid")


async def _usage_in_last_day(
    db: AsyncSession,
    *,
    organization_id: UUID,
    workspace_id: UUID,
    requested_by: str,
    project_key: str | None,
) -> tuple[int, int]:
    row = (
        await db.execute(
            text("""
        SELECT
          COALESCE(sum(u.tokens) FILTER (WHERE j.requested_by=:user),0) user_tokens,
          COALESCE(sum(u.tokens) FILTER (WHERE j.project_key=:project),0) project_tokens
        FROM ai_usage_ledger u JOIN ai_generation_jobs j ON j.id=u.job_id
        WHERE u.created_at >= now()-interval '1 day'
          AND j.organization_id=:organization AND j.workspace_id=:workspace
    """),
            {
                "organization": organization_id,
                "workspace": workspace_id,
                "user": requested_by,
                "project": project_key,
            },
        )
    ).mappings().one()
    return int(row["user_tokens"]), int(row["project_tokens"])


async def _cancel_requested(db: AsyncSession, job_id: UUID) -> bool:
    return bool(
        (
            await db.execute(
                text(
                    "SELECT cancel_requested_at IS NOT NULL FROM ai_generation_jobs WHERE id=:job"
                ),
                {"job": job_id},
            )
        ).scalar_one()
    )


async def _maintain_lease(
    session_factory: async_sessionmaker[AsyncSession],
    job_id: UUID,
    fencing_token: int,
    stopped: asyncio.Event,
) -> None:
    while True:
        try:
            await asyncio.wait_for(stopped.wait(), timeout=20)
            return
        except TimeoutError:
            pass
        async with session_factory() as lease_db:
            renewed = (
                await lease_db.execute(
                    text("""
                UPDATE ai_generation_jobs
                SET lease_expires_at=now()+make_interval(secs=>:seconds),updated_at=now()
                WHERE id=:job AND lease_owner=:worker AND fencing_token=:token
                  AND state IN ('leased','cancel_requested')
                  AND lease_expires_at > now()
                RETURNING id
            """),
                    {
                        "seconds": settings.ai_job_lease_seconds,
                        "job": job_id,
                        "worker": settings.openai_worker_id,
                        "token": fencing_token,
                    },
                )
            ).scalar_one_or_none()
            await lease_db.commit()
            if renewed is None:
                raise AIProviderError("provider_lease_lost")


def _routing(command: AICommand) -> tuple[str, str]:
    if command.command_type.value == "ai.chat.v1":
        return settings.openai_chat_model, settings.openai_chat_reasoning_effort
    if command.command_type.value == "ai.coding.v1":
        return settings.openai_coding_model, settings.openai_coding_reasoning_effort
    raise AIProviderError("provider_capability_denied")


def _estimated_cost(model: str, input_tokens: int, output_tokens: int) -> int:
    rates = PRICE_MICRO_USD_PER_TOKEN.get(model)
    if rates is None:
        raise AIProviderError("provider_price_policy_missing")
    return input_tokens * rates[0] + output_tokens * rates[1]


async def process_job(
    db: AsyncSession,
    provider: AIProvider,
    job: dict[str, Any],
    session_factory: async_sessionmaker[AsyncSession],
) -> str:
    job_id = UUID(str(job["id"]))
    token = int(job["fencing_token"])
    worker_id = settings.openai_worker_id
    command = AICommand.model_validate(job["command_payload"])
    model, effort = _routing(command)
    if effort not in {"low", "medium"}:
        raise AIProviderError("provider_reasoning_policy_invalid")
    user_tokens, project_tokens = await _usage_in_last_day(
        db,
        organization_id=UUID(str(job["organization_id"])),
        workspace_id=UUID(str(job["workspace_id"])),
        requested_by=command.actor_id,
        project_key=job.get("project_key"),
    )
    if user_tokens >= settings.openai_daily_user_token_limit:
        raise AIProviderError("user_token_limit_exceeded")
    if job.get("project_key") and project_tokens >= settings.openai_daily_project_token_limit:
        raise AIProviderError("project_token_limit_exceeded")
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    pieces: list[str] = []
    sequence = 0
    input_tokens = output_tokens = 0
    request = ProviderRequest(
        model=model,
        reasoning_effort=effort,  # type: ignore[arg-type]
        input_text=redact_provider_input(
            json.dumps(command.input, sort_keys=True, separators=(",", ":"))
        ),
        safety_identifier=safety_identifier(
            command.actor_id, settings.openai_safety_salt
        ),
        max_output_tokens=min(command.model_policy.max_tokens, 8192),
    )
    rates = PRICE_MICRO_USD_PER_TOKEN.get(model)
    if rates is None:
        raise AIProviderError("provider_price_policy_missing")
    estimated_input_tokens = max(1, len(request.input_text.encode()) // 3)
    projected_cost = estimated_input_tokens * rates[0] + request.max_output_tokens * rates[1]
    if projected_cost > settings.openai_max_estimated_cost_micro_usd:
        raise AIProviderError("job_cost_limit_exceeded")
    lease_stopped = asyncio.Event()
    lease_task = asyncio.create_task(
        _maintain_lease(session_factory, job_id, token, lease_stopped),
        name="openai-job-lease",
    )
    try:
        try:
            async for event in provider.stream(request):
                if lease_task.done():
                    lease_task.result()
                if await _cancel_requested(db, job_id):
                    return await ai_jobs.finish(
                        db,
                        job_id,
                        worker_id,
                        token,
                        failed=False,
                        error_code=None,
                        retryable=False,
                        correlation_id=command.correlation_id,
                    )
                if event.kind == "delta" and event.delta:
                    await ai_jobs.append_chunk(
                        db,
                        job_id,
                        worker_id,
                        token,
                        sequence,
                        event.delta,
                        settings.ai_job_max_output_bytes,
                    )
                    pieces.append(event.delta)
                    sequence += 1
                elif event.kind == "completed":
                    input_tokens = event.input_tokens
                    output_tokens = event.output_tokens
        except AIProviderError as exc:
            if pieces and exc.retryable:
                raise AIProviderError(exc.code, retryable=False) from exc
            raise
    finally:
        lease_stopped.set()
        await lease_task
    if not pieces:
        raise AIProviderError("provider_empty_result")
    cost = _estimated_cost(model, input_tokens, output_tokens)
    if cost > settings.openai_max_estimated_cost_micro_usd:
        raise AIProviderError("job_cost_limit_exceeded")
    completed_at = datetime.now(timezone.utc)
    elapsed = time.monotonic() - started
    result = AIResult(
        command_id=command.command_id,
        job_id=job_id,
        status="SUCCEEDED",
        result_schema_version="1.0",
        model_used=model,
        provider_used="openai",
        started_at=started_at,
        completed_at=completed_at,
        latency_ms=int(elapsed * 1000),
        token_usage={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
        resource_usage={
            "estimated_cost_micro_usd": cost,
            "chunk_count": sequence,
        },
        output={"proposal": "".join(pieces)},
        policy_decisions=["server-authorized", "store-false", "no-provider-tools"],
        audit_reference=f"openai-{job_id}",
    )
    completion_state = await ai_orchestration.store_result(db, job, result)
    return await ai_jobs.finish(
        db,
        job_id,
        worker_id,
        token,
        failed=False,
        error_code=None,
        retryable=False,
        correlation_id=command.correlation_id,
        completion_state=completion_state,
    )


async def cycle(
    provider: AIProvider, session_factory: async_sessionmaker[AsyncSession]
) -> str:
    if not settings.openai_provider_enabled:
        raise RuntimeError("OPENAI_PROVIDER_ENABLED is false")
    async with session_factory() as db:
        await validate_worker_registration(db)
        job = await ai_jobs.claim(
            db,
            settings.openai_worker_id,
            settings.ai_job_lease_seconds,
            "openai-provider-cycle",
            service_id=settings.openai_worker_service_id,
            allowed_model_profiles=OPENAI_PROFILES,
        )
        if job is None:
            return "empty"
        try:
            return await process_job(db, provider, job, session_factory)
        except AIProviderError as exc:
            logger.warning("OpenAI job failed code=%s", exc.code)
            return await ai_jobs.finish(
                db,
                UUID(str(job["id"])),
                settings.openai_worker_id,
                int(job["fencing_token"]),
                failed=True,
                error_code=exc.code,
                retryable=exc.retryable,
                correlation_id="openai-provider-cycle",
                safe_error_details=exc.safe_details(),
            )
        except Exception:
            logger.error("OpenAI job failed code=provider_worker_error")
            try:
                return await ai_jobs.finish(
                    db,
                    UUID(str(job["id"])),
                    settings.openai_worker_id,
                    int(job["fencing_token"]),
                    failed=True,
                    error_code="provider_worker_error",
                    retryable=False,
                    correlation_id="openai-provider-cycle",
                    safe_error_details={"component": "openai-responses"},
                )
            except PermissionError:
                await db.rollback()
                await ai_jobs.recover_expired(
                    db,
                    UUID(str(job["organization_id"])),
                    UUID(str(job["workspace_id"])),
                )
                return "lease_lost"


async def run_forever(
    provider: AIProvider, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    validated_worker_concurrency()
    while True:
        try:
            await cycle(provider, session_factory)
        except OverflowError as exc:
            if str(exc) != "worker_concurrency_limit":
                raise
            logger.info("OpenAI worker capacity occupied")
        await asyncio.sleep(0.25)
