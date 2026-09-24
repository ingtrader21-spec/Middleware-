"""Durable, single-concurrency social publishing worker."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.social.adapters import HootsuiteProviderAdapter, PostlyProviderAdapter
from app.social.domain import JobType, ProviderName
from app.social.providers import SocialError, SocialProviderRegistry
from app.social.production import ProductionCanaryPolicy, require_provider_health
from app.social.queue import RedisSocialQueue, retry_delay
from app.social.sql_repository import SqlSocialRepository
from app.social import metrics


def build_registry() -> SocialProviderRegistry:
    registry = SocialProviderRegistry()
    registry.register(PostlyProviderAdapter())
    registry.register(HootsuiteProviderAdapter())
    return registry


async def process_claimed_job(
    session: AsyncSession, registry: SocialProviderRegistry, job: dict[str, Any]
) -> str:
    repository = SqlSocialRepository(session)
    post = await repository.get_post(job["social_post_id"])
    adapter = registry.get(post.provider)
    started = time.monotonic()
    try:
        action = JobType(job["job_type"])
        if (
            post.provider is ProviderName.POSTLY
            and not settings.postiz_delivery_enabled
        ):
            raise SocialError(
                "SOCIAL_PROVIDER_DISABLED",
                "Postly delivery is disabled",
                status_code=403,
            )
        if action is JobType.PUBLISH:
            if not settings.social_publish_enabled or (
                post.provider is ProviderName.POSTLY
                and not settings.postiz_publish_enabled
            ):
                raise SocialError(
                    "SOCIAL_PROVIDER_DISABLED",
                    "Social publishing is disabled",
                    status_code=403,
                )
            if settings.social_production_mode:
                if not job.get("production_canary"):
                    raise SocialError(
                        "SOCIAL_PRODUCTION_CANARY_REQUIRED",
                        "Production publish job is not a canary",
                        status_code=403,
                    )
                production_context = await repository.production_publish_context(
                    post, content_approved=job.get("content_approved_at") is not None
                )
                metrics.production_account_connected.labels(
                    post.provider.value, "other"
                ).set(1 if production_context.connection_state == "connected" else 0)
                if str(production_context.account_id) != str(
                    job.get("production_account_id")
                ):
                    raise SocialError(
                        "SOCIAL_PRODUCTION_ACCOUNT_CHANGED",
                        "Production account ownership changed after validation",
                        status_code=409,
                    )
                ProductionCanaryPolicy(settings).validate(production_context)
                require_provider_health(await adapter.health_check())
            result = await adapter.publish_post(post, job["correlation_id"])
        elif action is JobType.SCHEDULE:
            result = await adapter.schedule_post(post, job["correlation_id"])
        elif action is JobType.CANCEL:
            result = await adapter.cancel_post(post, job["correlation_id"])
        elif action is JobType.DELETE:
            result = await adapter.delete_post(post, job["correlation_id"])
        else:
            account_refs = await repository.staging_provider_account_refs(post.id)
            result = await adapter.create_post(
                post, account_refs, job["correlation_id"]
            )
        await repository.complete_job(
            job, provider_post_id=result.provider_post_id, status=result.status
        )
        metrics.provider_requests.labels(post.provider.value, "success").inc()
        if action is JobType.PUBLISH:
            metrics.publish_success.labels(post.provider.value, "other").inc()
            if job.get("production_canary"):
                metrics.production_publish_success.labels(
                    post.provider.value, "other"
                ).inc()
            metrics.publish_duration.labels(post.provider.value, "other").observe(
                time.monotonic() - started
            )
        return "completed"
    except SocialError as exc:
        metrics.provider_requests.labels(post.provider.value, "error").inc()
        metrics.provider_errors.labels(post.provider.value, exc.code).inc()
        if JobType(job["job_type"]) is JobType.PUBLISH:
            metrics.publish_failures.labels(
                post.provider.value, "other", exc.code
            ).inc()
            if job.get("production_canary"):
                metrics.production_publish_failures.labels(
                    post.provider.value, "other", exc.code
                ).inc()
            if exc.unknown_result:
                metrics.unknown_result.labels(post.provider.value).inc()
        if exc.code == "SOCIAL_PROVIDER_RATE_LIMITED":
            metrics.provider_rate_limits.labels(post.provider.value).inc()
        return await repository.fail_job(
            job,
            exc,
            max_attempts=settings.social_job_max_attempts,
            delay_seconds=retry_delay(int(job["attempt_count"]) + 1),
        )


async def recover_and_signal(
    session_factory: async_sessionmaker[AsyncSession], queue: RedisSocialQueue
) -> int:
    async with session_factory() as session:
        repository = SqlSocialRepository(session)
        recovered = await repository.recover_stale_jobs()
        signalable = await repository.signalable_jobs()
    unique = {
        job_id: correlation_id for job_id, correlation_id in recovered + signalable
    }
    for job_id, correlation_id in unique.items():
        await queue.enqueue(job_id, correlation_id)
    return len(unique)


async def run_forever(
    session_factory: async_sessionmaker[AsyncSession], redis: Redis
) -> None:
    if not settings.social_worker_enabled or not settings.social_sql_repository_enabled:
        raise RuntimeError("social worker and SQL repository must be enabled")
    if settings.social_worker_concurrency != 1:
        raise RuntimeError("social worker concurrency must equal 1")
    queue = RedisSocialQueue(redis)
    registry = build_registry()
    while True:
        await recover_and_signal(session_factory, queue)
        signal = await queue.claim(timeout_seconds=1)
        if signal is None:
            await asyncio.sleep(settings.social_worker_poll_seconds)
            continue
        async with session_factory() as session:
            jobs = await SqlSocialRepository(session).claim_jobs(
                worker_id=settings.social_worker_id,
                limit=1,
                lease_seconds=settings.social_worker_lease_seconds,
            )
            if jobs:
                await process_claimed_job(session, registry, jobs[0])
                continue
