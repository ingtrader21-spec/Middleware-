import asyncio
import os
from typing import Any
from uuid import UUID, uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.social.domain import (
    Capability,
    JobType,
    NormalizedEvent,
    ProviderName,
    ProviderResult,
    SocialPostStatus,
)
from app.social.providers import SocialProviderAdapter, SocialProviderRegistry
from app.social.production import ProductionCanaryPolicy
from app.social.sql_repository import SqlSocialRepository
from app.social.queue import RedisSocialQueue
from app.workers.social import process_claimed_job


DATABASE_URL = os.getenv("TEST_DATABASE_URL", "")
REDIS_URL = os.getenv("TEST_REDIS_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="TEST_DATABASE_URL is required"
)


class CountingPostlyAdapter(SocialProviderAdapter):
    name = ProviderName.POSTLY

    def __init__(self) -> None:
        self.calls = 0

    async def health_check(self) -> dict[str, Any]:
        return {"status": "HEALTHY"}

    def get_capabilities(self) -> frozenset[Capability]:
        return frozenset({Capability.POST_CREATE})

    async def create_post(self, post, account_refs, correlation_id):
        self.calls += 1
        return ProviderResult(f"staging-{post.id}", SocialPostStatus.DRAFT)

    async def publish_post(self, post, correlation_id):
        self.calls += 1
        return ProviderResult(f"production-{post.id}", SocialPostStatus.PUBLISHED)


async def seed_account(session, tenant_id: UUID) -> UUID:
    account_id = uuid4()
    await session.execute(
        text("""INSERT INTO social_accounts
        (id,tenant_id,provider,provider_account_id,network,external_profile_name,
         external_profile_id,connection_state,capabilities,metadata)
        VALUES (:id,:tenant,'postly',:external,'other','synthetic staging account',
         :external,'connected','[]'::jsonb,'{"classification":"STAGING_SAFE"}'::jsonb)"""),
        {"id": account_id, "tenant": tenant_id, "external": f"synthetic-{account_id}"},
    )
    await session.commit()
    return account_id


def test_durable_idempotency_worker_and_event_outbox(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "postiz_delivery_enabled", True)
    monkeypatch.setattr(settings, "social_n8n_events_enabled", True)

    async def scenario() -> None:
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        tenant_id = uuid4()
        key = f"phase2-{uuid4()}"
        correlation_id = f"phase2-correlation-{uuid4()}"
        async with factory() as session:
            account_id = await seed_account(session, tenant_id)
            repository = SqlSocialRepository(session)
            first = await repository.create_post_intent(
                tenant_id=tenant_id,
                provider=ProviderName.POSTLY,
                account_ids=(account_id,),
                content={"text": "CODESTRA STAGING DRAFT - NON-PRODUCTION"},
                campaign_id=None,
                publish_at=None,
                metadata={"classification": "STAGING_SAFE"},
                idempotency_key=key,
                correlation_id=correlation_id,
                request_id="phase2-request",
            )
            second = await repository.create_post_intent(
                tenant_id=tenant_id,
                provider=ProviderName.POSTLY,
                account_ids=(account_id,),
                content={"text": "CODESTRA STAGING DRAFT - NON-PRODUCTION"},
                campaign_id=None,
                publish_at=None,
                metadata={"classification": "STAGING_SAFE"},
                idempotency_key=key,
                correlation_id=correlation_id,
                request_id="phase2-request",
            )
            assert first[:2] == second[:2]
            assert first[2] is True and second[2] is False
            counts = (
                (
                    await session.execute(
                        text("""SELECT
                    (SELECT count(*) FROM social_posts WHERE tenant_id=:tenant) posts,
                    (SELECT count(*) FROM social_publish_jobs WHERE tenant_id=:tenant) jobs,
                    (SELECT count(*) FROM social_idempotency_records WHERE tenant_id=:tenant) keys,
                    (SELECT count(*) FROM social_audit_events WHERE tenant_id=:tenant) audits"""),
                        {"tenant": tenant_id},
                    )
                )
                .mappings()
                .one()
            )
            assert dict(counts) == {"posts": 1, "jobs": 1, "keys": 1, "audits": 1}
            updated = await repository.update_post(
                first[0],
                content={"text": "updated staging draft"},
                metadata={"classification": "STAGING_SAFE"},
                correlation_id="phase2-update-correlation",
                request_id="phase2-update-request",
            )
            assert updated.id == first[0]
            assert updated.content["text"] == "updated staging draft"
            assert (
                await session.scalar(
                    text("""SELECT count(*) FROM social_audit_events
                    WHERE social_post_id=:post AND action='POST_UPDATED'"""),
                    {"post": first[0]},
                )
                == 1
            )

        adapter = CountingPostlyAdapter()
        registry = SocialProviderRegistry()
        registry.register(adapter)
        async with factory() as session:
            jobs = await SqlSocialRepository(session).claim_jobs(
                worker_id="postly-social-01", limit=100, lease_seconds=60
            )
            own_job = next(item for item in jobs if UUID(str(item["id"])) == first[1])
            assert await process_claimed_job(session, registry, own_job) == "completed"
            assert adapter.calls == 1
            event_count = await session.scalar(
                text(
                    "SELECT count(*) FROM integration_event WHERE correlation_id=:correlation"
                ),
                {"correlation": correlation_id},
            )
            assert event_count == 1
            delivery_status = await session.scalar(
                text(
                    """SELECT d.status FROM integration_delivery d
                    JOIN integration_event e ON e.id=d.event_id
                    WHERE e.correlation_id=:correlation AND d.target='n8n'"""
                ),
                {"correlation": correlation_id},
            )
            assert delivery_status == "pending"
        await engine.dispose()

    asyncio.run(scenario())


def test_database_failure_prevents_provider_dispatch():
    async def scenario() -> None:
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        adapter = CountingPostlyAdapter()
        tenant_id = uuid4()
        async with factory() as session:
            with pytest.raises(Exception):
                await SqlSocialRepository(session).create_post_intent(
                    tenant_id=tenant_id,
                    provider=ProviderName.POSTLY,
                    account_ids=(uuid4(),),
                    content={"text": "must roll back"},
                    campaign_id=None,
                    publish_at=None,
                    metadata={},
                    idempotency_key=f"failure-{uuid4()}",
                    correlation_id="database-failure",
                    request_id="database-failure",
                )
            await session.rollback()
            assert (
                await session.scalar(
                    text("SELECT count(*) FROM social_posts WHERE tenant_id=:tenant"),
                    {"tenant": tenant_id},
                )
                == 0
            )
            assert (
                await session.scalar(
                    text(
                        "SELECT count(*) FROM outbox_event WHERE correlation_id='database-failure'"
                    )
                )
                == 0
            )
            assert adapter.calls == 0
        await engine.dispose()

    asyncio.run(scenario())


def test_webhook_receipt_is_persistently_deduplicated():
    async def scenario() -> None:
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        tenant_id = uuid4()
        subject_id = uuid4()
        provider_event_id = f"evt-{uuid4()}"
        event = NormalizedEvent(
            "social.post.published",
            ProviderName.POSTLY,
            subject_id,
            "webhook-correlation",
            tenant_id,
            {"status": "published"},
        )
        async with factory() as session:
            repository = SqlSocialRepository(session)
            first = await repository.persist_webhook(
                provider=ProviderName.POSTLY,
                provider_event_id=provider_event_id,
                payload_hash="a" * 64,
                correlation_id="webhook-correlation",
                event=event,
                safe_payload=event.payload,
            )
            second = await repository.persist_webhook(
                provider=ProviderName.POSTLY,
                provider_event_id=provider_event_id,
                payload_hash="a" * 64,
                correlation_id="webhook-correlation",
                event=event,
                safe_payload=event.payload,
            )
            assert first is True and second is False
            assert (
                await session.scalar(
                    text(
                        "SELECT count(*) FROM social_webhook_events WHERE provider_event_id=:event"
                    ),
                    {"event": provider_event_id},
                )
                == 1
            )
        await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.skipif(not REDIS_URL, reason="TEST_REDIS_URL is required")
def test_redis_loss_preserves_and_recovers_canonical_job():
    async def scenario() -> None:
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        redis = Redis.from_url(REDIS_URL, decode_responses=True)
        await redis.flushdb()
        tenant_id = uuid4()
        async with factory() as session:
            account_id = await seed_account(session, tenant_id)
            repository = SqlSocialRepository(session)
            post_id, job_id, _ = await repository.create_post_intent(
                tenant_id=tenant_id,
                provider=ProviderName.POSTLY,
                account_ids=(account_id,),
                content={"text": "recoverable staging draft"},
                campaign_id=None,
                publish_at=None,
                metadata={},
                idempotency_key=f"redis-recovery-{uuid4()}",
                correlation_id="redis-recovery",
                request_id="redis-recovery",
            )
            queue = RedisSocialQueue(redis)
            await queue.enqueue(job_id, "redis-recovery")
            await redis.flushdb()
            assert (
                await session.scalar(
                    text("SELECT count(*) FROM social_posts WHERE id=:post"),
                    {"post": post_id},
                )
                == 1
            )
            assert (
                await session.scalar(
                    text("SELECT count(*) FROM social_publish_jobs WHERE id=:job"),
                    {"job": job_id},
                )
                == 1
            )
            signalable = await repository.signalable_jobs()
            recovered = next(item for item in signalable if item[0] == job_id)
            await queue.enqueue(*recovered)
            assert await redis.llen(queue.queue_key) == 1
        await redis.aclose()
        await engine.dispose()

    asyncio.run(scenario())


def test_production_dry_run_persists_audit_without_publish_job_or_provider_call():
    async def scenario() -> None:
        from app.core.config import settings

        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        tenant_id = uuid4()
        campaign_id = uuid4()
        correlation_id = f"production-dry-run-{uuid4()}"
        adapter = CountingPostlyAdapter()
        async with factory() as session:
            await session.execute(
                text("""INSERT INTO social_campaigns(id,tenant_id,name,status,metadata)
                VALUES (:id,:tenant,'synthetic canary','DRAFT','{}'::jsonb)"""),
                {"id": campaign_id, "tenant": tenant_id},
            )
            account_id = await seed_account(session, tenant_id)
            await session.execute(
                text("""UPDATE social_accounts SET metadata=
                '{"classification":"PRODUCTION_APPROVED_CANARY"}'::jsonb WHERE id=:account"""),
                {"account": account_id},
            )
            await session.commit()
            repository = SqlSocialRepository(session)
            post_id, create_job_id, _ = await repository.create_post_intent(
                tenant_id=tenant_id,
                provider=ProviderName.POSTLY,
                account_ids=(account_id,),
                content={"text": "approved low-risk informational content"},
                campaign_id=campaign_id,
                publish_at=None,
                metadata={},
                idempotency_key=f"dry-run-create-{uuid4()}",
                correlation_id=correlation_id,
                request_id="production-dry-run",
            )
            post = await repository.get_post(post_id)
            context = await repository.production_publish_context(
                post, content_approved=True
            )
            inventory = await repository.list_accounts(account_id)
            assert inventory[0]["classification"] == "PRODUCTION_APPROVED_CANARY"
            assert "provider_account_id" not in inventory[0]
            assert "metadata" not in inventory[0]
            policy = ProductionCanaryPolicy(
                settings.model_copy(
                    update={
                        "social_production_mode": True,
                        "social_integration_enabled": True,
                        "social_publish_enabled": True,
                        "social_production_canary_enabled": True,
                        "social_sql_repository_enabled": True,
                        "social_worker_enabled": True,
                        "social_production_backup_gate_verified": True,
                        "social_production_rollback_gate_verified": True,
                        "social_production_webhook_gate_verified": True,
                        "social_production_monitoring_gate_verified": True,
                        "social_production_canary_account_ids": str(account_id),
                        "social_production_canary_tenant_ids": str(tenant_id),
                        "social_production_canary_campaign_ids": str(campaign_id),
                    }
                )
            )
            policy.validate(context)
            await repository.audit_production_dry_run(
                post,
                context,
                correlation_id=correlation_id,
                request_id="production-dry-run",
                idempotency_key="dry-run-publish-key",
            )
            assert (
                await session.scalar(
                    text("""SELECT count(*) FROM social_publish_jobs
                    WHERE social_post_id=:post AND job_type='SOCIAL_POST_PUBLISH'"""),
                    {"post": post_id},
                )
                == 0
            )
            assert (
                await session.scalar(
                    text("""SELECT count(*) FROM social_audit_events
                    WHERE social_post_id=:post AND action='PRODUCTION_DRY_RUN_VALIDATED'"""),
                    {"post": post_id},
                )
                == 1
            )
            assert adapter.calls == 0
            assert create_job_id is not None
        await engine.dispose()

    asyncio.run(scenario())


def test_production_canary_idempotency_calls_one_mock_provider(monkeypatch):
    from app.core.config import settings

    async def scenario() -> None:
        engine = create_async_engine(DATABASE_URL)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        tenant_id = uuid4()
        async with factory() as session:
            account_id = await seed_account(session, tenant_id)
            await session.execute(
                text("""UPDATE social_accounts SET metadata=
                '{"classification":"PRODUCTION_APPROVED_CANARY"}'::jsonb WHERE id=:account"""),
                {"account": account_id},
            )
            await session.commit()
            repository = SqlSocialRepository(session)
            post_id, create_job_id, _ = await repository.create_post_intent(
                tenant_id=tenant_id,
                provider=ProviderName.POSTLY,
                account_ids=(account_id,),
                content={"text": "human-approved synthetic canary"},
                campaign_id=None,
                publish_at=None,
                metadata={},
                idempotency_key=f"production-create-{uuid4()}",
                correlation_id="production-idempotency",
                request_id="production-idempotency",
            )
            await session.execute(
                text("UPDATE social_publish_jobs SET state='completed' WHERE id=:job"),
                {"job": create_job_id},
            )
            await session.commit()
            post = await repository.get_post(post_id)
            context = await repository.production_publish_context(
                post, content_approved=True
            )
            key = f"production-publish-{uuid4()}"
            first = await repository.enqueue_command(
                post=post,
                action=JobType.PUBLISH,
                idempotency_key=key,
                correlation_id="production-idempotency",
                request_id="production-idempotency",
                production_context=context,
            )
            second = await repository.enqueue_command(
                post=post,
                action=JobType.PUBLISH,
                idempotency_key=key,
                correlation_id="production-idempotency",
                request_id="production-idempotency",
                production_context=context,
            )
            assert first[0] == second[0]
            assert first[1] is True and second[1] is False

        for name, value in {
            "social_production_mode": True,
            "social_integration_enabled": True,
            "social_publish_enabled": True,
            "postiz_publish_enabled": True,
            "postiz_delivery_enabled": True,
            "social_production_canary_enabled": True,
            "social_sql_repository_enabled": True,
            "social_worker_enabled": True,
            "social_production_backup_gate_verified": True,
            "social_production_rollback_gate_verified": True,
            "social_production_webhook_gate_verified": True,
            "social_production_monitoring_gate_verified": True,
            "social_production_canary_account_ids": str(account_id),
        }.items():
            monkeypatch.setattr(settings, name, value)
        adapter = CountingPostlyAdapter()
        registry = SocialProviderRegistry()
        registry.register(adapter)
        async with factory() as session:
            jobs = await SqlSocialRepository(session).claim_jobs(
                worker_id="postly-social-01", limit=100, lease_seconds=60
            )
            own_job = next(item for item in jobs if UUID(str(item["id"])) == first[0])
            assert await process_claimed_job(session, registry, own_job) == "completed"
            assert adapter.calls == 1
            assert (
                await session.scalar(
                    text("""SELECT count(*) FROM social_publish_jobs
                    WHERE social_post_id=:post AND job_type='SOCIAL_POST_PUBLISH'"""),
                    {"post": post_id},
                )
                == 1
            )
            assert (
                await session.scalar(
                    text("""SELECT count(*) FROM social_audit_events
                    WHERE social_post_id=:post AND action='POST_PUBLISHED'
                      AND account_id=:account"""),
                    {"post": post_id, "account": account_id},
                )
                == 1
            )
        await engine.dispose()

    asyncio.run(scenario())
