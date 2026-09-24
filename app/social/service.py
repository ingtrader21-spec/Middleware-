from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from app.core.config import settings
from app.social.domain import (
    Capability,
    JobType,
    ProviderName,
    SocialAccount,
    SocialPost,
    SocialPostStatus,
    SocialPublishJob,
)
from app.social.providers import SocialError, SocialProviderRegistry


class SocialRepository:
    """Testable repository contract; SQL-backed persistence is defined by migration 0033."""

    def __init__(self) -> None:
        self.accounts: dict[UUID, SocialAccount] = {}
        self.posts: dict[UUID, SocialPost] = {}
        self.jobs: dict[UUID, SocialPublishJob] = {}
        self.idempotency: dict[tuple[UUID, str, UUID, str], tuple[str, UUID]] = {}
        self.webhook_ids: set[str] = set()
        self.audit: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def create_post_and_job(
        self,
        post: SocialPost,
        job: SocialPublishJob,
        action: str,
        request_hash: str,
        idempotency_subject: UUID | None = None,
    ) -> tuple[SocialPost, SocialPublishJob, bool]:
        # A create retry may not know the Codestra UUID allocated on its first
        # request. Scope it to tenant/action/key until the canonical post exists;
        # commands on an existing post remain scoped to that post UUID.
        subject_id = idempotency_subject or UUID(int=0)
        key = (post.tenant_id, action, subject_id, job.idempotency_key)
        async with self._lock:
            existing = self.idempotency.get(key)
            if existing:
                old_hash, old_job_id = existing
                if old_hash != request_hash:
                    raise SocialError(
                        "SOCIAL_IDEMPOTENCY_CONFLICT",
                        "Idempotency key was used with a different request",
                        status_code=409,
                    )
                old_job = self.jobs[old_job_id]
                return self.posts[old_job.social_post_id], old_job, False
            self.posts[post.id] = post
            self.jobs[job.id] = job
            self.idempotency[key] = (request_hash, job.id)
            return post, job, True

    async def enqueue_existing(
        self, post: SocialPost, job: SocialPublishJob, action: str
    ) -> tuple[SocialPublishJob, bool]:
        digest = hashlib.sha256(f"{post.id}:{action}".encode()).hexdigest()
        _, stored, created = await self.create_post_and_job(
            post, job, action, digest, post.id
        )
        return stored, created


class SocialPublishingService:
    def __init__(
        self,
        registry: SocialProviderRegistry,
        repository: SocialRepository | None = None,
    ) -> None:
        self.registry = registry
        self.repository = repository or SocialRepository()

    def _enabled(self) -> None:
        if not settings.social_integration_enabled:
            raise SocialError(
                "SOCIAL_PROVIDER_DISABLED",
                "Social integration is disabled",
                status_code=503,
            )

    def resolve_provider(self, post: SocialPost | None = None) -> ProviderName:
        if post is not None:
            return post.provider
        try:
            return ProviderName(settings.social_provider)
        except ValueError as exc:
            raise SocialError(
                "SOCIAL_PROVIDER_NOT_CONFIGURED",
                "Configured social provider is invalid",
                status_code=503,
            ) from exc

    async def create_post(
        self,
        *,
        tenant_id: UUID,
        account_ids: tuple[UUID, ...],
        content: dict[str, Any],
        campaign_id: UUID | None,
        publish_at: datetime | None,
        metadata: dict[str, Any],
        idempotency_key: str,
        correlation_id: str,
        request_id: str,
        post_id: UUID | None = None,
    ) -> tuple[SocialPost, SocialPublishJob, bool]:
        self._enabled()
        if not account_ids or not str(content.get("text", "")).strip():
            raise SocialError(
                "SOCIAL_POST_INVALID",
                "Accounts and content text are required",
                status_code=422,
            )
        provider = self.resolve_provider()
        self.registry.require(provider, Capability.POST_CREATE)
        post = SocialPost(
            tenant_id,
            provider,
            account_ids,
            content,
            id=post_id or uuid4(),
            campaign_id=campaign_id,
            publish_at=publish_at,
            metadata=metadata,
            status=SocialPostStatus.QUEUED,
        )
        job_type = JobType.SCHEDULE if publish_at else JobType.CREATE
        job = SocialPublishJob(
            tenant_id,
            post.id,
            provider,
            job_type,
            correlation_id,
            request_id,
            idempotency_key,
        )
        request_hash = hashlib.sha256(
            json.dumps(
                {
                    "accounts": [str(x) for x in account_ids],
                    "content": content,
                    "campaign_id": str(campaign_id),
                    "publish_at": publish_at.isoformat() if publish_at else None,
                    "metadata": metadata,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        result = await self.repository.create_post_and_job(
            post, job, job_type, request_hash
        )
        if result[2]:
            self._audit("POST_CREATED", post, job, "QUEUED")
        return result

    async def command(
        self,
        post_id: UUID,
        action: JobType,
        idempotency_key: str,
        correlation_id: str,
        request_id: str,
    ) -> tuple[SocialPublishJob, bool]:
        self._enabled()
        try:
            post = self.repository.posts[post_id]
        except KeyError as exc:
            raise SocialError(
                "SOCIAL_POST_NOT_FOUND", "Social post was not found", status_code=404
            ) from exc
        capability = {
            JobType.PUBLISH: Capability.POST_PUBLISH,
            JobType.SCHEDULE: Capability.POST_SCHEDULE,
            JobType.CANCEL: Capability.POST_CANCEL,
            JobType.DELETE: Capability.POST_DELETE,
        }[action]
        self.registry.require(post.provider, capability)
        if action is JobType.PUBLISH and not settings.social_publish_enabled:
            raise SocialError(
                "SOCIAL_PROVIDER_DISABLED",
                "Social publishing is disabled",
                status_code=403,
            )
        job = SocialPublishJob(
            post.tenant_id,
            post.id,
            post.provider,
            action,
            correlation_id,
            request_id,
            idempotency_key,
        )
        stored, created = await self.repository.enqueue_existing(post, job, action)
        if created:
            self._audit(f"POST_{action.name}_REQUESTED", post, stored, "QUEUED")
        return stored, created

    async def process_job(self, job_id: UUID) -> SocialPost:
        job = self.repository.jobs[job_id]
        post = self.repository.posts[job.social_post_id]
        adapter = self.registry.get(post.provider)
        if job.job_type is JobType.PUBLISH:
            if not settings.social_publish_enabled:
                raise SocialError(
                    "SOCIAL_PROVIDER_DISABLED",
                    "Social publishing is disabled",
                    status_code=403,
                )
            result = await adapter.publish_post(post, job.correlation_id)
        elif job.job_type is JobType.SCHEDULE:
            result = await adapter.schedule_post(post, job.correlation_id)
        elif job.job_type is JobType.CANCEL:
            result = await adapter.cancel_post(post, job.correlation_id)
        elif job.job_type is JobType.DELETE:
            result = await adapter.delete_post(post, job.correlation_id)
        else:
            refs = [
                self.repository.accounts[x].provider_account_id
                for x in post.account_ids
                if x in self.repository.accounts
            ]
            result = await adapter.create_post(post, refs, job.correlation_id)
        post.provider_post_id = result.provider_post_id or post.provider_post_id
        post.status = result.status
        post.updated_at = datetime.now(timezone.utc)
        job.state = "completed"
        self._audit(f"POST_{post.status}", post, job, "SUCCESS")
        return post

    def _audit(
        self, action: str, post: SocialPost, job: SocialPublishJob, result: str
    ) -> None:
        self.repository.audit.append(
            {
                "actor_type": "machine",
                "actor_id": "codestra-social-api",
                "action": action,
                "social_post_id": str(post.id),
                "campaign_id": str(post.campaign_id) if post.campaign_id else None,
                "provider": post.provider,
                "correlation_id": job.correlation_id,
                "request_id": job.request_id,
                "job_id": str(job.id),
                "idempotency_key_hash": hashlib.sha256(
                    job.idempotency_key.encode()
                ).hexdigest(),
                "result": result,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
