from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.social.domain import (
    JobType,
    NormalizedEvent,
    ProviderName,
    SocialPost,
    SocialPostStatus,
)
from app.social.providers import SocialError
from app.social.production import ProductionPublishContext


ZERO_UUID = UUID(int=0)


class SqlSocialRepository:
    """PostgreSQL source of truth for the controlled social staging runtime."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_post_intent(
        self,
        *,
        tenant_id: UUID,
        provider: ProviderName,
        account_ids: tuple[UUID, ...],
        content: dict[str, Any],
        campaign_id: UUID | None,
        publish_at: datetime | None,
        metadata: dict[str, Any],
        idempotency_key: str,
        correlation_id: str,
        request_id: str,
        post_id: UUID | None = None,
    ) -> tuple[UUID, UUID, bool]:
        post_id = post_id or uuid4()
        job_id = uuid4()
        action = JobType.SCHEDULE.value if publish_at else JobType.CREATE.value
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        request_hash = hashlib.sha256(
            json.dumps(
                {
                    "accounts": [str(item) for item in account_ids],
                    "content": content,
                    "campaign_id": str(campaign_id) if campaign_id else None,
                    "publish_at": publish_at.isoformat() if publish_at else None,
                    "metadata": metadata,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        reserved = (
            (
                await self.session.execute(
                    text("""
                INSERT INTO social_idempotency_records
                  (tenant_id,action,subject_id,key_hash,request_hash,social_post_id,job_id)
                VALUES (:tenant,:action,:subject,:key_hash,:request_hash,:post,:job)
                ON CONFLICT DO NOTHING RETURNING social_post_id,job_id
                """),
                    {
                        "tenant": tenant_id,
                        "action": action,
                        "subject": ZERO_UUID,
                        "key_hash": key_hash,
                        "request_hash": request_hash,
                        "post": post_id,
                        "job": job_id,
                    },
                )
            )
            .mappings()
            .first()
        )
        if reserved is None:
            existing = (
                (
                    await self.session.execute(
                        text("""SELECT request_hash,social_post_id,job_id FROM social_idempotency_records
                    WHERE tenant_id=:tenant AND action=:action AND subject_id=:subject AND key_hash=:key_hash"""),
                        {
                            "tenant": tenant_id,
                            "action": action,
                            "subject": ZERO_UUID,
                            "key_hash": key_hash,
                        },
                    )
                )
                .mappings()
                .one()
            )
            if existing["request_hash"] != request_hash:
                raise SocialError(
                    "SOCIAL_IDEMPOTENCY_CONFLICT",
                    "Idempotency key was used with a different request",
                    status_code=409,
                )
            await self.session.rollback()
            return (
                UUID(str(existing["social_post_id"])),
                UUID(str(existing["job_id"])),
                False,
            )

        await self.session.execute(
            text("""INSERT INTO social_posts
            (id,tenant_id,campaign_id,provider,status,content,publish_at,metadata)
            VALUES (:id,:tenant,:campaign,:provider,'QUEUED',CAST(:content AS jsonb),:publish_at,CAST(:metadata AS jsonb))"""),
            {
                "id": post_id,
                "tenant": tenant_id,
                "campaign": campaign_id,
                "provider": provider.value,
                "content": json.dumps(content),
                "publish_at": publish_at,
                "metadata": json.dumps(metadata),
            },
        )
        for account_id in account_ids:
            await self.session.execute(
                text(
                    "INSERT INTO social_post_accounts(social_post_id,social_account_id) VALUES (:post,:account)"
                ),
                {"post": post_id, "account": account_id},
            )
        await self.session.execute(
            text("""INSERT INTO social_publish_jobs
            (id,tenant_id,social_post_id,provider,job_type,state,correlation_id,request_id,idempotency_key)
            VALUES (:id,:tenant,:post,:provider,:job_type,'queued',:correlation,:request,:key)"""),
            {
                "id": job_id,
                "tenant": tenant_id,
                "post": post_id,
                "provider": provider.value,
                "job_type": action,
                "correlation": correlation_id,
                "request": request_id,
                "key": key_hash,
            },
        )
        await self._audit(
            tenant_id,
            "POST_CREATED",
            post_id,
            campaign_id,
            provider,
            correlation_id,
            request_id,
            job_id,
            key_hash,
            "QUEUED",
        )
        await self.session.execute(
            text("""INSERT INTO outbox_event(id,topic,payload,correlation_id,status,attempts)
            VALUES (:id,'social.job.signal',CAST(:payload AS jsonb),:correlation,'pending',0)"""),
            {
                "id": uuid4(),
                "payload": json.dumps(
                    {"job_id": str(job_id), "correlation_id": correlation_id}
                ),
                "correlation": correlation_id,
            },
        )
        await self.session.commit()
        return post_id, job_id, True

    async def get_post(self, post_id: UUID) -> SocialPost:
        row = (
            (
                await self.session.execute(
                    text("""SELECT p.*,COALESCE(array_agg(a.social_account_id) FILTER (WHERE a.social_account_id IS NOT NULL),'{}') accounts
                FROM social_posts p LEFT JOIN social_post_accounts a ON a.social_post_id=p.id
                WHERE p.id=:post GROUP BY p.id"""),
                    {"post": post_id},
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise SocialError(
                "SOCIAL_POST_NOT_FOUND", "Social post was not found", status_code=404
            )
        return SocialPost(
            tenant_id=UUID(str(row["tenant_id"])),
            provider=ProviderName(row["provider"]),
            account_ids=tuple(UUID(str(item)) for item in row["accounts"]),
            content=dict(row["content"]),
            id=UUID(str(row["id"])),
            campaign_id=UUID(str(row["campaign_id"])) if row["campaign_id"] else None,
            provider_post_id=row["provider_post_id"],
            status=SocialPostStatus(row["status"]),
            publish_at=row["publish_at"],
            metadata=dict(row["metadata"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def list_accounts(
        self, account_id: UUID | None = None
    ) -> list[dict[str, Any]]:
        query = (
            """SELECT id,tenant_id,provider,network,external_profile_name,
            external_profile_id,connection_state,capabilities,
            COALESCE(metadata->>'classification','UNKNOWN') classification,last_sync_at,
            created_at,updated_at FROM social_accounts
            WHERE id=:account_id ORDER BY created_at,id"""
            if account_id is not None
            else """SELECT id,tenant_id,provider,network,external_profile_name,
            external_profile_id,connection_state,capabilities,
            COALESCE(metadata->>'classification','UNKNOWN') classification,last_sync_at,
            created_at,updated_at FROM social_accounts ORDER BY created_at,id"""
        )
        rows = (
            (
                await self.session.execute(
                    text(query),
                    {"account_id": account_id} if account_id is not None else {},
                )
            )
            .mappings()
            .all()
        )
        return [dict(row) for row in rows]

    async def update_post(
        self,
        post_id: UUID,
        *,
        content: dict[str, Any] | None,
        metadata: dict[str, Any] | None,
        correlation_id: str,
        request_id: str,
    ) -> SocialPost:
        row = (
            (
                await self.session.execute(
                    text("""UPDATE social_posts
                SET content=COALESCE(CAST(:content AS jsonb),content),
                    metadata=COALESCE(CAST(:metadata AS jsonb),metadata),updated_at=now()
                WHERE id=:post AND status IN ('DRAFT','QUEUED','SCHEDULED')
                RETURNING tenant_id,provider,campaign_id"""),
                    {
                        "post": post_id,
                        "content": json.dumps(content) if content is not None else None,
                        "metadata": json.dumps(metadata)
                        if metadata is not None
                        else None,
                    },
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            exists = await self.session.scalar(
                text("SELECT 1 FROM social_posts WHERE id=:post"), {"post": post_id}
            )
            code = "SOCIAL_POST_NOT_EDITABLE" if exists else "SOCIAL_POST_NOT_FOUND"
            status_code = 409 if exists else 404
            raise SocialError(
                code, "Social post cannot be edited", status_code=status_code
            )
        await self.session.execute(
            text("""INSERT INTO social_audit_events
            (id,tenant_id,actor_type,actor_id,action,social_post_id,campaign_id,provider,
             correlation_id,request_id,result,metadata)
            VALUES (:id,:tenant,'machine','codestra-social-api','POST_UPDATED',:post,:campaign,
             :provider,:correlation,:request,'UPDATED','{}'::jsonb)"""),
            {
                "id": uuid4(),
                "tenant": row["tenant_id"],
                "post": post_id,
                "campaign": row["campaign_id"],
                "provider": row["provider"],
                "correlation": correlation_id,
                "request": request_id,
            },
        )
        await self.session.commit()
        return await self.get_post(post_id)

    async def staging_provider_account_refs(self, post_id: UUID) -> list[str]:
        rows = (
            (
                await self.session.execute(
                    text("""SELECT a.provider_account_id,a.connection_state,a.metadata
                FROM social_accounts a JOIN social_post_accounts p ON p.social_account_id=a.id
                WHERE p.social_post_id=:post ORDER BY a.id"""),
                    {"post": post_id},
                )
            )
            .mappings()
            .all()
        )
        if not rows:
            raise SocialError(
                "SOCIAL_ACCOUNT_NOT_FOUND",
                "No social account is assigned",
                status_code=422,
            )
        if any(
            row["connection_state"] != "connected"
            or dict(row["metadata"]).get("classification") != "STAGING_SAFE"
            for row in rows
        ):
            raise SocialError(
                "SOCIAL_ACCOUNT_NOT_STAGING_SAFE",
                "All target accounts must be connected staging accounts",
                status_code=403,
            )
        return [str(row["provider_account_id"]) for row in rows]

    async def production_publish_context(
        self, post: SocialPost, *, content_approved: bool
    ) -> ProductionPublishContext:
        rows = (
            (
                await self.session.execute(
                    text("""SELECT a.id,a.provider,a.connection_state,a.metadata
                FROM social_accounts a JOIN social_post_accounts p ON p.social_account_id=a.id
                WHERE p.social_post_id=:post ORDER BY a.id"""),
                    {"post": post.id},
                )
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            raise SocialError(
                "SOCIAL_PRODUCTION_SINGLE_ACCOUNT_REQUIRED",
                "Production canary requires exactly one account",
                status_code=403,
            )
        row = rows[0]
        if ProviderName(row["provider"]) is not post.provider:
            raise SocialError(
                "SOCIAL_PROVIDER_OWNERSHIP_MISMATCH",
                "Post and account providers do not match",
                status_code=409,
            )
        return ProductionPublishContext(
            tenant_id=post.tenant_id,
            campaign_id=post.campaign_id,
            account_id=UUID(str(row["id"])),
            provider=post.provider,
            classification=str(dict(row["metadata"]).get("classification", "UNKNOWN")),
            connection_state=str(row["connection_state"]),
            content_approved=content_approved,
        )

    async def audit_production_dry_run(
        self,
        post: SocialPost,
        context: ProductionPublishContext,
        *,
        correlation_id: str,
        request_id: str,
        idempotency_key: str,
    ) -> None:
        await self.session.execute(
            text("""INSERT INTO social_audit_events
            (id,tenant_id,actor_type,actor_id,action,social_post_id,campaign_id,provider,
             account_id,correlation_id,request_id,idempotency_key_hash,result,metadata)
            VALUES (:id,:tenant,'machine','codestra-social-api','PRODUCTION_DRY_RUN_VALIDATED',
             :post,:campaign,:provider,:account,:correlation,:request,:key_hash,'PASS',
             CAST(:metadata AS jsonb))"""),
            {
                "id": uuid4(),
                "tenant": post.tenant_id,
                "post": post.id,
                "campaign": post.campaign_id,
                "provider": post.provider.value,
                "account": context.account_id,
                "correlation": correlation_id,
                "request": request_id,
                "key_hash": hashlib.sha256(idempotency_key.encode()).hexdigest(),
                "metadata": json.dumps({"dry_run": True}),
            },
        )
        await self.session.commit()

    async def enqueue_command(
        self,
        *,
        post: SocialPost,
        action: JobType,
        idempotency_key: str,
        correlation_id: str,
        request_id: str,
        production_context: ProductionPublishContext | None = None,
    ) -> tuple[UUID, bool]:
        job_id = uuid4()
        key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
        request_hash = hashlib.sha256(f"{post.id}:{action.value}".encode()).hexdigest()
        reserved = (
            await self.session.execute(
                text("""INSERT INTO social_idempotency_records
                (tenant_id,action,subject_id,key_hash,request_hash,social_post_id,job_id)
                VALUES (:tenant,:action,:subject,:key_hash,:request_hash,:post,:job)
                ON CONFLICT DO NOTHING RETURNING job_id"""),
                {
                    "tenant": post.tenant_id,
                    "action": action.value,
                    "subject": post.id,
                    "key_hash": key_hash,
                    "request_hash": request_hash,
                    "post": post.id,
                    "job": job_id,
                },
            )
        ).scalar_one_or_none()
        if reserved is None:
            existing = (
                (
                    await self.session.execute(
                        text("""SELECT request_hash,job_id FROM social_idempotency_records
                    WHERE tenant_id=:tenant AND action=:action AND subject_id=:subject AND key_hash=:key_hash"""),
                        {
                            "tenant": post.tenant_id,
                            "action": action.value,
                            "subject": post.id,
                            "key_hash": key_hash,
                        },
                    )
                )
                .mappings()
                .one()
            )
            if existing["request_hash"] != request_hash:
                raise SocialError(
                    "SOCIAL_IDEMPOTENCY_CONFLICT",
                    "Idempotency key was used with a different request",
                    status_code=409,
                )
            await self.session.rollback()
            return UUID(str(existing["job_id"])), False
        await self.session.execute(
            text("""INSERT INTO social_publish_jobs
            (id,tenant_id,social_post_id,provider,job_type,state,correlation_id,request_id,idempotency_key,
             production_canary,production_account_id,content_approved_at)
            VALUES (:id,:tenant,:post,:provider,:job_type,'queued',:correlation,:request,:key,
             :production_canary,:production_account,CASE WHEN :content_approved THEN now() END)"""),
            {
                "id": job_id,
                "tenant": post.tenant_id,
                "post": post.id,
                "provider": post.provider.value,
                "job_type": action.value,
                "correlation": correlation_id,
                "request": request_id,
                "key": key_hash,
                "production_canary": production_context is not None,
                "production_account": production_context.account_id
                if production_context
                else None,
                "content_approved": bool(
                    production_context and production_context.content_approved
                ),
            },
        )
        await self._audit(
            post.tenant_id,
            f"POST_{action.name}_REQUESTED",
            post.id,
            post.campaign_id,
            post.provider,
            correlation_id,
            request_id,
            job_id,
            key_hash,
            "QUEUED",
            production_context.account_id if production_context else None,
        )
        await self.session.execute(
            text("""INSERT INTO outbox_event(id,topic,payload,correlation_id,status,attempts)
            VALUES (:id,'social.job.signal',CAST(:payload AS jsonb),:correlation,'pending',0)"""),
            {
                "id": uuid4(),
                "payload": json.dumps(
                    {"job_id": str(job_id), "correlation_id": correlation_id}
                ),
                "correlation": correlation_id,
            },
        )
        await self.session.commit()
        return job_id, True

    async def claim_jobs(
        self, *, worker_id: str, limit: int, lease_seconds: int
    ) -> list[dict[str, Any]]:
        rows = await self.session.execute(
            text("""WITH claimable AS (
              SELECT id FROM social_publish_jobs
              WHERE state IN ('queued','retry') AND (next_attempt_at IS NULL OR next_attempt_at<=now())
                AND (lease_expires_at IS NULL OR lease_expires_at<=now())
              ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT :limit)
            UPDATE social_publish_jobs j SET state='processing',lease_owner=:worker,
              lease_expires_at=now()+make_interval(secs=>:lease),fencing_token=fencing_token+1,updated_at=now()
            FROM claimable WHERE j.id=claimable.id RETURNING j.*"""),
            {"worker": worker_id, "lease": lease_seconds, "limit": limit},
        )
        await self.session.commit()
        return [dict(row) for row in rows.mappings()]

    async def recover_stale_jobs(self) -> list[tuple[UUID, str]]:
        rows = await self.session.execute(
            text("""UPDATE social_publish_jobs SET state='retry',lease_owner=NULL,lease_expires_at=NULL,
            next_attempt_at=now(),last_error_code=COALESCE(last_error_code,'SOCIAL_WORKER_LEASE_EXPIRED'),updated_at=now()
            WHERE state='processing' AND lease_expires_at<=now() RETURNING id,correlation_id""")
        )
        await self.session.commit()
        return [
            (UUID(str(row["id"])), str(row["correlation_id"]))
            for row in rows.mappings()
        ]

    async def signalable_jobs(self, limit: int = 100) -> list[tuple[UUID, str]]:
        rows = await self.session.execute(
            text("""SELECT id,correlation_id FROM social_publish_jobs
            WHERE state IN ('queued','retry')
              AND (next_attempt_at IS NULL OR next_attempt_at<=now())
              AND (lease_expires_at IS NULL OR lease_expires_at<=now())
            ORDER BY created_at,id LIMIT :limit"""),
            {"limit": limit},
        )
        return [
            (UUID(str(row["id"])), str(row["correlation_id"]))
            for row in rows.mappings()
        ]

    async def complete_job(
        self,
        job: dict[str, Any],
        *,
        provider_post_id: str | None,
        status: SocialPostStatus,
    ) -> UUID:
        event_id = uuid4()
        event_type = f"social.post.{status.value.lower()}"
        completed = (
            await self.session.execute(
                text("""UPDATE social_publish_jobs SET state='completed',result_certainty='CONFIRMED',lease_owner=NULL,
            lease_expires_at=NULL,updated_at=now()
            WHERE id=:job AND state='processing' AND fencing_token=:token RETURNING id"""),
                {"job": job["id"], "token": job["fencing_token"]},
            )
        ).scalar_one_or_none()
        if completed is None:
            await self.session.rollback()
            raise SocialError(
                "SOCIAL_WORKER_LEASE_LOST",
                "Social job lease was lost before result persistence",
                status_code=409,
                unknown_result=True,
            )
        await self.session.execute(
            text("""UPDATE social_posts SET provider_post_id=COALESCE(:provider_post_id,provider_post_id),status=:status,updated_at=now()
            WHERE id=:post"""),
            {
                "provider_post_id": provider_post_id,
                "status": status.value,
                "post": job["social_post_id"],
            },
        )
        await self.session.execute(
            text("""INSERT INTO social_publish_attempts(id,job_id,attempt_number,result,created_at)
            VALUES (:id,:job,:attempt,'SUCCESS',now())"""),
            {"id": uuid4(), "job": job["id"], "attempt": int(job["attempt_count"]) + 1},
        )
        payload = {
            "event_id": str(event_id),
            "event_type": event_type,
            "event_version": 1,
            "correlation_id": job["correlation_id"],
            "tenant_id": str(job["tenant_id"]),
            "source": "social",
            "provider": job["provider"],
            "subject_id": str(job["social_post_id"]),
            "payload": {"status": status.value},
        }
        payload_json = json.dumps(payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
        integration_id = (
            await self.session.execute(
                text("""INSERT INTO integration_event
                (idempotency_key,event_type,schema_version,original_event_id,entity_key,source_system,correlation_id,payload_json,payload_hash,state)
                VALUES (:key,:type,'1.0',:original,:entity,'social',:correlation,CAST(:payload AS jsonb),:hash,'queued') RETURNING id"""),
                {
                    "key": f"social:{event_id}",
                    "type": event_type,
                    "original": str(event_id),
                    "entity": f"social_post:{job['social_post_id']}",
                    "correlation": job["correlation_id"],
                    "payload": payload_json,
                    "hash": payload_hash,
                },
            )
        ).scalar_one()
        await self.session.execute(
            text("""INSERT INTO social_provider_events
            (id,event_type,event_version,occurred_at,correlation_id,tenant_id,provider,subject_id,payload)
            VALUES (:id,:type,1,now(),:correlation,:tenant,:provider,:subject,CAST(:payload AS jsonb))"""),
            {
                "id": event_id,
                "type": event_type,
                "correlation": job["correlation_id"],
                "tenant": job["tenant_id"],
                "provider": job["provider"],
                "subject": job["social_post_id"],
                "payload": json.dumps(payload["payload"]),
            },
        )
        if settings.social_n8n_events_enabled:
            await self.session.execute(
                text("""INSERT INTO integration_delivery(id,event_id,target,status,attempts)
                VALUES (:id,:event,'n8n','pending',0) ON CONFLICT DO NOTHING"""),
                {"id": uuid4(), "event": integration_id},
            )
        if job.get("production_canary"):
            await self.session.execute(
                text("""INSERT INTO social_audit_events
                (id,tenant_id,actor_type,actor_id,action,social_post_id,provider,account_id,
                 correlation_id,request_id,job_id,result,metadata)
                VALUES (:id,:tenant,'machine','postly-social-01','POST_PUBLISHED',:post,
                 :provider,:account,:correlation,:request,:job,'PUBLISHED',CAST(:metadata AS jsonb))"""),
                {
                    "id": uuid4(),
                    "tenant": job["tenant_id"],
                    "post": job["social_post_id"],
                    "provider": job["provider"],
                    "account": job["production_account_id"],
                    "correlation": job["correlation_id"],
                    "request": job["request_id"],
                    "job": job["id"],
                    "metadata": json.dumps(
                        {"provider_post_id": provider_post_id}
                        if provider_post_id
                        else {}
                    ),
                },
            )
        await self.session.commit()
        return event_id

    async def fail_job(
        self,
        job: dict[str, Any],
        error: SocialError,
        *,
        max_attempts: int,
        delay_seconds: float,
    ) -> str:
        attempts = int(job["attempt_count"]) + 1
        unknown = error.unknown_result or error.code == "SOCIAL_PROVIDER_UNKNOWN_RESULT"
        dead = unknown or not error.retryable or attempts >= max_attempts
        state = "dead_letter" if dead else "retry"
        certainty = "UNKNOWN_AFTER_SEND" if unknown else "FAILED_BEFORE_SEND"
        next_at = (
            None
            if dead
            else datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
        )
        updated = (
            await self.session.execute(
                text("""UPDATE social_publish_jobs SET state=:state,attempt_count=:attempts,result_certainty=:certainty,
            last_error_code=:code,last_error_summary=:summary,next_attempt_at=:next_at,lease_owner=NULL,lease_expires_at=NULL,
            failed_at=:failed_at,updated_at=now()
            WHERE id=:job AND state='processing' AND fencing_token=:token RETURNING id"""),
                {
                    "state": state,
                    "attempts": attempts,
                    "certainty": certainty,
                    "code": error.code,
                    "summary": error.safe_message[:512],
                    "next_at": next_at,
                    "failed_at": datetime.now(timezone.utc) if dead else None,
                    "job": job["id"],
                    "token": job["fencing_token"],
                },
            )
        ).scalar_one_or_none()
        if updated is None:
            await self.session.rollback()
            return "lease_lost"
        await self.session.execute(
            text("""INSERT INTO social_publish_attempts(id,job_id,attempt_number,result,error_code,error_summary,created_at)
            VALUES (:id,:job,:attempt,:result,:code,:summary,now())"""),
            {
                "id": uuid4(),
                "job": job["id"],
                "attempt": attempts,
                "result": state.upper(),
                "code": error.code,
                "summary": error.safe_message[:512],
            },
        )
        if job.get("production_canary"):
            await self.session.execute(
                text("""INSERT INTO social_audit_events
                (id,tenant_id,actor_type,actor_id,action,social_post_id,provider,account_id,
                 correlation_id,request_id,job_id,result,error_code,metadata)
                VALUES (:id,:tenant,'machine','postly-social-01','POST_FAILED',:post,
                 :provider,:account,:correlation,:request,:job,:result,:error,'{}'::jsonb)"""),
                {
                    "id": uuid4(),
                    "tenant": job["tenant_id"],
                    "post": job["social_post_id"],
                    "provider": job["provider"],
                    "account": job["production_account_id"],
                    "correlation": job["correlation_id"],
                    "request": job["request_id"],
                    "job": job["id"],
                    "result": state.upper(),
                    "error": error.code,
                },
            )
        await self.session.commit()
        return state

    async def persist_webhook(
        self,
        *,
        provider: ProviderName,
        provider_event_id: str,
        payload_hash: str,
        correlation_id: str,
        event: NormalizedEvent,
        safe_payload: dict[str, Any],
    ) -> bool:
        row = await self.session.execute(
            text("""INSERT INTO social_webhook_events
            (id,provider,provider_event_id,payload_hash,signature_valid,state,correlation_id,safe_payload,
             normalized_event_type,subject_id,tenant_id,received_at)
            VALUES (:id,:provider,:provider_event,:hash,true,'accepted',:correlation,CAST(:payload AS jsonb),
             :type,:subject,:tenant,now()) ON CONFLICT (provider,provider_event_id) DO NOTHING RETURNING id"""),
            {
                "id": uuid4(),
                "provider": provider.value,
                "provider_event": provider_event_id,
                "hash": payload_hash,
                "correlation": correlation_id,
                "payload": json.dumps(safe_payload),
                "type": event.event_type,
                "subject": event.subject_id,
                "tenant": event.tenant_id,
            },
        )
        created = row.scalar_one_or_none() is not None
        if created:
            normalized_payload = {
                "event_id": str(event.event_id),
                "event_type": event.event_type,
                "event_version": event.event_version,
                "occurred_at": event.occurred_at.isoformat(),
                "correlation_id": correlation_id,
                "tenant_id": str(event.tenant_id),
                "source": "social",
                "provider": provider.value,
                "subject_id": str(event.subject_id),
                "payload": safe_payload,
            }
            normalized_json = json.dumps(normalized_payload, sort_keys=True)
            normalized_hash = hashlib.sha256(normalized_json.encode()).hexdigest()
            await self.session.execute(
                text("""INSERT INTO social_provider_events
                (id,event_type,event_version,occurred_at,correlation_id,tenant_id,provider,subject_id,payload)
                VALUES (:id,:type,:version,:occurred,:correlation,:tenant,:provider,:subject,CAST(:payload AS jsonb))"""),
                {
                    "id": event.event_id,
                    "type": event.event_type,
                    "version": event.event_version,
                    "occurred": event.occurred_at,
                    "correlation": correlation_id,
                    "tenant": event.tenant_id,
                    "provider": provider.value,
                    "subject": event.subject_id,
                    "payload": json.dumps(safe_payload),
                },
            )
            integration_id = (
                await self.session.execute(
                    text("""INSERT INTO integration_event
                    (idempotency_key,event_type,schema_version,original_event_id,entity_key,source_system,
                     correlation_id,payload_json,payload_hash,state)
                    VALUES (:key,:type,'1.0',:original,:entity,'social',:correlation,
                     CAST(:payload AS jsonb),:hash,'queued') RETURNING id"""),
                    {
                        "key": f"social-webhook:{provider.value}:{provider_event_id}",
                        "type": event.event_type,
                        "original": str(event.event_id),
                        "entity": f"social:{event.subject_id}",
                        "correlation": correlation_id,
                        "payload": normalized_json,
                        "hash": normalized_hash,
                    },
                )
            ).scalar_one()
            if settings.social_n8n_events_enabled:
                await self.session.execute(
                    text("""INSERT INTO integration_delivery(id,event_id,target,status,attempts)
                    VALUES (:id,:event,'n8n','pending',0) ON CONFLICT DO NOTHING"""),
                    {"id": uuid4(), "event": integration_id},
                )
        await self.session.commit()
        return created

    async def _audit(
        self,
        tenant_id: UUID,
        action: str,
        post_id: UUID,
        campaign_id: UUID | None,
        provider: ProviderName,
        correlation_id: str,
        request_id: str,
        job_id: UUID,
        key_hash: str,
        result: str,
        account_id: UUID | None = None,
    ) -> None:
        await self.session.execute(
            text("""INSERT INTO social_audit_events
            (id,tenant_id,actor_type,actor_id,action,social_post_id,campaign_id,provider,account_id,correlation_id,
             request_id,job_id,idempotency_key_hash,result,metadata)
            VALUES (:id,:tenant,'machine','codestra-social-api',:action,:post,:campaign,:provider,:account,:correlation,
             :request,:job,:key_hash,:result,'{}'::jsonb)"""),
            {
                "id": uuid4(),
                "tenant": tenant_id,
                "action": action,
                "post": post_id,
                "campaign": campaign_id,
                "provider": provider.value,
                "account": account_id,
                "correlation": correlation_id,
                "request": request_id,
                "job": job_id,
                "key_hash": key_hash,
                "result": result,
            },
        )
