from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_session
from app.social.adapters import HootsuiteProviderAdapter, PostlyProviderAdapter
from app.social.domain import Capability, JobType
from app.social.providers import SocialError, SocialProviderRegistry
from app.social.production import ProductionCanaryPolicy, require_provider_health
from app.social.service import SocialPublishingService
from app.social.sql_repository import SqlSocialRepository
from app.social import metrics


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MediaReference(StrictModel):
    asset_id: UUID


class Content(StrictModel):
    text: str = Field(min_length=1, max_length=10000)
    media: list[MediaReference] = Field(default_factory=list, max_length=50)


class Schedule(StrictModel):
    publish_at: datetime


class CreateSocialPost(StrictModel):
    id: UUID | None = None
    tenant_id: UUID
    campaign_id: UUID | None = None
    accounts: list[UUID] = Field(min_length=1, max_length=50)
    content: Content
    schedule: Schedule | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateSocialPost(StrictModel):
    content: Content | None = None
    metadata: dict[str, Any] | None = None


class CreateCampaign(StrictModel):
    tenant_id: UUID
    name: str = Field(min_length=1, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


registry = SocialProviderRegistry()
registry.register(PostlyProviderAdapter())
registry.register(HootsuiteProviderAdapter())
service = SocialPublishingService(registry)
campaign_store: dict[UUID, dict[str, Any]] = {}
router = APIRouter(prefix="/api/v1/social", tags=["social"])


def _error(exc: SocialError) -> HTTPException:
    return HTTPException(
        exc.status_code,
        {"code": exc.code, "message": exc.safe_message, "retryable": exc.retryable},
    )


def _require(permission: str, supplied: str | None) -> None:
    permissions = {item.strip() for item in (supplied or "").split(",") if item.strip()}
    if permission not in permissions and "social.admin" not in permissions:
        raise HTTPException(
            403,
            {
                "code": "SOCIAL_PERMISSION_DENIED",
                "message": f"Permission {permission} is required",
            },
        )


def _ids(request: Request) -> tuple[str, str]:
    return (
        request.headers.get("X-Correlation-ID") or str(uuid4()),
        request.headers.get("X-Request-ID") or str(uuid4()),
    )


def _post(post: Any) -> dict[str, Any]:
    return {
        "id": post.id,
        "tenant_id": post.tenant_id,
        "campaign_id": post.campaign_id,
        "accounts": post.account_ids,
        "content": post.content,
        "schedule": {"publish_at": post.publish_at} if post.publish_at else None,
        "provider": post.provider,
        "status": post.status,
        "created_at": post.created_at,
        "updated_at": post.updated_at,
    }


@router.get("/providers")
async def providers(
    x_codestra_permissions: str | None = Header(None),
) -> list[dict[str, Any]]:
    _require("social.read", x_codestra_permissions)
    return [
        {"provider": item.name, "capabilities": sorted(item.get_capabilities())}
        for item in registry.providers()
    ]


@router.get("/providers/{provider}")
async def provider(
    provider: str, x_codestra_permissions: str | None = Header(None)
) -> dict[str, Any]:
    _require("social.read", x_codestra_permissions)
    try:
        adapter = registry.get(provider)
        result = await adapter.health_check()
        result["capabilities"] = sorted(adapter.get_capabilities())
        return result
    except SocialError as exc:
        raise _error(exc) from exc


@router.get("/accounts")
async def accounts(
    session: AsyncSession = Depends(get_session),
    x_codestra_permissions: str | None = Header(None),
) -> list[dict[str, Any]]:
    _require("social.accounts.read", x_codestra_permissions)
    if settings.social_sql_repository_enabled:
        return await SqlSocialRepository(session).list_accounts()
    return [
        {
            "id": item.id,
            "provider": item.provider,
            "network": item.network,
            "external_profile_name": item.external_profile_name,
            "external_profile_id": item.external_profile_id,
            "connection_state": item.connection_state,
            "capabilities": sorted(item.capabilities),
            "last_sync_at": item.last_sync_at,
        }
        for item in service.repository.accounts.values()
    ]


@router.get("/accounts/{account_id}")
async def account(
    account_id: UUID,
    session: AsyncSession = Depends(get_session),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    _require("social.accounts.read", x_codestra_permissions)
    if settings.social_sql_repository_enabled:
        rows = await SqlSocialRepository(session).list_accounts(account_id)
        if not rows:
            raise HTTPException(
                404,
                {
                    "code": "SOCIAL_ACCOUNT_NOT_FOUND",
                    "message": "Social account was not found",
                },
            )
        return rows[0]
    try:
        item = service.repository.accounts[account_id]
    except KeyError as exc:
        raise HTTPException(
            404,
            {
                "code": "SOCIAL_ACCOUNT_NOT_FOUND",
                "message": "Social account was not found",
            },
        ) from exc
    return {
        "id": item.id,
        "provider": item.provider,
        "network": item.network,
        "external_profile_name": item.external_profile_name,
        "external_profile_id": item.external_profile_id,
        "connection_state": item.connection_state,
        "capabilities": sorted(item.capabilities),
        "last_sync_at": item.last_sync_at,
    }


@router.post("/posts", status_code=202)
async def create_post(
    body: CreateSocialPost,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
    idempotency_key: str = Header(min_length=1, max_length=255),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    _require("social.write", x_codestra_permissions)
    correlation_id, request_id = _ids(request)
    try:
        if settings.social_sql_repository_enabled:
            if not settings.social_integration_enabled:
                raise SocialError(
                    "SOCIAL_PROVIDER_DISABLED",
                    "Social integration is disabled",
                    status_code=503,
                )
            provider_name = service.resolve_provider()
            registry.require(provider_name, Capability.POST_CREATE)
            repository = SqlSocialRepository(session)
            post_id, job_id, created = await repository.create_post_intent(
                tenant_id=body.tenant_id,
                provider=provider_name,
                account_ids=tuple(body.accounts),
                content=body.content.model_dump(mode="json"),
                campaign_id=body.campaign_id,
                publish_at=body.schedule.publish_at if body.schedule else None,
                metadata=body.metadata,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
                request_id=request_id,
                post_id=body.id,
            )
            post = await repository.get_post(post_id)
            metrics.publish_requests.labels(
                provider_name.value, "other", "queued"
            ).inc()
            response.headers["X-Correlation-ID"] = correlation_id
            return {
                "post": _post(post),
                "job_id": job_id,
                "idempotent_replay": not created,
            }
        post, job, created = await service.create_post(
            tenant_id=body.tenant_id,
            account_ids=tuple(body.accounts),
            content=body.content.model_dump(mode="json"),
            campaign_id=body.campaign_id,
            publish_at=body.schedule.publish_at if body.schedule else None,
            metadata=body.metadata,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            request_id=request_id,
            post_id=body.id,
        )
    except SocialError as exc:
        raise _error(exc) from exc
    response.headers["X-Correlation-ID"] = correlation_id
    return {"post": _post(post), "job_id": job.id, "idempotent_replay": not created}


@router.get("/posts/{post_id}")
async def get_post(
    post_id: UUID,
    session: AsyncSession = Depends(get_session),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    _require("social.read", x_codestra_permissions)
    try:
        if settings.social_sql_repository_enabled:
            return _post(await SqlSocialRepository(session).get_post(post_id))
        return _post(service.repository.posts[post_id])
    except (KeyError, SocialError) as exc:
        raise HTTPException(
            404,
            {"code": "SOCIAL_POST_NOT_FOUND", "message": "Social post was not found"},
        ) from exc


@router.patch("/posts/{post_id}")
async def update_post(
    post_id: UUID,
    body: UpdateSocialPost,
    request: Request,
    session: AsyncSession = Depends(get_session),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    _require("social.write", x_codestra_permissions)
    if settings.social_sql_repository_enabled:
        correlation_id, request_id = _ids(request)
        try:
            return _post(
                await SqlSocialRepository(session).update_post(
                    post_id,
                    content=body.content.model_dump(mode="json")
                    if body.content is not None
                    else None,
                    metadata=body.metadata,
                    correlation_id=correlation_id,
                    request_id=request_id,
                )
            )
        except SocialError as exc:
            raise _error(exc) from exc
    try:
        post = service.repository.posts[post_id]
    except KeyError as exc:
        raise HTTPException(
            404,
            {"code": "SOCIAL_POST_NOT_FOUND", "message": "Social post was not found"},
        ) from exc
    if post.status not in {"DRAFT", "QUEUED", "SCHEDULED"}:
        raise HTTPException(
            409,
            {
                "code": "SOCIAL_POST_NOT_EDITABLE",
                "message": "Social post cannot be edited in its current state",
            },
        )
    if body.content is not None:
        post.content = body.content.model_dump(mode="json")
    if body.metadata is not None:
        post.metadata = body.metadata
    post.updated_at = datetime.now(timezone.utc)
    return _post(post)


@router.post("/media", status_code=202)
async def media(x_codestra_permissions: str | None = Header(None)) -> dict[str, Any]:
    _require("social.write", x_codestra_permissions)
    raise HTTPException(
        503,
        {
            "code": "SOCIAL_PROVIDER_DISABLED",
            "message": "Social media upload is disabled",
        },
    )


@router.post("/campaigns", status_code=201)
async def create_campaign(
    body: CreateCampaign, x_codestra_permissions: str | None = Header(None)
) -> dict[str, Any]:
    _require("social.write", x_codestra_permissions)
    campaign_id = uuid4()
    campaign_store[campaign_id] = {
        "id": campaign_id,
        "tenant_id": body.tenant_id,
        "name": body.name,
        "status": "DRAFT",
        "metadata": body.metadata,
        "created_at": datetime.now(timezone.utc),
    }
    return campaign_store[campaign_id]


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: UUID, x_codestra_permissions: str | None = Header(None)
) -> dict[str, Any]:
    _require("social.read", x_codestra_permissions)
    try:
        return campaign_store[campaign_id]
    except KeyError as exc:
        raise HTTPException(
            404,
            {
                "code": "SOCIAL_CAMPAIGN_NOT_FOUND",
                "message": "Social campaign was not found",
            },
        ) from exc


@router.get("/analytics")
async def analytics(
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    _require("social.analytics.read", x_codestra_permissions)
    return {"items": [], "sync_enabled": False}


async def _command(
    post_id: UUID,
    action: JobType,
    request: Request,
    idempotency_key: str,
    permission: str,
    supplied: str | None,
    session: AsyncSession,
    *,
    dry_run: bool = False,
    content_approved: bool = False,
) -> dict[str, Any]:
    _require(permission, supplied)
    correlation_id, request_id = _ids(request)
    try:
        if dry_run and (
            action is not JobType.PUBLISH
            or not settings.social_production_mode
            or not settings.social_sql_repository_enabled
        ):
            raise SocialError(
                "SOCIAL_PRODUCTION_CANARY_DISABLED",
                "Production dry-run requires SQL-backed production canary mode",
                status_code=403,
            )
        if settings.social_sql_repository_enabled:
            if not settings.social_integration_enabled:
                raise SocialError(
                    "SOCIAL_PROVIDER_DISABLED",
                    "Social integration is disabled",
                    status_code=503,
                )
            repository = SqlSocialRepository(session)
            post = await repository.get_post(post_id)
            capability = {
                JobType.PUBLISH: Capability.POST_PUBLISH,
                JobType.SCHEDULE: Capability.POST_SCHEDULE,
                JobType.CANCEL: Capability.POST_CANCEL,
                JobType.DELETE: Capability.POST_DELETE,
            }[action]
            registry.require(post.provider, capability)
            if action is JobType.PUBLISH and not settings.social_publish_enabled:
                raise SocialError(
                    "SOCIAL_PROVIDER_DISABLED",
                    "Social publishing is disabled",
                    status_code=403,
                )
            if action is JobType.PUBLISH and settings.social_production_mode:
                try:
                    production_context = await repository.production_publish_context(
                        post, content_approved=content_approved
                    )
                    metrics.production_account_connected.labels(
                        post.provider.value, "other"
                    ).set(
                        1 if production_context.connection_state == "connected" else 0
                    )
                    ProductionCanaryPolicy(settings).validate(production_context)
                    require_provider_health(
                        await registry.get(post.provider).health_check()
                    )
                except SocialError as exc:
                    metrics.production_canary_denied.labels(exc.code).inc()
                    if exc.code == "SOCIAL_PROVIDER_FAILOVER_FORBIDDEN":
                        metrics.provider_failover_attempt.labels(
                            post.provider.value, "forbidden"
                        ).inc()
                    if exc.code == "SOCIAL_DUAL_PUBLISH_FORBIDDEN":
                        metrics.dual_publish_attempt.labels(post.provider.value).inc()
                    raise
                metrics.production_publish_requests.labels(
                    post.provider.value, "other", "dry_run" if dry_run else "accepted"
                ).inc()
                if dry_run:
                    await repository.audit_production_dry_run(
                        post,
                        production_context,
                        correlation_id=correlation_id,
                        request_id=request_id,
                        idempotency_key=idempotency_key,
                    )
                    return {
                        "post_id": post_id,
                        "provider": post.provider,
                        "account_id": production_context.account_id,
                        "dry_run": True,
                        "validation": "PASS",
                        "external_side_effect": False,
                    }
            job_id, created = await repository.enqueue_command(
                post=post,
                action=action,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
                request_id=request_id,
                production_context=production_context
                if action is JobType.PUBLISH and settings.social_production_mode
                else None,
            )
            if not created:
                metrics.duplicate_prevention.labels(
                    post.provider.value, action.value
                ).inc()
            return {
                "post_id": post_id,
                "job_id": job_id,
                "status": "QUEUED",
                "idempotent_replay": not created,
            }
        job, created = await service.command(
            post_id, action, idempotency_key, correlation_id, request_id
        )
    except SocialError as exc:
        raise _error(exc) from exc
    return {
        "post_id": post_id,
        "job_id": job.id,
        "status": job.state.upper(),
        "idempotent_replay": not created,
    }


@router.post("/posts/{post_id}/schedule", status_code=202)
async def schedule(
    post_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    idempotency_key: str = Header(min_length=1, max_length=255),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    return await _command(
        post_id,
        JobType.SCHEDULE,
        request,
        idempotency_key,
        "social.schedule",
        x_codestra_permissions,
        session,
    )


@router.post("/posts/{post_id}/publish", status_code=202)
async def publish(
    post_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    idempotency_key: str = Header(min_length=1, max_length=255),
    x_codestra_permissions: str | None = Header(None),
    dry_run: bool = False,
    x_social_content_approved: bool = Header(False),
) -> dict[str, Any]:
    return await _command(
        post_id,
        JobType.PUBLISH,
        request,
        idempotency_key,
        "social.publish",
        x_codestra_permissions,
        session,
        dry_run=dry_run,
        content_approved=x_social_content_approved,
    )


@router.post("/posts/{post_id}/cancel", status_code=202)
async def cancel(
    post_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    idempotency_key: str = Header(min_length=1, max_length=255),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    return await _command(
        post_id,
        JobType.CANCEL,
        request,
        idempotency_key,
        "social.cancel",
        x_codestra_permissions,
        session,
    )


@router.delete("/posts/{post_id}", status_code=202)
async def delete(
    post_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    idempotency_key: str = Header(min_length=1, max_length=255),
    x_codestra_permissions: str | None = Header(None),
) -> dict[str, Any]:
    return await _command(
        post_id,
        JobType.DELETE,
        request,
        idempotency_key,
        "social.delete",
        x_codestra_permissions,
        session,
    )


@router.post("/webhooks/{provider}", status_code=202)
async def webhook(
    provider: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    body = await request.body()
    correlation_id, _ = _ids(request)
    try:
        adapter = registry.require(provider, capability=Capability.WEBHOOK_EVENTS)
        await adapter.verify_webhook(body, request.headers)
        metrics.webhooks_received.labels(provider, "verified").inc()
        payload = json.loads(body)
        event_id = str(payload.get("id", ""))
        if not event_id:
            raise SocialError(
                "SOCIAL_WEBHOOK_INVALID",
                "Webhook event ID is required",
                status_code=422,
            )
        if (
            not settings.social_sql_repository_enabled
            and event_id in service.repository.webhook_ids
        ):
            return {"accepted": True, "duplicate": True}
        event = await adapter.normalize_webhook(payload, correlation_id)
        if settings.social_sql_repository_enabled:
            created = await SqlSocialRepository(session).persist_webhook(
                provider=event.provider,
                provider_event_id=event_id,
                payload_hash=hashlib.sha256(body).hexdigest(),
                correlation_id=correlation_id,
                event=event,
                safe_payload=event.payload,
            )
            if not created:
                return {"accepted": True, "duplicate": True}
        else:
            service.repository.webhook_ids.add(event_id)
        return {
            "accepted": True,
            "duplicate": False,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "occurred_at": datetime.now(timezone.utc),
        }
    except (SocialError, json.JSONDecodeError) as exc:
        if isinstance(exc, SocialError):
            metrics.webhooks_rejected.labels(provider, exc.code).inc()
            raise _error(exc) from exc
        metrics.webhooks_rejected.labels(provider, "malformed_json").inc()
        raise HTTPException(
            422,
            {"code": "SOCIAL_WEBHOOK_INVALID", "message": "Webhook payload is invalid"},
        ) from exc
