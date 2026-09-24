from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from app.core.config import settings
from app.integrations.postiz.client import PostizClient
from app.integrations.postiz.exceptions import PostizError
from app.social.domain import (
    Capability,
    NormalizedEvent,
    ProviderName,
    ProviderResult,
    SocialPost,
    SocialPostStatus,
)
from app.social.providers import SocialError, SocialProviderAdapter


POSTLY_CAPABILITIES = frozenset(
    {
        Capability.POST_CREATE,
        Capability.POST_DELETE,
        Capability.POST_SCHEDULE,
        Capability.POST_CANCEL,
        Capability.POST_PUBLISH,
        Capability.MEDIA_UPLOAD,
        Capability.IMAGE_POST,
        Capability.VIDEO_POST,
        Capability.MULTI_IMAGE,
        Capability.ANALYTICS,
        Capability.WEBHOOK_EVENTS,
    }
)


STATUS_MAP = {
    "draft": SocialPostStatus.DRAFT,
    "queued": SocialPostStatus.QUEUED,
    "scheduled": SocialPostStatus.SCHEDULED,
    "publishing": SocialPostStatus.PUBLISHING,
    "published": SocialPostStatus.PUBLISHED,
    "failed": SocialPostStatus.FAILED,
    "cancelled": SocialPostStatus.CANCELLED,
    "canceled": SocialPostStatus.CANCELLED,
    "deleted": SocialPostStatus.DELETED,
    "requires_action": SocialPostStatus.REQUIRES_ACTION,
}


def normalize_status(value: str | None) -> SocialPostStatus:
    return STATUS_MAP.get((value or "").strip().lower(), SocialPostStatus.UNKNOWN)


def map_postiz_error(exc: PostizError) -> SocialError:
    mappings = {
        "not_configured": ("SOCIAL_PROVIDER_NOT_CONFIGURED", 503),
        "authentication": ("SOCIAL_PROVIDER_AUTH_FAILED", 502),
        "rate_limit": ("SOCIAL_PROVIDER_RATE_LIMITED", 503),
        "temporary": ("SOCIAL_PROVIDER_UNAVAILABLE", 503),
        "unknown_result": ("SOCIAL_PROVIDER_UNKNOWN_RESULT", 503),
    }
    code, status = mappings.get(exc.code, ("SOCIAL_PUBLISH_FAILED", 502))
    return SocialError(
        code,
        "Social provider request failed",
        retryable=exc.retryable,
        status_code=status,
        unknown_result=exc.unknown_result,
    )


class PostlyProviderAdapter(SocialProviderAdapter):
    """Postly/Postiz boundary. No provider payload escapes this adapter."""

    name = ProviderName.POSTLY

    def __init__(self, client: PostizClient | None = None) -> None:
        self.client = client or PostizClient()

    def get_capabilities(self) -> frozenset[Capability]:
        return POSTLY_CAPABILITIES

    async def health_check(self) -> dict[str, Any]:
        configured = bool(
            settings.postiz_internal_base_url and settings.postiz_api_key_file
        )
        if not configured:
            return {
                "provider": self.name,
                "configured": False,
                "enabled": False,
                "reachable": False,
                "status": "NOT_CONFIGURED",
            }
        if not settings.postiz_delivery_enabled:
            return {
                "provider": self.name,
                "configured": True,
                "enabled": False,
                "reachable": None,
                "status": "DISABLED",
            }
        try:
            await self.client.connection_check("social-health-check")
        except PostizError:
            return {
                "provider": self.name,
                "configured": True,
                "enabled": True,
                "reachable": False,
                "status": "UNAVAILABLE",
            }
        return {
            "provider": self.name,
            "configured": True,
            "enabled": True,
            "reachable": True,
            "status": "AVAILABLE",
        }

    async def list_accounts(self) -> list[dict[str, Any]]:
        try:
            result = await self.client.channels("social-account-sync")
        except PostizError as exc:
            raise map_postiz_error(exc) from exc
        items = result if isinstance(result, list) else result.get("integrations", [])
        return [
            {
                "provider_account_id": str(item.get("id", "")),
                "network": str(item.get("providerIdentifier", "other")),
                "external_profile_name": str(item.get("name", "")),
            }
            for item in items
        ]

    def _payload(
        self, post: SocialPost, account_refs: list[str], *, publish: bool
    ) -> dict[str, Any]:
        return {
            "content": post.content.get("text", ""),
            "integration": account_refs,
            "date": post.publish_at.isoformat() if post.publish_at else None,
            "type": "schedule" if post.publish_at else ("now" if publish else "draft"),
            "settings": post.metadata.get("provider", {}),
        }

    async def _create(
        self, post: SocialPost, refs: list[str], correlation_id: str, *, publish: bool
    ) -> ProviderResult:
        try:
            raw = await self.client.create_post(
                self._payload(post, refs, publish=publish), correlation_id
            )
        except PostizError as exc:
            raise map_postiz_error(exc) from exc
        provider_id = str(raw.get("id") or raw.get("postId") or "") or None
        default = (
            SocialPostStatus.SCHEDULED
            if post.publish_at
            else (SocialPostStatus.PUBLISHED if publish else SocialPostStatus.DRAFT)
        )
        return ProviderResult(
            provider_id,
            normalize_status(raw.get("status")) if raw.get("status") else default,
        )

    async def create_post(
        self, post: SocialPost, account_refs: list[str], correlation_id: str
    ) -> ProviderResult:
        return await self._create(post, account_refs, correlation_id, publish=False)

    async def schedule_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return await self._create(post, [], correlation_id, publish=False)

    async def publish_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return await self._create(post, [], correlation_id, publish=True)

    async def cancel_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        if not post.provider_post_id:
            raise SocialError(
                "SOCIAL_POST_NOT_SYNCHRONIZED",
                "Social post has no provider reference",
                status_code=409,
            )
        try:
            await self.client.cancel_post(post.provider_post_id, correlation_id)
        except PostizError as exc:
            raise map_postiz_error(exc) from exc
        return ProviderResult(post.provider_post_id, SocialPostStatus.CANCELLED)

    async def delete_post(
        self, post: SocialPost, correlation_id: str
    ) -> ProviderResult:
        return await self.cancel_post(post, correlation_id)

    async def upload_media(
        self, media: Mapping[str, Any], correlation_id: str
    ) -> dict[str, Any]:
        source_url = str(media.get("source_url", ""))
        if not source_url:
            raise SocialError(
                "SOCIAL_MEDIA_INVALID", "A source URL is required", status_code=422
            )
        try:
            raw = await self.client.upload_from_url(source_url, correlation_id)
        except PostizError as exc:
            raise map_postiz_error(exc) from exc
        return {"provider_media_id": str(raw.get("id", "")), "status": "UPLOADED"}

    async def verify_webhook(self, body: bytes, headers: Mapping[str, str]) -> None:
        secret = settings.postly_webhook_verification_secret
        if not secret:
            raise SocialError(
                "SOCIAL_PROVIDER_NOT_CONFIGURED",
                "Webhook verification is not configured",
                status_code=503,
            )
        timestamp = headers.get("x-postly-timestamp", "")
        signature = headers.get("x-postly-signature", "")
        try:
            if abs(time.time() - int(timestamp)) > settings.social_webhook_ttl_seconds:
                raise ValueError
        except ValueError as exc:
            raise SocialError(
                "SOCIAL_WEBHOOK_INVALID_SIGNATURE",
                "Webhook timestamp is invalid",
                status_code=401,
            ) from exc
        expected = hmac.new(
            secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
            raise SocialError(
                "SOCIAL_WEBHOOK_INVALID_SIGNATURE",
                "Webhook signature is invalid",
                status_code=401,
            )

    async def normalize_webhook(
        self, payload: Mapping[str, Any], correlation_id: str
    ) -> NormalizedEvent:
        event_map = {
            "post.published": "social.post.published",
            "post.failed": "social.post.failed",
            "post.scheduled": "social.post.scheduled",
            "post.cancelled": "social.post.cancelled",
            "account.connected": "social.account.connected",
            "account.disconnected": "social.account.disconnected",
            "comment.created": "social.comment.received",
            "message.created": "social.message.received",
        }
        event_type = event_map.get(str(payload.get("type", "")))
        if not event_type:
            raise SocialError(
                "SOCIAL_WEBHOOK_EVENT_UNSUPPORTED",
                "Webhook event is unsupported",
                status_code=422,
            )
        try:
            subject_id = UUID(str(payload["codestra_subject_id"]))
            tenant_id = UUID(str(payload["tenant_id"]))
        except (KeyError, ValueError) as exc:
            raise SocialError(
                "SOCIAL_WEBHOOK_INVALID",
                "Webhook identifiers are invalid",
                status_code=422,
            ) from exc
        safe_payload = {
            key: payload[key]
            for key in ("status", "provider_post_id", "metrics")
            if key in payload
        }
        return NormalizedEvent(
            event_type, self.name, subject_id, correlation_id, tenant_id, safe_payload
        )


class HootsuiteProviderAdapter(SocialProviderAdapter):
    name = ProviderName.HOOTSUITE

    def get_capabilities(self) -> frozenset[Capability]:
        return frozenset()

    async def health_check(self) -> dict[str, Any]:
        configured = bool(
            settings.hootsuite_client_id_file and settings.hootsuite_client_secret_file
        )
        return {
            "provider": self.name,
            "configured": configured,
            "enabled": False,
            "reachable": None,
            "status": "DISABLED" if configured else "NOT_CONFIGURED",
        }
