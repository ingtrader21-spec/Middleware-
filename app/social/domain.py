from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class ProviderName(str, Enum):
    DISABLED = "disabled"
    POSTLY = "postly"
    HOOTSUITE = "hootsuite"


class SocialNetwork(str, Enum):
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    LINKEDIN = "linkedin"
    X = "x"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    PINTEREST = "pinterest"
    THREADS = "threads"
    GOOGLE_BUSINESS = "google_business"
    OTHER = "other"


class SocialPostStatus(str, Enum):
    DRAFT = "DRAFT"
    QUEUED = "QUEUED"
    SCHEDULED = "SCHEDULED"
    PUBLISHING = "PUBLISHING"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DELETED = "DELETED"
    REQUIRES_ACTION = "REQUIRES_ACTION"
    UNKNOWN = "UNKNOWN"


class Capability(str, Enum):
    POST_CREATE = "POST_CREATE"
    POST_UPDATE = "POST_UPDATE"
    POST_DELETE = "POST_DELETE"
    POST_SCHEDULE = "POST_SCHEDULE"
    POST_CANCEL = "POST_CANCEL"
    POST_PUBLISH = "POST_PUBLISH"
    MEDIA_UPLOAD = "MEDIA_UPLOAD"
    IMAGE_POST = "IMAGE_POST"
    VIDEO_POST = "VIDEO_POST"
    MULTI_IMAGE = "MULTI_IMAGE"
    COMMENT_READ = "COMMENT_READ"
    COMMENT_REPLY = "COMMENT_REPLY"
    MESSAGE_READ = "MESSAGE_READ"
    MESSAGE_REPLY = "MESSAGE_REPLY"
    ANALYTICS = "ANALYTICS"
    WEBHOOK_EVENTS = "WEBHOOK_EVENTS"


class JobType(str, Enum):
    CREATE = "SOCIAL_POST_CREATE"
    SCHEDULE = "SOCIAL_POST_SCHEDULE"
    PUBLISH = "SOCIAL_POST_PUBLISH"
    CANCEL = "SOCIAL_POST_CANCEL"
    DELETE = "SOCIAL_POST_DELETE"
    MEDIA_UPLOAD = "SOCIAL_MEDIA_UPLOAD"
    ACCOUNT_SYNC = "SOCIAL_ACCOUNT_SYNC"
    ANALYTICS_SYNC = "SOCIAL_ANALYTICS_SYNC"
    WEBHOOK_PROCESS = "SOCIAL_WEBHOOK_PROCESS"


@dataclass(slots=True)
class SocialAccount:
    tenant_id: UUID
    provider: ProviderName
    provider_account_id: str
    network: SocialNetwork
    external_profile_name: str
    external_profile_id: str
    id: UUID = field(default_factory=uuid4)
    connection_state: str = "connected"
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_sync_at: datetime | None = None


@dataclass(slots=True)
class SocialPost:
    tenant_id: UUID
    provider: ProviderName
    account_ids: tuple[UUID, ...]
    content: dict[str, Any]
    id: UUID = field(default_factory=uuid4)
    campaign_id: UUID | None = None
    provider_post_id: str | None = None
    status: SocialPostStatus = SocialPostStatus.DRAFT
    publish_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class SocialPublishJob:
    tenant_id: UUID
    social_post_id: UUID
    provider: ProviderName
    job_type: JobType
    correlation_id: str
    request_id: str
    idempotency_key: str
    id: UUID = field(default_factory=uuid4)
    state: str = "queued"
    attempt_count: int = 0
    last_error_code: str | None = None


@dataclass(slots=True)
class SocialCampaign:
    tenant_id: UUID
    name: str
    id: UUID = field(default_factory=uuid4)
    status: str = "DRAFT"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SocialMediaAsset:
    tenant_id: UUID
    media_type: str
    content_type: str
    storage_reference: str
    checksum_sha256: str
    id: UUID = field(default_factory=uuid4)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SocialPublishAttempt:
    job_id: UUID
    attempt_number: int
    result: str
    id: UUID = field(default_factory=uuid4)
    error_code: str | None = None


@dataclass(slots=True)
class SocialWebhookEvent:
    provider: ProviderName
    provider_event_id: str
    payload_hash: str
    correlation_id: str
    id: UUID = field(default_factory=uuid4)


@dataclass(slots=True)
class SocialProviderEvent:
    event_type: str
    provider: ProviderName
    subject_id: UUID
    tenant_id: UUID
    correlation_id: str
    id: UUID = field(default_factory=uuid4)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SocialAnalyticsSnapshot:
    tenant_id: UUID
    provider: ProviderName
    captured_at: datetime
    id: UUID = field(default_factory=uuid4)
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SocialAuditEvent:
    tenant_id: UUID
    actor_type: str
    actor_id: str
    action: str
    correlation_id: str
    request_id: str
    result: str
    id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True, slots=True)
class ProviderResult:
    provider_post_id: str | None
    status: SocialPostStatus
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    event_type: str
    provider: ProviderName
    subject_id: UUID
    correlation_id: str
    tenant_id: UUID
    payload: dict[str, Any]
    event_id: UUID = field(default_factory=uuid4)
    event_version: int = 1
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


NETWORK_ALIASES = {
    "twitter": SocialNetwork.X,
    "x/twitter": SocialNetwork.X,
    "googlebusiness": SocialNetwork.GOOGLE_BUSINESS,
    "google_business_profile": SocialNetwork.GOOGLE_BUSINESS,
}


def normalize_network(value: str) -> SocialNetwork:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in NETWORK_ALIASES:
        return NETWORK_ALIASES[normalized]
    try:
        return SocialNetwork(normalized)
    except ValueError:
        return SocialNetwork.OTHER
