from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PostizCommand(StrictModel):
    command_id: str = Field(min_length=1, max_length=128)
    event_id: str | None = None
    organization_id: str = Field(min_length=1, max_length=128)
    campaign_id: str | None = None
    odoo_record_id: int | None = None
    channel_ids: list[str] = Field(default_factory=list, max_length=50)
    media_ids: list[str] = Field(default_factory=list, max_length=50)
    correlation_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=256)
    requested_by: str = Field(min_length=1, max_length=128)
    requested_at: datetime


class PostizPostRequest(PostizCommand):
    content: str = Field(min_length=1, max_length=10000)
    scheduled_at: datetime | None = None
    publish: bool = False
    platform_settings: dict[str, Any] = Field(default_factory=dict)


class PostizMediaUploadRequest(PostizCommand):
    source_url: str | None = None
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(min_length=1, max_length=128)


class PostizCancelRequest(PostizCommand):
    post_id: str = Field(min_length=1, max_length=256)


class PostizAnalyticsRequest(PostizCommand):
    post_id: str | None = None
    integration_id: str | None = None
    date: str | None = None


class PostizResult(StrictModel):
    command_id: str
    status: Literal["DRAFT_CREATED", "SCHEDULED", "PUBLISHED", "PARTIALLY_PUBLISHED", "CANCELLED"]
    provider_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str
    trace_id: str
    completed_at: datetime | None = None


class PostizErrorResult(StrictModel):
    command_id: str
    status: Literal["FAILED_RETRYABLE", "FAILED_FINAL"]
    error_code: str
    error_message: str = Field(max_length=1000)
    retryable: bool
    correlation_id: str
    trace_id: str
