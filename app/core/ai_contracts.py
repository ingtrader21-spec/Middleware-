"""Strict versioned contracts for Middleware-controlled AI commands."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CommandType(str, Enum):
    CHAT = "ai.chat.v1"
    CODING = "ai.coding.v1"
    CRM = "ai.crm.v1"
    VOICE = "ai.voice.v1"
    EMBEDDINGS = "ai.embeddings.v1"


class ModelPolicy(StrictModel):
    profile: Literal[
        "fast-chat", "quality-chat", "coding-default", "coding-large",
        "crm-analysis", "voice-summary", "embedding-default",
    ]
    temperature: float = Field(default=0.2, ge=0, le=1)
    max_tokens: int = Field(default=1024, ge=1, le=8192)


class ResourceLimits(StrictModel):
    runtime_seconds: int = Field(default=300, ge=1, le=600)
    output_bytes: int = Field(default=262_144, ge=1, le=1_048_576)
    retry_count: int = Field(default=3, ge=0, le=5)
    token_budget: int = Field(default=4096, ge=1, le=32768)


class ApprovalPolicy(StrictModel):
    required: bool = False
    action_types: list[str] = Field(default_factory=list, max_length=16)


class CallbackPolicy(StrictModel):
    mode: Literal["poll", "none"] = "poll"


class AICommand(StrictModel):
    command_id: UUID
    command_type: CommandType
    schema_version: Literal["1.0"]
    tenant_id: UUID
    actor_id: str = Field(min_length=1, max_length=128)
    actor_type: Literal["user", "service", "workflow"]
    correlation_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,128}$")
    idempotency_key: str = Field(min_length=16, max_length=255)
    priority: int = Field(default=5, ge=0, le=9)
    requested_at: datetime
    deadline_at: datetime
    input: dict[str, Any]
    model_policy: ModelPolicy
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    data_classification: Literal["public", "internal", "confidential", "synthetic"]
    approval_policy: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    callback_policy: CallbackPolicy = Field(default_factory=CallbackPolicy)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timezone is required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def policy_consistency(self) -> AICommand:
        if self.deadline_at <= self.requested_at:
            raise ValueError("deadline must follow requested_at")
        if (self.deadline_at - self.requested_at).total_seconds() > 3600:
            raise ValueError("deadline exceeds one-hour policy")
        allowed_profiles = {
            CommandType.CHAT: {"fast-chat", "quality-chat"},
            CommandType.CODING: {"coding-default", "coding-large"},
            CommandType.CRM: {"crm-analysis"},
            CommandType.VOICE: {"voice-summary"},
            CommandType.EMBEDDINGS: {"embedding-default"},
        }
        if self.model_policy.profile not in allowed_profiles[self.command_type]:
            raise ValueError("unsupported model policy")
        encoded = self.model_dump_json().encode()
        if len(encoded) > 131_072:
            raise ValueError("command payload exceeds policy")
        forbidden = {"shell", "command", "provider_url", "endpoint", "credentials", "password", "token"}
        if forbidden.intersection(key.lower() for key in self.input):
            raise ValueError("privileged input field is forbidden")
        business = self.command_type in {CommandType.CRM, CommandType.VOICE}
        if business and not self.approval_policy.required:
            raise ValueError("business command proposals require approval")
        return self


class AIResult(StrictModel):
    command_id: UUID
    job_id: UUID
    status: Literal["SUCCEEDED", "FAILED_RETRYABLE", "FAILED_FINAL", "CANCELLED"]
    result_schema_version: Literal["1.0"]
    model_used: str = Field(min_length=1, max_length=128)
    provider_used: Literal["litellm", "ollama", "openai", "mock"]
    started_at: datetime
    completed_at: datetime
    latency_ms: int = Field(ge=0)
    token_usage: dict[str, int] = Field(default_factory=dict)
    resource_usage: dict[str, int | float] = Field(default_factory=dict)
    output: dict[str, Any]
    structured_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    policy_decisions: list[str] = Field(default_factory=list)
    error: dict[str, str] | None = None
    retryability: Literal["none", "retryable", "final"] = "none"
    audit_reference: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def valid_timing_and_size(self) -> AIResult:
        if self.completed_at < self.started_at:
            raise ValueError("completion precedes start")
        if len(self.model_dump_json().encode()) > 1_048_576:
            raise ValueError("result exceeds policy")
        return self


PUBLIC_STATES = {
    "queued": "PENDING", "available": "AVAILABLE", "leased": "LEASED",
    "running": "RUNNING", "retry_wait": "FAILED_RETRYABLE",
    "completed": "SUCCEEDED", "failed": "FAILED_FINAL",
    "cancel_requested": "CANCEL_REQUESTED", "cancelled": "CANCELLED",
    "expired": "EXPIRED", "dead_letter": "DEAD_LETTERED",
    "approval_required": "APPROVAL_REQUIRED", "approved": "APPROVED",
    "rejected": "REJECTED",
}
