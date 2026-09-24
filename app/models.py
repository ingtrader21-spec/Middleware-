from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical_contracts import validate_contract


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(
        pattern=r"^codestra\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$",
        max_length=180,
    )
    event_version: Literal["1.0"]
    occurred_at: datetime
    received_at: datetime
    source: str = Field(
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        max_length=100,
    )
    tenant_id: str = Field(min_length=1, max_length=128)
    customer_id: str | None = Field(default=None, min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=180)
    causation_id: str = Field(min_length=1, max_length=180)
    idempotency_key: str = Field(min_length=8, max_length=180)
    payload: dict[str, Any]
    metadata: dict[str, Any]

    @field_validator("occurred_at", "received_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamps must include an explicit timezone")
        return value

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 64:
            raise ValueError("metadata may contain at most 64 properties")
        return value

    @model_validator(mode="after")
    def enforce_canonical_contract(self) -> "EventEnvelope":
        validate_contract("event", self.model_dump(mode="json", exclude_none=True))
        return self


class IngressResult(BaseModel):
    event_id: str
    tenant_id: str
    status: Literal["accepted", "duplicate"]
    duplicate: bool
    correlation_id: str
