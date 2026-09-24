"""Strict inputs shared by the 36 monitoring operations."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Environment = Literal["development", "test", "staging", "production"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Profile(Input):
    environment: Environment
    expected_revision: int = Field(ge=0)
    config_digest: Digest
    metrics_owner: Literal["prometheus", "otel", "not-applicable"]
    logs_owner: Literal["alloy", "otel", "not-applicable"]
    traces_owner: Literal["otel", "not-applicable"]
    dashboard_ids: list[Identifier] = Field(default_factory=list, max_length=20)


class ContractRefresh(Input):
    environment: Environment
    expected_revision: int = Field(ge=0)
    artifact_id: Identifier
    sha256: Digest


class Reconciliation(Input):
    environment: Environment
    service_ids: list[Identifier] = Field(min_length=1, max_length=100)


class Observation(Input):
    kind: Literal[
        "host",
        "deployment",
        "health",
        "integration",
        "agent",
        "campaign",
        "certificate",
        "backup",
        "slo",
        "dashboard",
        "security",
        "error",
        "config",
    ]
    resource_id: Identifier
    service_id: Identifier
    environment: Environment
    source_deployment: Identifier
    sequence: int = Field(ge=1)
    observed_at: AwareDatetime
    campaign_id: Identifier | None = None
    data: dict[str, Any]

    @model_validator(mode="after")
    def scoped_presence(self):
        if self.kind in {"agent", "campaign"} and not self.campaign_id:
            raise ValueError("campaign_id required for presence projections")
        return self


class Heartbeat(Input):
    service_id: Identifier
    environment: Environment
    source_deployment: Identifier
    sequence: int = Field(ge=1)
    observed_at: AwareDatetime
    signals: list[Literal["metrics", "logs", "traces"]] = Field(max_length=3)


class QueryRequest(Input):
    service_id: Identifier
    environment: Environment
    query_id: Identifier
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    step_seconds: int = Field(default=60, ge=1, le=86400)
    limit: int = Field(default=100, ge=1, le=1000)

    @model_validator(mode="after")
    def valid_window(self):
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must be supplied together")
        if self.start and self.end:
            duration = (self.end - self.start).total_seconds()
            if duration <= 0 or duration > 604800:
                raise ValueError("query window must be positive and at most seven days")
            if duration / self.step_seconds > 10000:
                raise ValueError("query exceeds point budget")
        return self


class ProbeRequest(Input):
    service_id: Identifier
    environment: Environment
    target_id: Identifier


class BrowserEvent(Input):
    service_id: Identifier
    environment: Environment
    event_id: Identifier
    event_type: Literal["error", "performance"]
    release: Identifier
    route_template: str = Field(pattern=r"^/[A-Za-z0-9_/{}:.-]*$", max_length=256)
    metric: Literal["lcp_ms", "inp_ms", "cls", "error_count"]
    value: float = Field(ge=0, le=1000000, allow_inf_nan=False)
    occurred_at: AwareDatetime


class Envelope(BaseModel):
    data: Any
    observed_at: datetime | None
    freshness: Literal["fresh", "stale", "unknown", "not-applicable"]
    source_revision: str | int | None = None
    correlation_id: str
    next_cursor: str | None = None
