"""Pydantic request and response models for Connector Runtime v1."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Meta(StrictModel):
    correlation_id: UUID
    api_version: Literal["v1"] = "v1"


class OperationProjection(StrictModel):
    operation_id: UUID
    status: str
    resource_version: int | None = None


class OperationAccepted(StrictModel):
    data: OperationProjection
    meta: Meta


class ConnectorProjection(StrictModel):
    connector_id: str
    display_name: str
    version: str
    cell: str
    state: str
    manifest_digest: str
    runtime_binding_status: str
    workflow_families: list[str] = Field(default_factory=list)
    resource_version: int | None = None


class ConnectorPage(StrictModel):
    data: list[ConnectorProjection]
    meta: Meta
    next_cursor: str | None = None


class ManifestValidationRequest(StrictModel):
    manifest: dict[str, Any]


class ManifestValidationProjection(StrictModel):
    valid: bool
    connector_id: str
    version: str
    manifest_digest: str
    warnings: list[str] = Field(default_factory=list)


class ManifestValidationResponse(StrictModel):
    data: ManifestValidationProjection
    meta: Meta


class ConnectorInstallRequest(StrictModel):
    manifest: dict[str, Any]
    expected_manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class ConnectorUpgradeRequest(StrictModel):
    manifest: dict[str, Any]
    expected_manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class ConnectionCreateRequest(StrictModel):
    connector_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    external_account_reference: str | None = Field(default=None, max_length=256)
    configuration: dict[str, Any] = Field(default_factory=dict)
    secret_references: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("secret_references")
    @classmethod
    def validate_secret_references(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 128 or not value.replace("_", "A").isalnum():
                raise ValueError("secret references must be uppercase aliases")
            if value.upper() != value:
                raise ValueError("secret references must be uppercase aliases")
        if len(values) != len(set(values)):
            raise ValueError("secret references must be unique")
        return values


class ConnectionProjection(StrictModel):
    connection_id: UUID
    tenant_id: UUID
    connector_id: str
    external_account_reference: str | None
    state: str
    resource_version: int
    last_tested_at: datetime | None = None
    last_test_code: str | None = None


class ConnectionResponse(StrictModel):
    data: ConnectionProjection
    meta: Meta


class WebhookCreateRequest(StrictModel):
    endpoint_key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    secret_reference_current: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9_]+$",
    )


class WebhookUpdateRequest(StrictModel):
    state: Literal["DISABLED", "SUSPENDED"] | None = None


class WebhookRotateRequest(StrictModel):
    new_secret_reference: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9_]+$",
    )
    overlap_seconds: int = Field(default=300, ge=30, le=3600)


class WebhookProjection(StrictModel):
    webhook_id: UUID
    connection_id: UUID
    tenant_id: UUID
    connector_id: str
    endpoint_key: str
    public_path: str
    state: str
    resource_version: int
    previous_secret_valid_until: datetime | None = None


class WebhookResponse(StrictModel):
    data: WebhookProjection
    meta: Meta


class WebhookPage(StrictModel):
    data: list[WebhookProjection]
    meta: Meta
    next_cursor: str | None = None


class DeliveryProjection(StrictModel):
    inbox_id: UUID
    webhook_id: UUID
    event_id: str
    body_sha256: str
    verification_state: str
    processing_state: str
    correlation_id: UUID
    received_at: datetime
    processed_at: datetime | None = None
    error_code: str | None = None


class DeliveryPage(StrictModel):
    data: list[DeliveryProjection]
    meta: Meta
    next_cursor: str | None = None


class HealthProjection(StrictModel):
    status: Literal["ok", "degraded", "not_ready"]
    service: str
    release_sha: str
    checks: dict[str, str] = Field(default_factory=dict)


class HealthResponse(StrictModel):
    data: HealthProjection
    meta: Meta
