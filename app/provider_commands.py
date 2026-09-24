from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field


class ProviderCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = Field(pattern=r"^codestra\.(vicidial|postiz)\.command\.v1$")
    command_id: str = Field(min_length=1, max_length=128)
    command_type: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=64)
    organization_id: str = Field(min_length=1, max_length=128)
    campaign_reference: str | None = None
    list_reference: str | None = None
    lead_reference: str | None = None
    agent_reference: str | None = None
    extension_reference: str | None = None
    phone_reference: str | None = None
    approved_actions: list[str] = Field(default_factory=list, max_length=32)
    constraints: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    requested_at: datetime
    expires_at: datetime


VICIDIAL_ALLOWED = {"agent_provision", "extension_mapping", "campaign_sync", "list_sync", "synthetic_lead_delivery", "callback_schedule", "manual_call_request", "preview_call_request", "call_result_read", "recording_metadata_read", "agent_state_read", "reconciliation"}
POSTIZ_ALLOWED = {"channel_discovery", "media_upload", "draft_create", "draft_update", "future_schedule", "future_schedule_cancel", "approval_request", "status_read", "analytics_read", "reconciliation"}
BLOCKED = {"predictive_dialing", "customer_list_dialing", "bulk_real_lead_import", "unapproved_external_call", "immediate_public_publish", "unapproved_schedule", "direct_database_write", "direct_sql"}


class ProviderCommandStore:
    def __init__(self) -> None:
        self.commands: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[str, str] = {}
        self.audit: list[dict[str, Any]] = []

    def create(self, command: ProviderCommand, allowed: set[str], provider: str) -> dict[str, Any]:
        if command.command_type in BLOCKED or command.command_type not in allowed:
            raise HTTPException(403, "provider command is not allowlisted")
        if command.expires_at <= command.requested_at:
            raise HTTPException(422, "command expiration must be after request time")
        existing = self.idempotency.get(command.idempotency_key)
        if existing:
            return {**self.commands[existing], "duplicate": True}
        record = {**command.model_dump(mode="json"), "provider": provider, "status": "RECEIVED", "duplicate": False}
        self.commands[command.command_id] = record
        self.idempotency[command.idempotency_key] = command.command_id
        self.audit.append({"command_id": command.command_id, "event": "command_received"})
        return record

    def get(self, command_id: str) -> dict[str, Any]:
        if command_id not in self.commands:
            raise HTTPException(404, "provider command not found")
        return self.commands[command_id]

    def transition(self, command_id: str, status: str, **extra: Any) -> dict[str, Any]:
        record = self.get(command_id)
        record.update(status=status, **extra)
        self.audit.append({"command_id": command_id, "event": f"command_{status.lower()}"})
        return record


VICIDIAL_STORE = ProviderCommandStore()
POSTIZ_STORE = ProviderCommandStore()
