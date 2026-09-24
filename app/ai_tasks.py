from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field


class TaskType(StrEnum):
    LEAD_ANALYSIS = "lead_analysis"
    CALL_SUMMARY = "call_summary"
    CALL_QUALITY_REVIEW = "call_quality_review"
    DISPOSITION_SUGGESTION = "disposition_suggestion"
    NEXT_BEST_ACTION = "next_best_action"
    UPSELL_RECOMMENDATION = "upsell_recommendation"
    CAMPAIGN_DRAFT = "campaign_draft"
    DOCUMENT_GENERATION = "document_generation"
    INTERNAL_REPORT = "internal_report"
    TRANSLATION = "translation"
    CLASSIFICATION = "classification"


class TaskStatus(StrEnum):
    RECEIVED = "RECEIVED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_FINAL = "FAILED_FINAL"
    CANCELLED = "CANCELLED"
    RECONCILED = "RECONCILED"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AiTask(StrictModel):
    schema_version: str = Field(pattern=r"^codestra\.ai\.task\.v1$")
    task_id: str = Field(min_length=1, max_length=128)
    task_type: TaskType
    model_policy: str = Field(min_length=1, max_length=128)
    source_system: str = Field(min_length=1, max_length=64)
    organization_id: str = Field(min_length=1, max_length=128)
    input_reference: str = Field(min_length=1, max_length=256)
    approved_context: dict[str, Any] = Field(default_factory=dict)
    requested_outputs: list[str] = Field(min_length=1, max_length=32)
    constraints: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    requested_at: datetime
    expires_at: datetime


class AiProgress(StrictModel):
    task_id: str
    status: str = Field(pattern=r"^(RUNNING|COMPLETED|FAILED_RETRYABLE|FAILED_FINAL|CANCELLED)$")
    percent: int = Field(ge=0, le=100)
    trace_id: str
    correlation_id: str


class AiResult(StrictModel):
    task_id: str
    status: str = Field(pattern=r"^(COMPLETED|FAILED_RETRYABLE|FAILED_FINAL)$")
    output: dict[str, Any] = Field(default_factory=dict)
    model: str = Field(default="mock-unconfigured", max_length=128)
    trace_id: str
    correlation_id: str


class AiError(StrictModel):
    task_id: str
    error_code: str = Field(min_length=1, max_length=64)
    message: str = Field(max_length=1000)
    retryable: bool
    trace_id: str
    correlation_id: str


class AiReconciliation(StrictModel):
    task_id: str
    provider_execution_id: str | None = None
    observed_status: str
    trace_id: str
    correlation_id: str


class AiTaskStore:
    def __init__(self) -> None:
        self.tasks: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[str, str] = {}
        self.audit: list[dict[str, Any]] = []

    def _audit(self, task_id: str, event: str, **details: Any) -> None:
        self.audit.append({"task_id": task_id, "event": event, "at": datetime.now(timezone.utc).isoformat(), **details})

    def create(self, task: AiTask) -> dict[str, Any]:
        if task.expires_at <= task.requested_at:
            raise HTTPException(422, "task expiration must be after request time")
        existing_id = self.idempotency.get(task.idempotency_key)
        if existing_id:
            existing = self.tasks[existing_id]
            if existing["trace_id"] != task.trace_id or existing["task_type"] != task.task_type.value:
                raise HTTPException(409, "AI task idempotency conflict")
            return {**existing, "duplicate": True}
        record = {**task.model_dump(mode="json"), "status": TaskStatus.RECEIVED.value, "duplicate": False}
        self.tasks[task.task_id] = record
        self.idempotency[task.idempotency_key] = task.task_id
        self._audit(task.task_id, "task_received", trace_id=task.trace_id)
        return record

    def get(self, task_id: str) -> dict[str, Any]:
        if task_id not in self.tasks:
            raise HTTPException(404, "AI task not found")
        return self.tasks[task_id]

    def transition(self, task_id: str, status: TaskStatus, **details: Any) -> dict[str, Any]:
        record = self.get(task_id)
        record["status"] = status.value
        record.update(details)
        self._audit(task_id, f"task_{status.value.lower()}", **details)
        return record


AI_STORE = AiTaskStore()
