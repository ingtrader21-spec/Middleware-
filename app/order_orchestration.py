"""Middleware-owned approved-order orchestration contract.

This module is deliberately persistence-agnostic for the first release: the
canonical order state is held by middleware and the durable outbox/inbox
adapters can replace the in-memory store without changing the HTTP contract.
n8n receives only validated, allowlisted commands.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app import metrics
from app.core.config import settings


class OrderStatus(str, Enum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    QUEUED = "QUEUED"
    DISPATCHED_TO_N8N = "DISPATCHED_TO_N8N"
    RUNNING = "RUNNING"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    COMPLETED = "COMPLETED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    FAILED_FINAL = "FAILED_FINAL"
    DEAD_LETTER = "DEAD_LETTER"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


ALLOWED_WORKFLOWS = frozenset(
    {
        "CDST-ORDER-VALIDATE-V1",
        "CDST-ORDER-ROUTER-V1",
        "CDST-ORDER-EXECUTE-V1",
        "CDST-ORDER-SHIPPING-V1",
        "CDST-ORDER-FULFILLMENT-V1",
        "CDST-ORDER-CUSTOMER-SETUP-V1",
        "CDST-ORDER-SOCIAL-DRAFT-V1",
        "CDST-ORDER-SOCIAL-CAMPAIGN-V1",
        "CDST-ORDER-CALLBACK-V1",
        "CDST-ORDER-INTERNAL-REPORT-V1",
        "CDST-ORDER-RESULT-V1",
        "CDST-ORDER-FAILURE-V1",
        "CDST-ORDER-DEAD-LETTER-V1",
        "CDST-ORDER-RECONCILIATION-V1",
    }
)
ALLOWED_ACTIONS = frozenset(
    {
        "validate_customer",
        "create_fulfillment_task",
        "request_shipping_quote",
        "schedule_pickup",
        "create_callback",
        "prepare_campaign_draft",
        "create_social_draft",
        "request_document",
        "generate_internal_report",
        "notify_internal_team",
    }
)
BLOCKED_ACTIONS = frozenset(
    {
        "charge_payment_method",
        "send_customer_message",
        "place_external_call",
        "publish_social_post",
        "delete_record",
        "cancel_customer_service",
        "export_customer_database",
    }
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Approval(StrictModel):
    required: bool = True
    status: str = Field(pattern="^(pending|approved|rejected)$")
    approved_by: str | None = Field(default=None, max_length=128)
    approved_at: datetime | None = None
    content_hash: str = Field(min_length=64, max_length=64)


class OrderEnvelope(StrictModel):
    schema_version: str = Field(pattern="^codestra\\.order\\.command\\.v1$")
    command_id: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    order_id: str = Field(min_length=1, max_length=128)
    order_type: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=32)
    organization_id: str = Field(min_length=1, max_length=128)
    customer_reference: str = Field(min_length=1, max_length=128)
    workflow_code: str = Field(min_length=1, max_length=64)
    workflow_version: str = Field(default="1", min_length=1, max_length=16)
    approval: Approval
    approval_required: bool | None = None
    approval_status: str | None = None
    approval_reference: str | None = None
    approval_content_hash: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    requested_actions: list[str] = Field(min_length=1, max_length=20)
    approved_actions: list[str] | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=16, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    requested_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_time_order(self) -> OrderEnvelope:
        if self.expires_at <= self.requested_at:
            raise ValueError("expires_at must be after requested_at")
        return self

    @model_validator(mode="after")
    def normalize_approval_fields(self) -> OrderEnvelope:
        if self.approval_required is None:
            self.approval_required = self.approval.required
        if self.approval_status is None:
            self.approval_status = self.approval.status
        if self.approval_content_hash is None:
            self.approval_content_hash = self.approval.content_hash
        if self.approved_actions is None:
            self.approved_actions = list(self.requested_actions)
        return self


class ApprovalRequest(StrictModel):
    approved_by: str = Field(min_length=1, max_length=128)
    content_hash: str = Field(min_length=64, max_length=64)


class ResultEnvelope(StrictModel):
    schema_version: str = Field(pattern="^codestra\\.order\\.result\\.v1$")
    command_id: str = Field(min_length=1, max_length=128)
    order_id: str = Field(min_length=1, max_length=128)
    workflow_code: str = Field(min_length=1, max_length=64)
    execution_id: str = Field(min_length=1, max_length=128)
    status: str = Field(pattern="^(completed|partially_completed|failed)$")
    completed_actions: list[str] = Field(default_factory=list)
    failed_actions: list[str] = Field(default_factory=list)
    result: dict[str, Any] = Field(default_factory=dict)
    retryable: bool = False
    error_code: str | None = None
    error_message: str | None = None
    correlation_id: str
    trace_id: str
    started_at: datetime
    completed_at: datetime


class ErrorEnvelope(StrictModel):
    command_id: str
    order_id: str
    workflow_code: str
    error_code: str
    error_message: str = Field(max_length=512)
    retryable: bool = False
    correlation_id: str
    trace_id: str


class DeadLetterEnvelope(StrictModel):
    schema_version: str = Field(pattern="^codestra\\.order\\.dead_letter\\.v1$")
    command_id: str
    order_id: str
    workflow_code: str
    reason_code: str
    reason: str = Field(max_length=512)
    retry_count: int = Field(ge=0)
    correlation_id: str
    trace_id: str


def content_hash(order: OrderEnvelope) -> str:
    data = order.model_dump(
        mode="json",
        exclude={
            "approval", "approval_required", "approval_status",
            "approval_reference", "approval_content_hash", "approved_actions",
        },
    )
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_synthetic(order: OrderEnvelope) -> bool:
    return order.order_id.startswith("CODESTRA-INTEGRATION-TEST-")


def validate_for_dispatch(order: OrderEnvelope) -> None:
    now = datetime.now(UTC)
    if order.expires_at <= now:
        raise HTTPException(422, "order has expired")
    if order.workflow_code not in ALLOWED_WORKFLOWS:
        raise HTTPException(422, "workflow code is not allowlisted")
    if any(action in BLOCKED_ACTIONS for action in order.requested_actions):
        raise HTTPException(422, "requested action is blocked")
    if not set(order.requested_actions).issubset(ALLOWED_ACTIONS):
        raise HTTPException(422, "requested action is not allowlisted")
    if order.approval.required and order.approval.status != "approved":
        raise HTTPException(409, "approval is required before dispatch")
    if order.approval.content_hash != content_hash(order):
        raise HTTPException(409, "approval content hash does not match order")
    if not _is_synthetic(order) and not settings.order_orchestration_enabled:
        raise HTTPException(503, "order orchestration is disabled")
    if not settings.n8n_order_dispatch_enabled and not _is_synthetic(order):
        raise HTTPException(503, "n8n order dispatch is disabled")


class OrderStore:
    def __init__(self) -> None:
        self.orders: dict[str, dict[str, Any]] = {}
        self.by_idempotency: dict[str, str] = {}
        self.commands: dict[str, dict[str, Any]] = {}
        self.audit_events: list[dict[str, Any]] = []
        self.metrics: dict[str, int] = {}

    def _count(self, name: str) -> None:
        self.metrics[name] = self.metrics.get(name, 0) + 1
        prometheus_metric = {
            "orders_received_total": metrics.ORDER_RECEIVED,
            "orders_validated_total": metrics.ORDER_VALIDATED,
            "orders_approved_total": metrics.ORDER_APPROVED,
            "orders_dispatched_total": metrics.ORDER_DISPATCHED,
            "orders_started_total": metrics.ORDER_STARTED,
            "orders_completed_total": metrics.ORDER_COMPLETED,
            "orders_failed_total": metrics.ORDER_FAILED,
            "orders_retried_total": metrics.ORDER_RETRIED,
            "orders_dead_lettered_total": metrics.ORDER_DEAD_LETTERED,
            "orders_human_review_total": metrics.ORDER_HUMAN_REVIEW,
            "order_duplicate_suppression_total": metrics.ORDER_DUPLICATE_SUPPRESSION,
            "order_callback_failure_total": metrics.ORDER_CALLBACK_FAILURE,
            "order_progress_total": metrics.ORDER_PROGRESS,
            "security_failure_retry_total": metrics.ORDER_SECURITY_RETRY,
        }.get(name)
        if prometheus_metric is not None:
            prometheus_metric.inc()

    def _audit(self, order_id: str, event: str, **details: Any) -> None:
        self.audit_events.append({"order_id": order_id, "event": event, **details})

    def create(self, order: OrderEnvelope) -> dict[str, Any]:
        existing_id = self.by_idempotency.get(order.idempotency_key)
        if existing_id:
            existing = self.orders[existing_id]
            if existing["content_hash"] != content_hash(order):
                raise HTTPException(409, "duplicate idempotency key conflict")
            self._count("order_duplicate_suppression_total")
            return {**existing, "duplicate": True}
        status = OrderStatus.APPROVAL_REQUIRED.value if order.approval.required else OrderStatus.VALIDATED.value
        record = {
            "order_id": order.order_id,
            "command_id": order.command_id,
            "workflow_code": order.workflow_code,
            "status": status,
            "content_hash": content_hash(order),
            "trace_id": order.trace_id,
            "correlation_id": order.correlation_id,
            "envelope": order.model_dump(mode="json"),
            "duplicate": False,
        }
        self.orders[order.order_id] = record
        self.by_idempotency[order.idempotency_key] = order.order_id
        self._count("orders_received_total")
        self._count("orders_approved_total" if order.approval.status == "approved" else "orders_validated_total")
        self._audit(order.order_id, "order_received", trace_id=order.trace_id)
        return record

    def get(self, order_id: str) -> dict[str, Any]:
        if order_id not in self.orders:
            raise HTTPException(404, "order not found")
        return self.orders[order_id]

    def command(self, command_id: str, order_id: str) -> dict[str, Any]:
        record = self.get(order_id)
        existing = self.commands.get(command_id)
        if existing:
            if existing["order_id"] != order_id:
                raise HTTPException(409, "command reference conflict")
            return existing
        command = {
            "command_id": command_id, "order_id": order_id,
            "workflow_code": record["workflow_code"],
            "status": OrderStatus.QUEUED.value, "progress": [], "attempts": 0,
        }
        self.commands[command_id] = command
        self._count("orders_dispatched_total")
        self._audit(order_id, "command_created", command_id=command_id)
        return command

    def record_failure(self, command_id: str, error_code: str, retryable: bool,
                       max_attempts: int = 3) -> dict[str, Any]:
        command = self.commands.get(command_id)
        if not command:
            raise HTTPException(404, "command not found")
        order = self.get(command["order_id"])
        command["attempts"] += 1
        security_failure = error_code in {"AUTHENTICATION_FAILURE", "AUTHORIZATION_FAILURE", "INVALID_SIGNATURE"}
        can_retry = retryable and not security_failure and command["attempts"] < max_attempts
        if can_retry:
            command["status"] = OrderStatus.RETRY_SCHEDULED.value
            order["status"] = OrderStatus.FAILED_RETRYABLE.value
            self._count("orders_retried_total")
        else:
            command["status"] = OrderStatus.DEAD_LETTER.value if retryable else OrderStatus.FAILED_FINAL.value
            order["status"] = command["status"]
            if retryable:
                self._count("orders_dead_lettered_total")
        if security_failure:
            self._count("security_failure_retry_total")
        self._count("orders_failed_total")
        self._audit(order["order_id"], "command_failure", command_id=command_id,
                    error_code=error_code, retryable=can_retry)
        return command

    def record_result(self, command_id: str, status: str) -> dict[str, Any]:
        command = self.commands.get(command_id)
        if not command:
            raise HTTPException(404, "command not found")
        if command["status"] == OrderStatus.COMPLETED.value and status == "completed":
            return command
        order = self.get(command["order_id"])
        command["status"] = OrderStatus.COMPLETED.value if status == "completed" else OrderStatus.PARTIALLY_COMPLETED.value
        order["status"] = command["status"]
        self._count("orders_completed_total" if status == "completed" else "orders_failed_total")
        self._audit(order["order_id"], "command_result", command_id=command_id, status=status)
        return command


def verify_body_integrity(body: BaseModel | dict[str, Any], timestamp: str | None, nonce: str | None,
                          signature: str | None, body_hash: str | None) -> None:
    if not all((timestamp, nonce, signature, body_hash)):
        raise HTTPException(401, "timestamp, nonce, signature, and body hash are required")
    payload = body.model_dump(mode="json") if isinstance(body, BaseModel) else body
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    computed_hash = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(computed_hash, body_hash or ""):
        raise HTTPException(401, "body hash mismatch")
    if settings.middleware_secret:
        expected = hmac.new(settings.middleware_secret.encode(), f"{timestamp}.{nonce}.{computed_hash}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature or ""):
            raise HTTPException(401, "signature invalid")


STORE = OrderStore()
