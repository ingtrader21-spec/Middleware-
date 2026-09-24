from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from .contracts import WebhookRoute
from .models import EventEnvelope, IngressResult
from .replay import ReplayBusy
from app.core.runtime import RuntimeContainer as Runtime
from .security import RequestValidationError, authorize_tenant, verify_signed_request
from .storage import ReplayConflict, canonical_payload_sha256


CANONICAL_ERROR_SCHEMA = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "object",
            "required": ["code", "message", "correlation_id", "retryable", "details"],
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "correlation_id": {"type": "string"},
                "retryable": {"type": "boolean"},
                "details": {"type": "object"},
            },
        }
    },
}
EVENT_TYPE_422_RESPONSE = {
    "description": "Event type is not allowed for this webhook",
    "content": {"application/json": {"schema": CANONICAL_ERROR_SCHEMA}},
}


class IngressError(RuntimeError):
    status_code = 400
    code = "ingress_error"
    retryable = False


class EventTypeError(IngressError):
    status_code = 422
    code = "event_type_not_allowed"


class ReplayConflictError(IngressError):
    status_code = 409
    code = "idempotency_conflict"


class ProcessingConflictError(IngressError):
    status_code = 409
    code = "processing_conflict"
    retryable = True


class PayloadTooLargeError(IngressError):
    status_code = 413
    code = "payload_too_large"


def semantic_digest(envelope: EventEnvelope) -> str:
    return canonical_payload_sha256(envelope.model_dump(mode="json"))


async def accept_webhook(
    runtime: Runtime,
    route: WebhookRoute,
    *,
    claims: dict[str, Any],
    method: str,
    path: str,
    raw_body: bytes,
    headers: dict[str, str],
) -> tuple[IngressResult, int]:
    signed = verify_signed_request(
        settings=runtime.settings,
        method=method,
        path=path,
        body=raw_body,
        headers=headers,
        expected_source_client_id=route.producer_client_id,
    )
    try:
        payload: Any = json.loads(raw_body)
        envelope = EventEnvelope.model_validate(payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise RequestValidationError("body does not match the canonical event envelope") from exc

    authorize_tenant(claims, envelope.tenant_id)
    if envelope.event_type not in route.event_types:
        raise EventTypeError("event type is not allowed for this route")
    if signed.event_type != envelope.event_type:
        raise RequestValidationError("X-Codestra-Event-Type does not match body")
    if signed.event_id != envelope.event_id:
        raise RequestValidationError("X-Codestra-Event-Id does not match body")
    if signed.tenant_id != envelope.tenant_id:
        raise RequestValidationError("X-Codestra-Tenant-Id does not match body")
    if signed.correlation_id != envelope.correlation_id:
        raise RequestValidationError("X-Correlation-Id does not match body")
    if envelope.idempotency_key != signed.idempotency_key:
        raise RequestValidationError("body idempotency_key does not match headers")
    if envelope.source != route.producer_client_id:
        raise RequestValidationError("body source does not match route producer")

    semantic_sha = semantic_digest(envelope)
    token: str | None = None
    try:
        token = await runtime.replay.acquire(
            envelope.tenant_id,
            envelope.event_id,
        )
        try:
            if runtime.automation is not None:
                result = await runtime.automation.accept_event(
                    runtime.inbox,
                    envelope,
                    producer_client_id=route.producer_client_id,
                    body_sha256=signed.body_sha256,
                    semantic_sha256=semantic_sha,
                )
            else:
                result = await runtime.inbox.accept(
                    envelope,
                    producer_client_id=route.producer_client_id,
                    body_sha256=signed.body_sha256,
                    semantic_sha256=semantic_sha,
                )
        except ReplayConflict as exc:
            raise ReplayConflictError(str(exc)) from exc
    except ReplayBusy as exc:
        raise ProcessingConflictError(str(exc)) from exc
    finally:
        if token is not None:
            await runtime.replay.release(
                envelope.tenant_id,
                envelope.event_id,
                token,
            )

    return result, 200 if result.duplicate else 202
