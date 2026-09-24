"""Shared storage primitives used by API handlers and workers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def canonical_sha256(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IdempotencyDecision:
    status: str
    operation_id: UUID | None
    response_status: int | None
    response_body: Mapping[str, Any] | None


async def claim_idempotency(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    scope: str,
    idempotency_key: str,
    request_hash: str,
) -> IdempotencyDecision:
    row = (
        await session.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_idempotency_keys
                    (tenant_id, scope, idempotency_key, request_sha256)
                VALUES (:tenant_id, :scope, :key, :request_hash)
                ON CONFLICT (tenant_id, scope, idempotency_key) DO NOTHING
                RETURNING operation_id, response_status, response_body
                """
            ),
            {"tenant_id": tenant_id, "scope": scope, "key": idempotency_key, "request_hash": request_hash},
        )
    ).mappings().one_or_none()
    if row is not None:
        return IdempotencyDecision("NEW", row["operation_id"], row["response_status"], row["response_body"])
    existing = (
        await session.execute(
            text(
                """
                SELECT request_sha256, operation_id, response_status, response_body
                FROM connector_sdk.connector_idempotency_keys
                WHERE tenant_id=:tenant_id AND scope=:scope AND idempotency_key=:key
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "scope": scope, "key": idempotency_key},
        )
    ).mappings().one()
    if existing["request_sha256"] != request_hash:
        return IdempotencyDecision("CONFLICT", existing["operation_id"], None, None)
    return IdempotencyDecision("REPLAY", existing["operation_id"], existing["response_status"], existing["response_body"])


async def claim_webhook_event(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    webhook_id: UUID,
    event_id: str,
    body_sha256: str,
    retention_seconds: int = 604800,
) -> str:
    inserted = (
        await session.execute(
            text(
                """
                INSERT INTO connector_sdk.connector_webhook_event_keys
                    (tenant_id, webhook_id, event_id, body_sha256, expires_at)
                VALUES (:tenant_id, :webhook_id, :event_id, :body_sha256,
                        now() + make_interval(secs => :retention_seconds))
                ON CONFLICT (webhook_id, event_id) DO NOTHING
                RETURNING body_sha256
                """
            ),
            {"tenant_id": tenant_id, "webhook_id": webhook_id, "event_id": event_id, "body_sha256": body_sha256, "retention_seconds": retention_seconds},
        )
    ).scalar_one_or_none()
    if inserted is not None:
        return "NEW"
    prior = (
        await session.execute(
            text(
                """
                SELECT body_sha256 FROM connector_sdk.connector_webhook_event_keys
                WHERE webhook_id=:webhook_id AND event_id=:event_id
                FOR UPDATE
                """
            ),
            {"webhook_id": webhook_id, "event_id": event_id},
        )
    ).scalar_one()
    return "EXACT_REPLAY" if prior == body_sha256 else "SEMANTIC_CONFLICT"
