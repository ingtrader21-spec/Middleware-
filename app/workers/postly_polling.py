"""Read-only Postly polling with transactional PostgreSQL checkpoints."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.integrations.postiz.client import PostizClient
from app.integrations.postiz.exceptions import PostizError
from app.social.metrics import poll_cycles, poll_events_emitted, poll_failures


STATUS_EVENTS = {
    "published": "social.post.published",
    "posted": "social.post.published",
    "failed": "social.post.failed",
    "error": "social.post.failed",
    "cancelled": "social.post.cancelled",
    "canceled": "social.post.cancelled",
}


def _items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        values = raw
    elif isinstance(raw, dict):
        values = raw.get("posts") or raw.get("items") or []
    else:
        values = []
    return [item for item in values if isinstance(item, dict)][: settings.postly_poll_batch_size]


def _provider_version(item: dict[str, Any]) -> str:
    for key in ("updatedAt", "updated_at", "modifiedAt", "date", "status"):
        value = item.get(key)
        if value is not None and str(value):
            return str(value)[:128]
    return hashlib.sha256(
        json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _belongs_to_account(item: dict[str, Any], provider_account_id: str) -> bool:
    values = item.get("integration") or item.get("integrations") or []
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list):
        return False
    identifiers = {
        str(value.get("id", "")) if isinstance(value, dict) else str(value)
        for value in values
    }
    return provider_account_id in identifiers


async def poll_account(
    session: AsyncSession,
    client: PostizClient,
    account: dict[str, Any],
    *,
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(UTC)
    account_id = UUID(str(account["id"]))
    correlation_id = f"postly-poll-{account_id}-{int(now.timestamp())}"
    checkpoint = (
        await session.execute(
            text(
                """SELECT last_updated_at FROM social_poll_checkpoints
                WHERE provider='postly' AND account_id=:account FOR UPDATE"""
            ),
            {"account": account_id},
        )
    ).mappings().first()
    start = (
        checkpoint["last_updated_at"] - timedelta(seconds=settings.postly_poll_lookback_seconds)
        if checkpoint and checkpoint["last_updated_at"]
        else now - timedelta(seconds=settings.postly_poll_lookback_seconds)
    )
    await session.execute(
        text(
            """INSERT INTO social_poll_checkpoints
            (provider,account_id,last_attempt_at,status,correlation_id)
            VALUES ('postly',:account,:now,'POLLING',:correlation)
            ON CONFLICT (provider,account_id) DO UPDATE SET
            last_attempt_at=:now,status='POLLING',error_code=NULL,
            correlation_id=:correlation,updated_at=:now"""
        ),
        {"account": account_id, "now": now, "correlation": correlation_id},
    )
    await session.commit()
    try:
        raw = await client.list_posts(
            start_date=start.isoformat(),
            end_date=now.isoformat(),
            correlation_id=correlation_id,
        )
    except PostizError as exc:
        status = "AUTH_REQUIRED" if exc.code == "authentication" else "BACKOFF"
        await session.execute(
            text(
                """UPDATE social_poll_checkpoints SET status=:status,error_code=:error,
                last_attempt_at=:now,updated_at=:now WHERE provider='postly' AND account_id=:account"""
            ),
            {"status": status, "error": exc.code[:64], "now": now, "account": account_id},
        )
        await session.commit()
        poll_failures.labels(reason=exc.code).inc()
        raise

    emitted = 0
    last_object: str | None = None
    for item in _items(raw):
        if not _belongs_to_account(item, str(account["provider_account_id"])):
            continue
        provider_object_id = str(item.get("id") or item.get("postId") or "")[:255]
        event_type = STATUS_EVENTS.get(str(item.get("status", "")).lower())
        if not provider_object_id or not event_type:
            continue
        subject = await session.scalar(
            text(
                """SELECT id FROM social_posts
                WHERE provider='postly' AND provider_post_id=:provider_id"""
            ),
            {"provider_id": provider_object_id},
        )
        if subject is None:
            continue
        subject_id = UUID(str(subject))
        version = _provider_version(item)
        observation_id = uuid5(
            NAMESPACE_URL,
            f"postly:{account_id}:{provider_object_id}:{event_type}:{version}",
        )
        safe_payload = {
            "status": str(item.get("status", ""))[:64],
            "provider_post_id": provider_object_id,
        }
        normalized = {
            "event_id": str(observation_id),
            "event_type": event_type,
            "event_version": 1,
            "occurred_at": now.isoformat(),
            "correlation_id": correlation_id,
            "tenant_id": str(account["tenant_id"]),
            "source": "social",
            "provider": "postly",
            "subject_id": str(subject_id),
            "payload": safe_payload,
        }
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        payload_hash = hashlib.sha256(encoded.encode()).hexdigest()
        inserted = await session.scalar(
            text(
                """INSERT INTO social_poll_observations
                (id,provider,account_id,provider_object_id,normalized_event_type,
                 provider_version,payload_hash)
                VALUES (:id,'postly',:account,:object,:type,:version,:hash)
                ON CONFLICT DO NOTHING RETURNING id"""
            ),
            {
                "id": observation_id,
                "account": account_id,
                "object": provider_object_id,
                "type": event_type,
                "version": version,
                "hash": payload_hash,
            },
        )
        if inserted is None:
            continue
        integration_id = await session.scalar(
            text(
                """INSERT INTO integration_event
                (idempotency_key,event_type,schema_version,original_event_id,entity_key,
                 source_system,correlation_id,payload_json,payload_hash,state)
                VALUES (:key,:type,'1.0',:original,:entity,'social',:correlation,
                 CAST(:payload AS jsonb),:hash,'queued') RETURNING id"""
            ),
            {
                "key": f"social-poll:{observation_id}",
                "type": event_type,
                "original": str(observation_id),
                "entity": f"social:{subject_id}",
                "correlation": correlation_id,
                "payload": encoded,
                "hash": payload_hash,
            },
        )
        await session.execute(
            text(
                """UPDATE social_poll_observations SET integration_event_id=:event
                WHERE id=:id"""
            ),
            {"event": integration_id, "id": observation_id},
        )
        if settings.social_n8n_events_enabled:
            await session.execute(
                text(
                    """INSERT INTO integration_delivery(id,event_id,target,status,attempts)
                    VALUES (:id,:event,'n8n','pending',0) ON CONFLICT DO NOTHING"""
                ),
                {"id": uuid4(), "event": integration_id},
            )
        emitted += 1
        last_object = provider_object_id
        poll_events_emitted.labels(event_type=event_type).inc()
    await session.execute(
        text(
            """UPDATE social_poll_checkpoints SET last_updated_at=:now,
            last_provider_object_id=COALESCE(:object,last_provider_object_id),
            last_success_at=:now,last_attempt_at=:now,status='READY',error_code=NULL,
            correlation_id=:correlation,updated_at=:now
            WHERE provider='postly' AND account_id=:account"""
        ),
        {
            "now": now,
            "object": last_object,
            "correlation": correlation_id,
            "account": account_id,
        },
    )
    await session.commit()
    poll_cycles.labels(result="success").inc()
    return emitted


async def poll_cycle(session: AsyncSession, client: PostizClient) -> int:
    accounts = (
        await session.execute(
            text(
                """SELECT id,tenant_id,provider_account_id FROM social_accounts
                WHERE provider='postly' AND connection_state='connected'
                ORDER BY id LIMIT :limit"""
            ),
            {"limit": settings.postly_poll_batch_size},
        )
    ).mappings().all()
    emitted = 0
    for account in accounts:
        try:
            emitted += await poll_account(session, client, dict(account))
        except PostizError:
            continue
    if not accounts:
        poll_cycles.labels(result="no_accounts").inc()
    return emitted
