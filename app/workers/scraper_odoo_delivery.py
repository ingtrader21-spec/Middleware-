"""Durable, staging-only delivery of validated scraper leads to Odoo."""

from __future__ import annotations

import asyncio
from typing import Mapping

import httpx
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text

from app.adapters.odoo.lead_automation import (
    OdooApplyError,
    OdooLeadApplyClient,
    TransportResponse,
)
from app.core.config import settings
from app.core.reliability import RetryPolicy
from app.db.session import SessionFactory
from app.metrics import DLQ_DEPTH, OLDEST_AGE, QUEUE_DEPTH, REDIS_ERRORS
from app.sales.queue import ScraperRedisQueue
from app.workers.outbox import acknowledge, record_failure, recover_expired_leases


CLAIM = text("""
WITH claimable AS (
    SELECT id FROM outbox_event
    WHERE topic='sales.lead.odoo.apply'
      AND status IN ('pending', 'retry')
      AND (next_attempt_at IS NULL OR next_attempt_at <= now())
    ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT :limit
)
UPDATE outbox_event AS item SET status='processing', locked_at=now(),
    next_attempt_at=now() + make_interval(secs => :lease)
FROM claimable WHERE item.id=claimable.id
RETURNING item.id,item.payload,item.attempts,item.correlation_id
""")

SIGNALABLE = text("""
SELECT id,correlation_id FROM outbox_event
WHERE topic='sales.lead.odoo.apply'
  AND status IN ('pending','retry')
  AND (next_attempt_at IS NULL OR next_attempt_at <= now())
ORDER BY created_at,id LIMIT :limit
""")

SCRAPER_METRICS = text("""
SELECT status,count(*) AS count,
       EXTRACT(EPOCH FROM (now()-min(received_at)))::bigint AS oldest
FROM sales_scraper_inbox GROUP BY status
""")

INBOX_RESULT = text("""
UPDATE sales_scraper_inbox
SET status=:status, attempts=:attempts,
    next_attempt_at=(SELECT next_attempt_at FROM outbox_event WHERE id=:outbox_id),
    rejection_code=:error_code, odoo_result_reference=:odoo_reference,
    updated_at=now()
WHERE correlation_id=:correlation_id AND status NOT IN ('delivered','dead_letter')
""")

INBOX_PROCESSING = text("""
UPDATE sales_scraper_inbox SET status='processing',updated_at=now()
WHERE correlation_id=:correlation_id AND status IN ('queued','retry_wait')
""")

INBOX_STATES = (
    "received",
    "eligible",
    "rejected",
    "queued",
    "processing",
    "retry_wait",
    "delivered",
    "dead_letter",
)


def _permanent_failure(exc: Exception) -> bool:
    """Contract, authentication, and acknowledgement failures must not retry."""
    return isinstance(exc, OdooApplyError)


def _transport(
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    timeout: float,
) -> TransportResponse:
    url = settings.scraper_odoo_apply_url.rstrip("/") + path
    response = httpx.request(method, url, content=body, headers=headers, timeout=timeout)
    return TransportResponse(response.status_code, response.content)


async def deliver_once(*, limit: int = 8, lease_seconds: int = 60) -> int:
    if not settings.scraper_middleware_delivery_enabled:
        return 0
    client = OdooLeadApplyClient(
        secret=settings.lead_automation_hmac_secret.encode(),
        transport=_transport,
    )
    async with SessionFactory() as session:
        await recover_expired_leases(session)
        rows = (
            await session.execute(CLAIM, {"limit": limit, "lease": lease_seconds})
        ).mappings().all()
        await session.commit()
    for row in rows:
        async with SessionFactory() as session:
            await session.execute(
                INBOX_PROCESSING, {"correlation_id": row["correlation_id"]}
            )
            await session.commit()
        try:
            outcome = await asyncio.to_thread(client.apply, row["payload"])
        except Exception as exc:
            async with SessionFactory() as session:
                status = await record_failure(
                    session,
                    row["id"],
                    int(row["attempts"]),
                    type(exc).__name__,
                    RetryPolicy(max_attempts=8, base_seconds=1, max_seconds=60),
                    permanent=_permanent_failure(exc),
                )
                await session.execute(
                    INBOX_RESULT,
                    {
                        "status": (
                            "dead_letter" if status == "dead_letter" else "retry_wait"
                        ),
                        "attempts": int(row["attempts"]) + 1,
                        "outbox_id": row["id"],
                        "error_code": type(exc).__name__,
                        "odoo_reference": None,
                        "correlation_id": row["correlation_id"],
                    },
                )
                await session.commit()
        else:
            async with SessionFactory() as session:
                await acknowledge(session, row["id"])
                await session.execute(
                    INBOX_RESULT,
                    {
                        "status": "delivered",
                        "attempts": int(row["attempts"]),
                        "outbox_id": row["id"],
                        "error_code": None,
                        "odoo_reference": str(outcome.ack["odoo_record_id"]),
                        "correlation_id": row["correlation_id"],
                    },
                )
                await session.commit()
    return len(rows)


async def recover_and_signal(queue: ScraperRedisQueue, *, limit: int = 100) -> int:
    async with SessionFactory() as session:
        rows = (await session.execute(SIGNALABLE, {"limit": limit})).mappings().all()
        metrics = (await session.execute(SCRAPER_METRICS)).mappings().all()
    counts = dict.fromkeys(INBOX_STATES, 0)
    oldest = 0
    dead_letters = 0
    for row in metrics:
        counts[row["status"]] = int(row["count"])
        if row["status"] in {"received", "eligible", "queued", "processing", "retry_wait"}:
            oldest = max(oldest, int(row["oldest"] or 0))
        if row["status"] == "dead_letter":
            dead_letters = int(row["count"])
    for status, count in counts.items():
        QUEUE_DEPTH.labels(target="scraper", status=status).set(count)
    OLDEST_AGE.labels(target="scraper").set(oldest)
    DLQ_DEPTH.labels(target="scraper").set(dead_letters)
    if not settings.scraper_middleware_delivery_enabled:
        return 0
    signaled = 0
    for row in rows:
        signaled += int(await queue.enqueue(row["id"], row["correlation_id"]))
    return signaled


async def run_forever() -> None:
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    queue = ScraperRedisQueue(redis)
    try:
        while True:
            try:
                await recover_and_signal(queue)
                if not settings.scraper_middleware_delivery_enabled:
                    await asyncio.sleep(1)
                    continue
                signal = await queue.claim(timeout_seconds=1)
            except RedisError:
                # PostgreSQL scanning is the safe recovery path during Redis loss.
                REDIS_ERRORS.labels(operation="scraper_signal").inc()
                signal = {"degraded": True}
            if signal is not None:
                await deliver_once()
            await asyncio.sleep(1)
    finally:
        await redis.aclose()
