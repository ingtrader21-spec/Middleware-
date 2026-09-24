"""Durable callback popup delivery to the existing application WebSocket gateway."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.callback_rls import set_callback_rls_context
from app.db.models import CallbackDelivery, CallbackRecord

STAGE_EVENTS = {
    "WARNING": "callback.warning",
    "WARNING_15M": "callback.warning",
    "DUE": "callback.due",
    "MISSED": "callback.missed",
    "ESCALATED": "callback.escalated",
    "CANCELLED": "callback.cancelled",
    "COMPLETED": "callback.completed",
    "RESCHEDULED": "callback.rescheduled",
}


def _masked_phone(value: str) -> str:
    digits = "".join(character for character in value if character.isdigit())
    return f"***{digits[-4:]}" if digits else ""


def _document(delivery: CallbackDelivery, callback: CallbackRecord) -> dict:
    event_type = STAGE_EVENTS.get(delivery.stage.upper())
    if not event_type:
        raise ValueError("unsupported callback delivery stage")
    if not callback.assigned_user_id or not callback.assigned_agent_id:
        raise ValueError("callback realtime target is incomplete")
    return {
        "event_id": delivery.idempotency_key,
        "schema_version": "1.0",
        "type": event_type,
        "correlation_id": callback.correlation_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "tenant_id": callback.tenant_id,
        "business_unit_id": callback.tenant_id,
        "campaign_id": callback.campaign_id,
        "user_id": callback.assigned_user_id,
        "agent_id": callback.assigned_agent_id,
        "call_id": callback.original_call_id,
        "sequence": callback.version,
        "payload": {
            "callback_id": str(callback.id),
            "callback_version": callback.version,
            "state": callback.state,
            "scheduled_at": callback.scheduled_at.isoformat(),
            "customer_timezone": callback.customer_timezone,
            "priority": callback.priority,
            "reason": callback.reason,
            "phone_masked": _masked_phone(callback.phone_number),
            "customer_context": callback.context_json or {},
        },
    }


async def deliver_callback_popups(
    db: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
    gateway_url: str,
    token_file: str,
    limit: int = 50,
    client: httpx.AsyncClient | None = None,
) -> dict[str, int]:
    """Claim and deliver callback popup rows with retry and stale protection."""
    if not tenant_id or not campaign_id:
        raise ValueError("callback delivery requires tenant and campaign allowlists")
    token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("WebSocket gateway token is empty")
    await set_callback_rls_context(
        db,
        tenant_id=tenant_id,
        campaign_ids=(campaign_id,),
        actor_id="callback-realtime-worker",
        role="service",
    )
    now = datetime.now(UTC)
    rows = (
        await db.execute(
            select(CallbackDelivery, CallbackRecord)
            .join(CallbackRecord)
            .where(
                CallbackRecord.tenant_id == tenant_id,
                CallbackRecord.campaign_id == campaign_id,
                CallbackDelivery.channel == "POPUP",
                CallbackDelivery.status.in_(["QUEUED", "RETRY_PENDING"]),
                CallbackDelivery.next_attempt_at <= now,
            )
            .order_by(CallbackDelivery.next_attempt_at)
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
    ).all()
    delivered = retried = stale = 0
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=5, follow_redirects=False)
    try:
        for delivery, callback in rows:
            if delivery.callback_version != callback.version:
                delivery.status = "STALE_CANCELLED"
                delivery.next_attempt_at = None
                stale += 1
                continue
            try:
                response = await http.post(
                    gateway_url,
                    headers={"X-Codestra-Internal-Token": token},
                    json=_document(delivery, callback),
                )
                response.raise_for_status()
                if not response.json().get("accepted"):
                    raise ValueError("WebSocket gateway did not accept callback event")
                delivery.status = "DELIVERED"
                delivery.provider_message_id = delivery.idempotency_key
                delivery.next_attempt_at = None
                delivered += 1
            except (httpx.HTTPError, ValueError):
                delivery.attempt_count += 1
                delivery.status = "RETRY_PENDING"
                delivery.last_error_code = "WEBSOCKET_DELIVERY_FAILED"
                delivery.next_attempt_at = now + timedelta(
                    seconds=min(300, 2 ** min(delivery.attempt_count, 8))
                )
                retried += 1
        await db.commit()
    finally:
        if owns_client:
            await http.aclose()
    return {"delivered": delivered, "retry_pending": retried, "stale": stale}
