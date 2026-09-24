"""Durable, lease-safe BREERO delivery to the restricted Odoo module."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.reliability import RetryPolicy

CLAIM = text("""WITH c AS (
 SELECT id FROM breero_odoo_outbox WHERE status IN ('pending','retry_wait')
 AND (next_attempt_at IS NULL OR next_attempt_at<=now())
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT :limit)
UPDATE breero_odoo_outbox o SET status='leased',lease_token=gen_random_uuid(),
 lease_expires_at=now()+make_interval(secs=>:lease),updated_at=now()
FROM c WHERE o.id=c.id RETURNING o.id,o.receipt_public_id,o.lease_token,o.attempts""")
RECOVER = text("""UPDATE breero_odoo_outbox SET status='retry_wait',lease_token=NULL,
 lease_expires_at=NULL,next_attempt_at=now(),last_safe_error='lease_expired',updated_at=now()
WHERE status='leased' AND lease_expires_at<=now() RETURNING id""")
RECEIPT = text("""SELECT public_id,event_id,event_type,schema_version,aggregate_id,
 aggregate_version,occurred_at,idempotency_key,source,payload,route_key
 FROM breero_event_receipt WHERE public_id=:receipt""")
ACK = text("""UPDATE breero_odoo_outbox SET status='delivered',odoo_model=:model,
 odoo_record_id=:record,lease_token=NULL,lease_expires_at=NULL,last_safe_error=NULL,updated_at=now()
WHERE id=:id AND status='leased' AND lease_token=:token RETURNING id""")
FAIL = text("""UPDATE breero_odoo_outbox SET status=:status,attempts=:attempts,
 next_attempt_at=CASE WHEN :delay IS NULL THEN NULL ELSE now()+make_interval(secs=>:delay) END,
 last_safe_error=:error,lease_token=NULL,lease_expires_at=NULL,updated_at=now()
WHERE id=:id AND status='leased' AND lease_token=:token RETURNING id""")
AUDIT = text("""INSERT INTO breero_integration_audit
(receipt_public_id,action,outcome,safe_detail) VALUES (:receipt,:action,:outcome,:detail)""")

ROUTES = {
    "BREERO_CUSTOMER_REQUESTS",
    "BREERO_SUPPORT_BUSINESS",
    "BREERO_PROVIDER_RECRUITMENT",
    "BREERO_LEAD_DISPUTES",
}


def build_odoo_envelope(receipt: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the complete, validated BREERO contract for Odoo."""
    occurred_at = receipt["occurred_at"]
    if hasattr(occurred_at, "isoformat"):
        occurred_at = occurred_at.isoformat()
    return {
        "event_id": str(receipt["event_id"]),
        "event_type": receipt["event_type"],
        "schema_version": receipt["schema_version"],
        "aggregate_id": str(receipt["aggregate_id"]),
        "aggregate_version": receipt["aggregate_version"],
        "occurred_at": occurred_at,
        "idempotency_key": receipt["idempotency_key"],
        "source": receipt["source"],
        "payload": receipt["payload"],
    }


class DeliveryFailure(RuntimeError):
    def __init__(self, code: str, *, permanent: bool = False):
        super().__init__(code)
        self.code = code
        self.permanent = permanent


class Transport(Protocol):
    async def deliver(
        self, envelope: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]: ...


@dataclass
class RestrictedOdooTransport:
    async def deliver(
        self, envelope: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        try:
            key = Path(settings.breero_odoo_api_key_file).read_text().strip()
        except OSError as exc:
            raise DeliveryFailure("credential_unavailable", permanent=True) from exc
        if not all(
            (
                settings.breero_odoo_url,
                settings.breero_odoo_database,
                settings.breero_odoo_username,
                key,
            )
        ):
            raise DeliveryFailure("odoo_not_configured", permanent=True)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                authentication = await client.post(
                    settings.breero_odoo_url.rstrip("/") + "/jsonrpc",
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "id": f"{idempotency_key}:authenticate",
                        "params": {
                            "service": "common",
                            "method": "authenticate",
                            "args": [
                                settings.breero_odoo_database,
                                settings.breero_odoo_username,
                                key,
                                {},
                            ],
                        },
                    },
                )
                authentication.raise_for_status()
                authentication_body = authentication.json()
                uid = authentication_body.get("result")
                if not isinstance(uid, int) or uid < 1:
                    raise DeliveryFailure("odoo_authentication_rejected", permanent=True)
                rpc = {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "id": idempotency_key,
                    "params": {
                        "service": "object",
                        "method": "execute_kw",
                        "args": [
                            settings.breero_odoo_database,
                            uid,
                            key,
                            "breero.sync.event",
                            "process_breero_event",
                            [envelope],
                            {},
                        ],
                    },
                }
                response = await client.post(
                    settings.breero_odoo_url.rstrip("/") + "/jsonrpc", json=rpc
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise DeliveryFailure("odoo_unavailable") from exc
        except httpx.HTTPStatusError as exc:
            raise DeliveryFailure(
                "odoo_http_error", permanent=exc.response.status_code in {400, 401, 403}
            ) from exc
        if body.get("error"):
            name = str(body["error"].get("data", {}).get("name", ""))
            raise DeliveryFailure(
                "odoo_rejected",
                permanent=any(
                    x in name
                    for x in ("AccessDenied", "AccessError", "ValidationError")
                ),
            )
        ack = body.get("result")
        if (
            not isinstance(ack, dict)
            or not isinstance(ack.get("odoo_record_id"), int)
            or ack["odoo_record_id"] < 1
            or not isinstance(ack.get("odoo_model"), str)
        ):
            raise DeliveryFailure("invalid_odoo_ack", permanent=True)
        return ack


async def recover_stale(session: AsyncSession) -> int:
    rows = (await session.execute(RECOVER)).all()
    await session.commit()
    return len(rows)


async def claim(session: AsyncSession, limit: int, lease: int) -> list[dict[str, Any]]:
    rows = (
        (await session.execute(CLAIM, {"limit": limit, "lease": lease}))
        .mappings()
        .all()
    )
    await session.commit()
    return [dict(row) for row in rows]


async def process(
    session: AsyncSession, item: dict[str, Any], transport: Transport
) -> str:
    receipt = (
        (await session.execute(RECEIPT, {"receipt": item["receipt_public_id"]}))
        .mappings()
        .one()
    )
    if receipt["route_key"] not in ROUTES:
        failure = DeliveryFailure("unknown_route", permanent=True)
    else:
        envelope = build_odoo_envelope(dict(receipt))
        try:
            ack = await transport.deliver(envelope, receipt["public_id"])
        except DeliveryFailure as exc:
            failure = exc
        else:
            changed = (
                await session.execute(
                    ACK,
                    {
                        "id": item["id"],
                        "token": item["lease_token"],
                        "model": ack["odoo_model"],
                        "record": ack["odoo_record_id"],
                    },
                )
            ).first()
            if changed is None:
                raise RuntimeError("delivery lease lost")
            await session.execute(
                text(
                    "UPDATE breero_event_receipt SET status='delivered',updated_at=now() WHERE public_id=:r"
                ),
                {"r": receipt["public_id"]},
            )
            await session.execute(
                AUDIT,
                {
                    "receipt": receipt["public_id"],
                    "action": "odoo.delivery",
                    "outcome": "delivered",
                    "detail": receipt["route_key"],
                },
            )
            await session.commit()
            return "delivered"
    attempts = int(item["attempts"]) + 1
    policy = RetryPolicy(
        max_attempts=settings.breero_worker_max_attempts,
        base_seconds=2,
        max_seconds=300,
    )
    dead = failure.permanent or attempts >= policy.max_attempts
    status = "dead_letter" if dead else "retry_wait"
    changed = (
        await session.execute(
            FAIL,
            {
                "id": item["id"],
                "token": item["lease_token"],
                "status": status,
                "attempts": attempts,
                "delay": None if dead else policy.delay(attempts),
                "error": failure.code,
            },
        )
    ).first()
    if changed is None:
        raise RuntimeError("delivery lease lost")
    await session.execute(
        text(
            "UPDATE breero_event_receipt SET status=:s,updated_at=now() WHERE public_id=:r"
        ),
        {"s": status, "r": receipt["public_id"]},
    )
    await session.execute(
        AUDIT,
        {
            "receipt": receipt["public_id"],
            "action": "odoo.delivery",
            "outcome": status,
            "detail": failure.code,
        },
    )
    await session.commit()
    return status


async def reconcile(session: AsyncSession) -> dict[str, int]:
    row = (
        (
            await session.execute(
                text("""SELECT count(*) AS receipts,
      count(o.id) AS outbox,count(*) FILTER (WHERE r.status='delivered' AND o.status='delivered') AS delivered,
      count(*) FILTER (WHERE o.id IS NULL OR r.status<>o.status) AS gaps
      FROM breero_event_receipt r LEFT JOIN breero_odoo_outbox o ON o.receipt_public_id=r.public_id""")
            )
        )
        .mappings()
        .one()
    )
    return {key: int(row[key]) for key in ("receipts", "outbox", "delivered", "gaps")}
