"""Lease-safe delivery of normalized Klyrow inbound mail to Odoo."""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

CLAIM = text("""WITH c AS (
 SELECT event_id FROM klyrow_mail_inbound WHERE status IN ('pending','retry_wait')
 AND (next_attempt_at IS NULL OR next_attempt_at<=now()) ORDER BY created_at
 FOR UPDATE SKIP LOCKED LIMIT :limit)
UPDATE klyrow_mail_inbound m SET status='leased',lease_token=gen_random_uuid(),
 lease_expires_at=now()+make_interval(secs=>:lease),updated_at=now()
FROM c WHERE m.event_id=c.event_id RETURNING m.*""")


class DeliveryFailure(RuntimeError):
    def __init__(self, code: str, *, permanent: bool = False):
        super().__init__(code)
        self.code, self.permanent = code, permanent


class Transport(Protocol):
    async def deliver(
        self, payload: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]: ...


def _odoo_payload(row: dict[str, Any]) -> dict[str, Any]:
    event = row["payload"]
    sender = parseaddr(event.get("sender") or "")[1]
    if not sender or sender.count("@") != 1 or sender.startswith("@") or sender.endswith("@"):
        raise DeliveryFailure("invalid_sender", permanent=True)
    message_id = (
        event.get("message_id") or f"<{row['provider_event_id']}@mail.klyrow.com>"
    )
    references = re.findall(r"<[^>]{1,996}>", event.get("references") or "")[:100]
    return {
        "event_id": row["event_id"],
        "idempotency_key": row["idempotency_key"],
        "correlation_id": event.get("inbound_id") or row["inbound_id"],
        "timestamp": datetime.now(UTC).isoformat(),
        "message_id": message_id,
        "in_reply_to": event.get("in_reply_to"),
        "references": references,
        "recipient": row["recipient"],
        "sender": sender,
        "subject": event.get("subject") or "",
        "body_text": event.get("text") or "",
        "body_html": event.get("html") or "",
        "raw_size": len((event.get("text") or "").encode())
        + len((event.get("html") or "").encode()),
        "attachments": [
            {
                "filename": item["filename"],
                "mimetype": item["content_type"],
                "content_base64": item["data_b64"],
            }
            for item in event.get("attachments", [])
        ],
        "authenticated_identity": "codestra-middleware",
        "signature_valid": True,
    }


@dataclass
class RestrictedOdooTransport:
    async def deliver(
        self, payload: dict[str, Any], idempotency_key: str
    ) -> dict[str, Any]:
        try:
            key = Path(settings.klyrow_mail_odoo_api_key_file).read_text().strip()
        except OSError as exc:
            raise DeliveryFailure("credential_unavailable", permanent=True) from exc
        if not all(
            (
                settings.klyrow_mail_odoo_url,
                settings.klyrow_mail_odoo_database,
                settings.klyrow_mail_odoo_username,
                key,
            )
        ):
            raise DeliveryFailure("odoo_not_configured", permanent=True)
        origin = urlsplit(settings.klyrow_mail_odoo_url)
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
        ):
            raise DeliveryFailure("odoo_https_origin_required", permanent=True)
        if not settings.klyrow_mail_odoo_ca_file:
            raise DeliveryFailure("odoo_tls_unavailable", permanent=True)
        try:
            tls = ssl.create_default_context(cafile=settings.klyrow_mail_odoo_ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise DeliveryFailure("odoo_tls_unavailable", permanent=True) from exc
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        url = settings.klyrow_mail_odoo_url.rstrip("/") + "/jsonrpc"
        try:
            async with httpx.AsyncClient(
                timeout=20, trust_env=False, verify=tls, follow_redirects=False
            ) as client:
                auth = await client.post(
                    url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "call",
                        "id": idempotency_key + ":auth",
                        "params": {
                            "service": "common",
                            "method": "authenticate",
                            "args": [
                                settings.klyrow_mail_odoo_database,
                                settings.klyrow_mail_odoo_username,
                                key,
                                {},
                            ],
                        },
                    },
                )
                auth.raise_for_status()
                uid = auth.json().get("result")
                if not isinstance(uid, int) or uid < 1:
                    raise DeliveryFailure(
                        "odoo_authentication_rejected", permanent=True
                    )
                rpc = {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "id": idempotency_key,
                    "params": {
                        "service": "object",
                        "method": "execute_kw",
                        "args": [
                            settings.klyrow_mail_odoo_database,
                            uid,
                            key,
                            "codestra.mail.inbound.event",
                            "ingest_event",
                            [payload],
                            {},
                        ],
                    },
                }
                response = await client.post(url, json=rpc)
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
        result = body.get("result")
        record_id = (
            result
            if isinstance(result, int)
            else (result.get("id") if isinstance(result, dict) else None)
        )
        if not isinstance(record_id, int) or record_id < 1:
            raise DeliveryFailure("invalid_odoo_ack", permanent=True)
        return {"odoo_record_id": record_id}


async def recover_stale(session: AsyncSession) -> int:
    rows = (
        await session.execute(
            text("""UPDATE klyrow_mail_inbound SET status='retry_wait',
      lease_token=NULL,lease_expires_at=NULL,next_attempt_at=now(),last_safe_error='lease_expired',updated_at=now()
      WHERE status='leased' AND lease_expires_at<=now() RETURNING event_id""")
        )
    ).all()
    await session.commit()
    return len(rows)


async def claim(session: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        (
            await session.execute(
                CLAIM,
                {
                    "limit": settings.klyrow_mail_worker_batch_size,
                    "lease": settings.klyrow_mail_worker_lease_seconds,
                },
            )
        )
        .mappings()
        .all()
    )
    await session.commit()
    return [dict(row) for row in rows]


async def process(
    session: AsyncSession, row: dict[str, Any], transport: Transport
) -> str:
    try:
        ack = await transport.deliver(_odoo_payload(row), row["idempotency_key"])
    except DeliveryFailure as failure:
        attempts = int(row["attempts"]) + 1
        dead = failure.permanent or attempts >= settings.klyrow_mail_worker_max_attempts
        changed = (
            await session.execute(
                text("""UPDATE klyrow_mail_inbound SET status=:status,attempts=:attempts,
          next_attempt_at=CASE WHEN :dead THEN NULL ELSE now()+make_interval(secs=>LEAST(300,2^:attempts)) END,
          last_safe_error=:error,lease_token=NULL,lease_expires_at=NULL,updated_at=now()
          WHERE event_id=:id AND status='leased' AND lease_token=:token RETURNING event_id"""),
                {
                    "status": "dead_letter" if dead else "retry_wait",
                    "attempts": attempts,
                    "dead": dead,
                    "error": failure.code,
                    "id": row["event_id"],
                    "token": row["lease_token"],
                },
            )
        ).first()
        if changed is None:
            raise RuntimeError("delivery_lease_lost")
        await session.commit()
        return "dead_letter" if dead else "retry_wait"
    changed = (
        await session.execute(
            text("""UPDATE klyrow_mail_inbound SET status='delivered',
      odoo_record_id=:record,last_safe_error=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=now()
      WHERE event_id=:id AND status='leased' AND lease_token=:token RETURNING event_id"""),
            {
                "record": ack["odoo_record_id"],
                "id": row["event_id"],
                "token": row["lease_token"],
            },
        )
    ).first()
    if changed is None:
        raise RuntimeError("delivery_lease_lost")
    await session.commit()
    return "delivered"
