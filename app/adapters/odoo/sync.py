"""Authenticated claim/lease intake from the authoritative Odoo outbox."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.service_tokens import client_credentials_token
from app.db.models import AuditEvent, IntegrationEvent
from app.db.session import SessionFactory


class OdooSyncError(RuntimeError):
    """Safe runtime error that never contains provider response bodies."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def traceparent(correlation_id: str, resource_id: str) -> str:
    trace_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    span_id = hashlib.sha256(resource_id.encode()).hexdigest()[:16]
    return f"00-{trace_id}-{span_id}-01"


@dataclass
class OdooRuntimeClient:
    http: httpx.AsyncClient
    access_token: str

    @classmethod
    async def create(cls) -> "OdooRuntimeClient":
        verify: bool | str = settings.odoo_ca_file or True
        http = httpx.AsyncClient(
            verify=verify,
            follow_redirects=False,
            timeout=httpx.Timeout(
                settings.odoo_read_timeout,
                connect=settings.odoo_connect_timeout,
            ),
        )
        try:
            token = await client_credentials_token(
                token_url=settings.odoo_token_url,
                client_id=settings.odoo_client_id,
                client_secret_file=settings.odoo_client_secret_file,
                audience=settings.odoo_audience,
                scope=settings.odoo_scope,
                client=http,
            )
        except Exception:
            await http.aclose()
            raise
        return cls(http=http, access_token=token)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        idempotency_key: str,
        correlation_id: str,
        causation_id: str,
    ) -> dict[str, Any]:
        raw = canonical_json(payload) if payload is not None else b""
        request_id = str(uuid4())
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "X-Codestra-Timestamp": str(int(time.time())),
            "X-Codestra-Nonce": secrets.token_hex(24),
            "X-Codestra-Body-SHA256": hashlib.sha256(raw).hexdigest(),
            "X-Codestra-Request-ID": request_id,
            "X-Codestra-Correlation-ID": correlation_id,
            "X-Codestra-Causation-ID": causation_id,
            "Idempotency-Key": idempotency_key,
            "traceparent": traceparent(correlation_id, request_id),
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        url = f"{settings.odoo_base_url.rstrip('/')}/{path.lstrip('/')}"
        response: httpx.Response | None = None
        for attempt in range(max(1, settings.odoo_max_retries)):
            try:
                response = await self.http.request(
                    method, url, content=raw or None, headers=headers
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt + 1 >= max(1, settings.odoo_max_retries):
                    raise OdooSyncError("Odoo dependency unavailable") from exc
                await asyncio.sleep(min(2**attempt, 4))
                continue
            if response.status_code in {429, 502, 503, 504} and attempt + 1 < max(
                1, settings.odoo_max_retries
            ):
                await asyncio.sleep(min(2**attempt, 4))
                continue
            break
        if response is None or response.is_redirect:
            raise OdooSyncError("Odoo response rejected")
        if response.status_code not in {200, 201}:
            raise OdooSyncError(
                f"Odoo request rejected with HTTP {response.status_code}"
            )
        try:
            document = response.json()
        except ValueError as exc:
            raise OdooSyncError("Odoo response is invalid") from exc
        if not isinstance(document, dict):
            raise OdooSyncError("Odoo response is invalid")
        return document


def _validate_record(record: dict[str, Any]) -> tuple[dict[str, Any], str]:
    required = {
        "event_id",
        "event_type",
        "schema_version",
        "payload",
        "payload_hash",
        "correlation_id",
        "lease_token",
        "lease_generation",
    }
    if not required.issubset(record) or not isinstance(record["payload"], dict):
        raise OdooSyncError("Odoo outbox record schema rejected")
    digest = hashlib.sha256(canonical_json(record["payload"])).hexdigest()
    supplied = str(record["payload_hash"]).removeprefix("sha256:")
    if not secrets.compare_digest(digest, supplied):
        raise OdooSyncError("Odoo outbox payload hash rejected")
    return record["payload"], digest


async def persist_intake(record: dict[str, Any]) -> tuple[bool, int]:
    payload, digest = _validate_record(record)
    event_id = str(record["event_id"])
    async with SessionFactory() as session:
        existing = await session.scalar(
            select(IntegrationEvent).where(
                IntegrationEvent.original_event_id == event_id
            )
        )
        if existing:
            if existing.payload_hash != digest:
                raise OdooSyncError("Odoo event idempotency conflict")
            return True, existing.id
        incoming = IntegrationEvent(
            idempotency_key=str(record.get("idempotency_key") or event_id),
            event_type=str(record["event_type"]),
            schema_version=str(record["schema_version"]),
            original_event_id=event_id,
            entity_key=f"odoo:{record.get('aggregate_type', 'record')}:{record.get('aggregate_public_id', event_id)}",
            source_system="odoo",
            correlation_id=str(record["correlation_id"]),
            payload_json=payload,
            payload_hash=digest,
            state="accepted",
        )
        session.add(incoming)
        session.add(
            AuditEvent(
                action="odoo.outbox.accepted",
                subject=event_id,
                correlation_id=str(record["correlation_id"]),
                decision="accepted",
                redacted_payload={
                    "event_type": str(record["event_type"]),
                    "schema_version": str(record["schema_version"]),
                    "payload_hash": digest,
                },
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            existing = await session.scalar(
                select(IntegrationEvent).where(
                    IntegrationEvent.original_event_id == event_id
                )
            )
            if existing is None or existing.payload_hash != digest:
                raise OdooSyncError("Odoo event idempotency conflict")
            return True, existing.id
        return False, incoming.id


async def run_sync_cycle() -> dict[str, object]:
    client = await OdooRuntimeClient.create()
    try:
        capabilities = await client.request(
            "GET",
            "/api/v1/integration/capabilities",
            None,
            idempotency_key=f"capabilities-{uuid4()}",
            correlation_id=str(uuid4()),
            causation_id="odoo-sync-cycle",
        )
        supported = set(capabilities.get("capabilities", []))
        required = {"outbox.claim", "outbox.acknowledge"}
        if not required.issubset(supported):
            raise OdooSyncError("Odoo capability contract incompatible")
        correlation_id = str(uuid4())
        claim = await client.request(
            "POST",
            "/api/v1/integration/outbox/claims",
            {
                "consumer_id": settings.odoo_sync_worker_id,
                "batch_size": settings.odoo_sync_batch_size,
                "lease_ttl_ms": settings.odoo_sync_lease_seconds * 1000,
                "environment": settings.environment.upper(),
            },
            idempotency_key=f"claim-{correlation_id}",
            correlation_id=correlation_id,
            causation_id="odoo-sync-cycle",
        )
        records = claim.get("records", [])
        if not isinstance(records, list):
            raise OdooSyncError("Odoo claim response schema rejected")
        accepted = duplicates = 0
        for record in records:
            if not isinstance(record, dict):
                raise OdooSyncError("Odoo claim response schema rejected")
            duplicate, _ = await persist_intake(record)
            duplicates += int(duplicate)
            accepted += int(not duplicate)
            event_id = str(record["event_id"])
            await client.request(
                "POST",
                f"/api/v1/integration/outbox/{event_id}/acknowledgements",
                {
                    "consumer_id": settings.odoo_sync_worker_id,
                    "lease_token": record["lease_token"],
                    "lease_generation": record["lease_generation"],
                    "idempotency_key": f"ack-{event_id}",
                    "correlation_id": str(record["correlation_id"]),
                    "causation_id": event_id,
                },
                idempotency_key=f"ack-{event_id}",
                correlation_id=str(record["correlation_id"]),
                causation_id=event_id,
            )
        return {
            "status": "processed" if records else "idle",
            "claimed": len(records),
            "accepted": accepted,
            "duplicates": duplicates,
        }
    finally:
        await client.aclose()
