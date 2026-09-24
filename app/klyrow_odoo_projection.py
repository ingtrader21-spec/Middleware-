"""Fail-closed Odoo writer for durable Klyrow business projections."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

import httpx

from .api.internal.klyrow_events import (
    KlyrowEvent,
    operation_id_for_klyrow_event,
)
from .models import EventEnvelope
from .odoo_transport import canonical_signing_string, sign
from .storage import KLYROW_ODOO_PROJECTION_DESTINATION, OutboxRecord
from .worker import KnownSafeRetryError


PROJECTION_PATH = "/codestra/middleware/v1/klyrow/events"
STATUS_PATH_TEMPLATE = "/codestra/middleware/v1/klyrow/events/{operation_id}"
SUPPORTED_EVENT_TYPES = frozenset(
    {
        "codestra.klyrow.tenant.created",
        "codestra.klyrow.tenant.updated",
        "codestra.klyrow.subscription.changed",
        "codestra.klyrow.usage.daily",
        "codestra.klyrow.kpi.daily",
        "codestra.klyrow.campaign.summary",
        "codestra.klyrow.domain.status",
        "codestra.klyrow.provider.health",
        "codestra.klyrow.account.held",
        "codestra.klyrow.account.released",
    }
)


class KlyrowProjectionError(RuntimeError):
    """Projection contract or outcome could not be proved."""


class KlyrowProjectionConfigurationError(KlyrowProjectionError):
    """The writer was composed without its required protected settings."""


@dataclass(slots=True)
class Projection:
    envelope: EventEnvelope
    operation_id: str
    body: bytes
    body_sha256: str


@dataclass(slots=True)
class KlyrowOdooProjectionDispatcher:
    client: httpx.AsyncClient
    base_url: str
    secrets: dict[str, bytes]
    default_secret: bytes | None = None

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://"):
            raise KlyrowProjectionConfigurationError("Odoo base URL must be HTTPS")
        if not self.secrets and not self.default_secret:
            raise KlyrowProjectionConfigurationError(
                "no Odoo signing secret is configured"
            )

    def _secret_for(self, tenant_id: str) -> bytes:
        secret = self.secrets.get(tenant_id) or self.default_secret
        if not secret or len(secret) < 32:
            raise KlyrowProjectionConfigurationError(
                f"no valid Odoo signing secret is configured for tenant {tenant_id}"
            )
        return secret

    @staticmethod
    def _projection(record: OutboxRecord) -> Projection:
        if record.destination != KLYROW_ODOO_PROJECTION_DESTINATION:
            raise KlyrowProjectionError("outbox row targets an unsupported destination")
        try:
            envelope = EventEnvelope.model_validate(record.payload)
        except Exception as exc:
            raise KlyrowProjectionError(
                "outbox payload is not a canonical event envelope"
            ) from exc
        if (
            envelope.tenant_id != record.tenant_id
            or envelope.event_type != record.event_type
            or envelope.idempotency_key != record.idempotency_key
        ):
            raise KlyrowProjectionError("outbox identity does not match its envelope")
        if envelope.event_type not in SUPPORTED_EVENT_TYPES:
            raise KlyrowProjectionError("unsupported Klyrow projection event type")
        if envelope.source != "klyrow-gateway":
            raise KlyrowProjectionError("Klyrow projection source is invalid")
        raw_source_event = envelope.payload.get("source_event")
        operation_id = envelope.payload.get("operation_id")
        try:
            source_event = KlyrowEvent.model_validate(raw_source_event)
        except Exception as exc:
            raise KlyrowProjectionError(
                "normalized Klyrow source event is invalid"
            ) from exc
        expected_causation_id = source_event.causation_id or source_event.id
        if (
            source_event.id != envelope.event_id
            or source_event.type != envelope.event_type.removeprefix("codestra.")
            or source_event.tenant_id != envelope.tenant_id
            or source_event.correlation_id != envelope.correlation_id
            or expected_causation_id != envelope.causation_id
            or not isinstance(operation_id, str)
            or operation_id != operation_id_for_klyrow_event(envelope.event_id)
            or envelope.metadata.get("operation_id") != operation_id
            or envelope.metadata.get("wire_event_type") != source_event.type
            or envelope.metadata.get("wire_source") != "klyrow"
        ):
            raise KlyrowProjectionError(
                "normalized Klyrow projection binding is invalid"
            )
        projection = {
            "operation_id": operation_id,
            "event_id": envelope.event_id,
            "event_type": source_event.type,
            "event_version": source_event.version,
            "source": "klyrow",
            "tenant_id": envelope.tenant_id,
            "correlation_id": envelope.correlation_id,
            "causation_id": envelope.causation_id,
            "occurred_at": source_event.occurred_at.isoformat().replace("+00:00", "Z"),
            "data": source_event.data,
            "trace_context": envelope.payload.get("trace_context", {}),
        }
        body = json.dumps(
            projection,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return Projection(
            envelope=envelope,
            operation_id=operation_id,
            body=body,
            body_sha256=hashlib.sha256(body).hexdigest(),
        )

    def _headers(
        self,
        projection: Projection,
        *,
        method: str,
        path: str,
        body: bytes,
    ) -> dict[str, str]:
        envelope = projection.envelope
        timestamp = str(int(time.time()))
        canonical = canonical_signing_string(
            timestamp=timestamp,
            event_id=envelope.event_id,
            method=method,
            path=path,
            tenant_id=envelope.tenant_id,
            correlation_id=envelope.correlation_id,
            idempotency_key=envelope.idempotency_key,
            body=body,
        )
        signature = sign(self._secret_for(envelope.tenant_id), canonical)
        return {
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Event-ID": envelope.event_id,
            "X-Codestra-Signature": f"sha256={signature}",
            "X-Tenant-ID": envelope.tenant_id,
            "X-Correlation-ID": envelope.correlation_id,
            "Idempotency-Key": envelope.idempotency_key,
        }

    @staticmethod
    def _proved_response(
        response: httpx.Response,
        projection: Projection,
    ) -> bool:
        try:
            value = response.json()
        except ValueError:
            return False
        return bool(
            isinstance(value, dict)
            and value.get("operation_id") == projection.operation_id
            and value.get("payload_sha256") == projection.body_sha256
            and value.get("status") in {"ACCEPTED", "APPLIED", "DUPLICATE"}
        )

    async def _readback(self, projection: Projection, *, reason: str) -> None:
        path = STATUS_PATH_TEMPLATE.format(operation_id=projection.operation_id)
        try:
            response = await self.client.get(
                self.base_url.rstrip("/") + path,
                headers=self._headers(projection, method="GET", path=path, body=b""),
            )
        except httpx.RequestError as exc:
            raise KlyrowProjectionError(
                f"Odoo projection outcome remains unknown after {reason}"
            ) from exc
        if response.status_code == 404:
            raise KnownSafeRetryError(
                f"Odoo proved the Klyrow projection is absent after {reason}"
            )
        if response.status_code == 200 and self._proved_response(response, projection):
            return
        raise KlyrowProjectionError(
            f"Odoo projection readback did not prove the outcome after {reason}"
        )

    async def dispatch(self, record: OutboxRecord) -> None:
        projection = self._projection(record)
        headers = self._headers(
            projection,
            method="POST",
            path=PROJECTION_PATH,
            body=projection.body,
        )
        headers["Content-Type"] = "application/json"
        try:
            response = await self.client.post(
                self.base_url.rstrip("/") + PROJECTION_PATH,
                content=projection.body,
                headers=headers,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise KnownSafeRetryError(
                "Odoo connection failed before the Klyrow projection was sent"
            ) from exc
        except httpx.RequestError as exc:
            await self._readback(projection, reason=type(exc).__name__)
            return

        if response.status_code in {200, 201, 202} and self._proved_response(
            response, projection
        ):
            return
        if response.status_code == 404:
            raise KnownSafeRetryError(
                "referenced Odoo business entity is not available yet"
            )
        if (
            response.status_code in {408, 409, 425, 429}
            or 500 <= response.status_code < 600
        ):
            await self._readback(
                projection,
                reason=f"HTTP {response.status_code}",
            )
            return
        raise KlyrowProjectionError(
            f"Odoo rejected Klyrow projection with status {response.status_code}"
        )
