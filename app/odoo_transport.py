"""Odoo 19 CRM lead delivery adapter.

The Odoo bridge authenticates each command with an HMAC-SHA256 signature over a
canonical string that includes the security headers, and records the outcome of
every command against a tenant-scoped idempotency key. This adapter is the
Middleware side of that contract.

Outcome discipline, which the outbox worker depends on:

* returning normally asserts that the command was delivered and its outcome
  observed;
* raising :class:`~app.worker.KnownSafeRetryError` asserts that no Odoo write
  can have committed, so an automatic retry is safe;
* raising anything else leaves the row quarantined as an unknown outcome for
  operator reconciliation.

A timeout is never treated as a failure. It is an unknown outcome, and it is
resolved by reading the command back before any retry is permitted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Callable

import httpx

from .commands import ODOO_COMMAND_DESTINATION, CommandEnvelope
from .storage import OutboxRecord
from .worker import KnownSafeRetryError

UPSERT_PATH = "/codestra/middleware/v1/commands/crm.lead.upsert"
STATUS_PATH_TEMPLATE = "/codestra/middleware/v1/commands/{command_id}/status"

SUPPORTED_TARGET = "odoo-19"
SUPPORTED_COMMAND_TYPE = "crm.lead.upsert"
SUPPORTED_CAPABILITY = "ODOO_WRITE"

# Gateway-level statuses do not prove whether Odoo itself saw the command.
AMBIGUOUS_STATUSES = frozenset({502, 503, 504})


class OdooTransportError(RuntimeError):
    """Raised when an Odoo outcome is rejected or cannot be confirmed."""


class OdooConfigurationError(RuntimeError):
    """Raised when the adapter is asked to run without its required controls."""


def canonical_signing_string(
    *,
    timestamp: str,
    event_id: str,
    method: str,
    path: str,
    tenant_id: str,
    correlation_id: str,
    idempotency_key: str,
    body: bytes,
) -> bytes:
    """Build the exact byte string the Odoo bridge signs.

    The security headers are inside the signature deliberately: without them a
    valid signature over a body could be replayed with swapped identity headers.
    """
    return b"\n".join(
        (
            timestamp.encode("utf-8"),
            event_id.encode("utf-8"),
            method.encode("utf-8"),
            path.encode("utf-8"),
            tenant_id.encode("utf-8"),
            correlation_id.encode("utf-8"),
            idempotency_key.encode("utf-8"),
            body,
        )
    )


def sign(secret: bytes, canonical: bytes) -> str:
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def serialize_command(command: CommandEnvelope) -> bytes:
    """Serialize the envelope exactly once, so the signed bytes are the sent bytes."""
    return json.dumps(
        command.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(slots=True)
class OdooCommandDispatcher:
    client: httpx.AsyncClient
    base_url: str
    secrets: dict[str, bytes]
    source_delivery_enabled: Callable[[str], bool]
    default_secret: bytes | None = None

    def __post_init__(self) -> None:
        if not self.base_url.startswith("https://"):
            raise OdooConfigurationError("Odoo base URL must be HTTPS")
        if not self.secrets and not self.default_secret:
            raise OdooConfigurationError("no Odoo signing secret is configured")

    def _secret_for(self, tenant_id: str) -> bytes:
        secret = self.secrets.get(tenant_id) or self.default_secret
        if not secret:
            raise OdooConfigurationError(
                f"no Odoo signing secret is configured for tenant {tenant_id}"
            )
        return secret

    def _headers(
        self,
        *,
        method: str,
        path: str,
        command: CommandEnvelope,
        body: bytes,
        event_id: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> dict[str, str]:
        timestamp = str(int(time.time()))
        canonical = canonical_signing_string(
            timestamp=timestamp,
            event_id=event_id,
            method=method,
            path=path,
            tenant_id=command.tenant_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            body=body,
        )
        signature = sign(self._secret_for(command.tenant_id), canonical)
        return {
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Event-ID": event_id,
            "X-Codestra-Signature": f"sha256={signature}",
            "X-Tenant-ID": command.tenant_id,
            "X-Correlation-ID": correlation_id,
            "Idempotency-Key": idempotency_key,
        }

    @staticmethod
    def _validate(record: OutboxRecord) -> CommandEnvelope:
        if record.destination != ODOO_COMMAND_DESTINATION:
            raise OdooTransportError(
                "outbox row targets an unsupported Odoo destination"
            )
        try:
            command = CommandEnvelope.model_validate(record.payload)
        except Exception as exc:
            raise OdooTransportError(
                "outbox command does not match the canonical command envelope"
            ) from exc
        if command.tenant_id != record.tenant_id:
            raise OdooTransportError(
                "outbox tenant does not match the command envelope"
            )
        if command.command_type != record.event_type:
            raise OdooTransportError(
                "outbox event type does not match the command type"
            )
        if command.idempotency_key != record.idempotency_key:
            raise OdooTransportError(
                "outbox idempotency key does not match the command envelope"
            )
        if (
            command.target != SUPPORTED_TARGET
            or command.command_type != SUPPORTED_COMMAND_TYPE
            or command.capability != SUPPORTED_CAPABILITY
        ):
            raise OdooTransportError(
                "outbox command is not a supported Odoo 19 lead upsert"
            )
        return command

    async def dispatch(self, record: OutboxRecord) -> None:
        command = self._validate(record)
        provenance = command.payload.get("provenance")
        provenance_method = provenance.get("method") if isinstance(provenance, dict) else None
        if not isinstance(provenance_method, str) or not self.source_delivery_enabled(provenance_method):
            raise OdooConfigurationError(
                "Odoo source-scoped delivery is disabled for this lead source"
            )
        body = serialize_command(command)
        headers = self._headers(
            method="POST",
            path=UPSERT_PATH,
            command=command,
            body=body,
            event_id=str(command.command_id),
            correlation_id=command.correlation_id,
            idempotency_key=command.idempotency_key,
        )
        headers["Content-Type"] = "application/json"
        try:
            response = await self.client.post(
                self.base_url.rstrip("/") + UPSERT_PATH,
                content=body,
                headers=headers,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # The connection was never established, so no Odoo write can exist.
            raise KnownSafeRetryError(
                "Odoo connection failed before the request was sent"
            ) from exc
        except httpx.RequestError as exc:
            # The request may have been received and applied. Read it back.
            await self._reconcile(command, reason=str(exc))
            return
        await self._interpret(command, response)

    async def _interpret(
        self, command: CommandEnvelope, response: httpx.Response
    ) -> None:
        if response.status_code in (200, 201):
            return
        if response.status_code in AMBIGUOUS_STATUSES:
            await self._reconcile(
                command, reason=f"gateway status {response.status_code}"
            )
            return
        raise OdooTransportError(
            "Odoo rejected the command with status "
            f"{response.status_code}: {self._error_code(response)}"
        )

    @staticmethod
    def _error_code(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return "unparseable-response"
        if isinstance(body, dict) and isinstance(body.get("error"), str):
            return body["error"]
        return "unspecified"

    async def _reconcile(self, command: CommandEnvelope, *, reason: str) -> None:
        """Resolve an unknown outcome by reading the command back.

        Returns normally only when Odoo confirms it recorded the command. Only a
        proven non-delivery is downgraded to a safe retry; anything else stays
        quarantined.
        """
        path = STATUS_PATH_TEMPLATE.format(command_id=command.command_id)
        event_id = str(uuid.uuid4())
        headers = self._headers(
            method="GET",
            path=path,
            command=command,
            body=b"",
            event_id=event_id,
            correlation_id=f"reconcile-{event_id}",
            idempotency_key=f"reconcile-{event_id}",
        )
        try:
            response = await self.client.get(
                self.base_url.rstrip("/") + path, headers=headers
            )
        except httpx.RequestError as exc:
            raise OdooTransportError(
                f"Odoo outcome unknown ({reason}) and reconciliation is unreachable"
            ) from exc
        if response.status_code == 200:
            return
        if response.status_code == 404:
            raise KnownSafeRetryError(
                f"reconciliation proved Odoo never recorded the command ({reason})"
            )
        raise OdooTransportError(
            f"Odoo outcome unknown ({reason}); reconciliation returned "
            f"{response.status_code}"
        )
