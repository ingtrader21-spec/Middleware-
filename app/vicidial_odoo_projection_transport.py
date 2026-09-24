from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote

import httpx

from .vicidial_odoo_projection_config import _https_origin
from .vicidial_odoo_projection_errors import (
    DeterministicRejection,
    KnownNotDelivered,
    OutcomeUnknown,
    ProjectionConfigurationError,
)
from .vicidial_odoo_projection_models import (
    AMBIGUOUS_STATUSES,
    CALL_EVENT_PATH,
    CALL_EVENT_STATUS_PATH,
    OdooCallEvent,
    canonical_event_body,
    sign_call_event,
)

_TERMINAL_CONFLICTS = frozenset(
    {"event_identity_conflict", "lifecycle_conflict", "stale_sequence"}
)


@dataclass(slots=True)
class OdooCallEventDispatcher:
    client: httpx.AsyncClient
    base_url: str
    tenant_secrets: Mapping[str, bytes]
    default_secret: bytes | None = None

    def __post_init__(self) -> None:
        self.base_url = _https_origin(self.base_url)
        if not self.tenant_secrets and not self.default_secret:
            raise ProjectionConfigurationError("an Odoo call-event HMAC secret is required")

    def _secret(self, tenant_id: str) -> bytes:
        value = self.tenant_secrets.get(tenant_id) or self.default_secret
        if not value or len(value) < 32:
            raise ProjectionConfigurationError("no >=32-byte secret exists for tenant")
        return value

    def _headers(self, event: OdooCallEvent, *, method: str, path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        signature = sign_call_event(
            self._secret(event.tenant_id),
            timestamp=timestamp,
            event_id=event.event_id,
            method=method,
            path=path,
            tenant_id=event.tenant_id,
            correlation_id=event.correlation_id,
            body=body,
        )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Idempotency-Key": event.event_id,
            "X-Codestra-Timestamp": timestamp,
            "X-Codestra-Event-ID": event.event_id,
            "X-Codestra-Signature": f"sha256={signature}",
            "X-Tenant-ID": event.tenant_id,
            "X-Correlation-ID": event.correlation_id,
        }

    @staticmethod
    def _expected_identity(event: OdooCallEvent, *, recorded: bool) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "call_id": event.call_id,
            "event_type": event.event_type,
            "sequence": event.sequence,
            "recorded": recorded,
        }

    @classmethod
    def _verify_evidence(cls, value: Any, event: OdooCallEvent) -> None:
        if not isinstance(value, dict):
            raise OutcomeUnknown("Odoo call-event evidence is not an object")
        for key, expected_value in cls._expected_identity(event, recorded=True).items():
            if value.get(key) != expected_value:
                raise OutcomeUnknown(f"Odoo evidence mismatch for {key}")

    @classmethod
    def _classify_conflict(cls, value: Any, event: OdooCallEvent) -> None:
        if not isinstance(value, dict):
            raise OutcomeUnknown("Odoo conflict evidence is not an object")
        for key, expected_value in cls._expected_identity(event, recorded=False).items():
            if value.get(key) != expected_value:
                raise OutcomeUnknown(f"Odoo conflict evidence mismatch for {key}")
        error = value.get("error")
        retryable = value.get("retryable")
        if error == "sequence_gap" and retryable is True:
            expected_sequence = value.get("expected_sequence")
            current_sequence = value.get("current_sequence")
            if (
                isinstance(expected_sequence, bool)
                or not isinstance(expected_sequence, int)
                or isinstance(current_sequence, bool)
                or not isinstance(current_sequence, int)
                or expected_sequence != current_sequence + 1
                or expected_sequence >= event.sequence
            ):
                raise OutcomeUnknown("Odoo sequence-gap evidence is inconsistent")
            raise KnownNotDelivered(
                f"Odoo proved sequence {event.sequence} is waiting for {expected_sequence}"
            )
        if error in _TERMINAL_CONFLICTS and retryable is False:
            raise DeterministicRejection(
                f"Odoo rejected call event with terminal conflict {error}"
            )
        raise OutcomeUnknown("Odoo returned an unrecognized conflict contract")

    async def submit(self, event: OdooCallEvent) -> None:
        body = canonical_event_body(event)
        headers = self._headers(event, method="POST", path=CALL_EVENT_PATH, body=body)
        try:
            response = await self.client.post(
                self.base_url + CALL_EVENT_PATH,
                content=body,
                headers=headers,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            await self.reconcile(event, reason=type(exc).__name__)
            return
        if response.status_code in {200, 202}:
            try:
                self._verify_evidence(response.json(), event)
            except ValueError as exc:
                raise OutcomeUnknown("Odoo returned invalid evidence JSON") from exc
            return
        if response.status_code == 409:
            try:
                self._classify_conflict(response.json(), event)
            except ValueError as exc:
                raise OutcomeUnknown("Odoo returned invalid conflict JSON") from exc
            return
        if response.status_code in AMBIGUOUS_STATUSES:
            await self.reconcile(event, reason=f"HTTP {response.status_code}")
            return
        raise DeterministicRejection(
            f"Odoo rejected call event with status {response.status_code}"
        )

    async def reconcile(self, event: OdooCallEvent, *, reason: str) -> None:
        path = CALL_EVENT_STATUS_PATH.format(event_id=quote(event.event_id, safe=""))
        headers = self._headers(event, method="GET", path=path, body=b"")
        try:
            response = await self.client.get(
                self.base_url + path,
                headers=headers,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise OutcomeUnknown(
                f"call-event outcome unknown ({reason}); read-back unreachable"
            ) from exc
        if response.status_code == 200:
            try:
                self._verify_evidence(response.json(), event)
            except ValueError as exc:
                raise OutcomeUnknown("Odoo read-back returned invalid JSON") from exc
            return
        if response.status_code == 404:
            raise KnownNotDelivered(f"Odoo proved event was not recorded ({reason})")
        raise OutcomeUnknown(
            f"call-event outcome unknown ({reason}); read-back returned {response.status_code}"
        )
