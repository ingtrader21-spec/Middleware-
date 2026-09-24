"""The N8N workflow-executor adapter behind the kernel adapter contract.

N8N is only an executor: the kernel decides (policy, capability, safety,
idempotency, ledger) and this adapter carries one ``automation.workflow.*``
command through the existing fail-closed production transport in
:mod:`app.adapters.n8n.transport` — ``attest_target`` (short-lived exact
target identity proof), ``reserve_delivery`` (an immutable one-attempt
reservation committed before any network action) and ``submit_reserved``
(exactly one POST, redirects rejected, the accepted response bound to the
reservation). Nothing about that transport is rewritten here.

Outcome mapping follows the transport's own guarantees:

* a duplicate reservation whose delivery was already ACCEPTED is reported as
  ACCEPTED again (the effect happened once);
* pre-send refusals (gates disabled, reservation not RESERVED, payload hash
  mismatch, target not attested, no fresh attestation) are REJECTED — the
  kernel never retries them;
* a response the transport refused after the send (redirect, non-202,
  binding mismatch, unparsable body) is also REJECTED: the reservation is
  FAILED and a reservation is one attempt by design;
* a transport error raised around the send (connection lost, timeout) is
  UNKNOWN: the effect may have happened, so the kernel reconciles through
  ``readback``, which reads the durable reservation instead of re-sending.

N8N may not authorize business effects, change capability state, write
provider state or bypass Middleware into Odoo/provider systems: it receives
the approved workflow envelope and reports its result through the
inbox/ledger ingress.
"""

from __future__ import annotations

import logging
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.commands import CommandEnvelope, CommandOperation, CommandPolicy
from app.platform.adapter import (
    AdapterConfigurationError,
    AdapterContext,
    AdapterReadiness,
    AdapterResult,
    BaseAdapter,
    ErrorClass,
    Outcome,
    ReadbackResult,
    ReadbackStatus,
)

logger = logging.getLogger("codestra.platform.adapters.n8n")

N8N_TARGET = "n8n-automation"
N8N_CAPABILITY = "N8N_WORKFLOW_DISPATCH"
N8N_PREFIX = "automation.workflow."
SUBMIT = "automation.workflow.submit.v1"
# Reservation states of app.db.models.BroadEventDelivery, as the transport writes them.
_RESERVATION_OUTCOMES: dict[str, Outcome] = {
    "RESERVED": Outcome.UNKNOWN,  # committed, not yet sent: still pending
    "TARGET_ATTESTED": Outcome.UNKNOWN,
    "SUBMITTING": Outcome.UNKNOWN,
    "ACCEPTED": Outcome.ACCEPTED,
    "FAILED": Outcome.REJECTED,
}
_RESERVATION_READBACK: dict[str, ReadbackStatus] = {
    "RESERVED": ReadbackStatus.NOT_FOUND,  # never sent: safe to execute again
    "TARGET_ATTESTED": ReadbackStatus.UNAVAILABLE,
    "SUBMITTING": ReadbackStatus.UNAVAILABLE,
    "ACCEPTED": ReadbackStatus.MATCHED,
    "FAILED": ReadbackStatus.MISMATCH,
}
CANCELLED_ERROR_CLASS = "CANCELLED_BEFORE_SUBMIT"
REQUIRED_SETTINGS = (
    "n8n_production_target_url",
    "n8n_production_target_identity",
    "n8n_production_image_digest",
    "n8n_workflow_package_sha256",
    "middleware_n8n_token_url",
    "middleware_n8n_client_id",
    "middleware_n8n_client_secret_file",
    "middleware_n8n_audience",
    "middleware_n8n_scope",
)
REQUIRED_PAYLOAD = ("event_id", "workflow_id", "workflow_version", "policy_hash", "envelope")


def n8n_policy() -> CommandPolicy:
    """The kernel policy of the N8N executor family (capability off by default)."""
    return CommandPolicy(prefix=N8N_PREFIX, target=N8N_TARGET, capability=N8N_CAPABILITY, readback_required=True)


class N8nTransport(Protocol):
    """The transport entry points this adapter wraps (``app.adapters.n8n.transport``)."""

    async def reserve_delivery(self, session: AsyncSession, *, event: Any, workflow_id: str, workflow_version: str, policy_hash: str) -> tuple[Any, bool]: ...

    async def submit_reserved(self, session: AsyncSession, delivery_id: UUID, envelope: dict[str, Any], *, client: httpx.AsyncClient | None = None) -> dict[str, Any]: ...


def _transport_error_type() -> type[Exception]:
    from app.adapters.n8n.transport import N8nTransportError

    return N8nTransportError


def _default_transport() -> N8nTransport:
    from app.adapters.n8n import transport

    return transport  # type: ignore[return-value]


@dataclass
class N8nWorkflowAdapter(BaseAdapter):
    """Maps ``automation.workflow.submit.v1`` onto the reservation transport."""

    settings: Any = None
    session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]] | None = None
    transport: N8nTransport = field(default_factory=_default_transport)
    adapter_id: str = "n8n-automation"
    provider_family: str = "n8n"
    version: str = "v3/2.0"
    connector_ids: tuple[str, ...] = (N8N_TARGET,)
    served_capabilities: tuple[str, ...] = (N8N_CAPABILITY,)
    supports_cancel: bool = True
    supports_status: bool = True
    safe_reexecution: bool = False
    external_effect: bool = True

    # --- contract -----------------------------------------------------------------------
    def validate_config(self) -> None:
        BaseAdapter.validate_config(self)
        if self.settings is None or self.session_factory is None:
            raise AdapterConfigurationError("n8n adapter needs settings and the ORM session factory")
        missing = [key for key in REQUIRED_SETTINGS if not getattr(self.settings, key, None)]
        if missing:
            raise AdapterConfigurationError(f"n8n adapter is not configured: missing {missing}")
        if not getattr(self.settings, "broad_event_pipeline_enabled", False):
            raise AdapterConfigurationError("n8n adapter needs the canonical broad-event gates enabled")

    async def readiness(self, context: AdapterContext) -> AdapterReadiness:
        """Ready only while a fresh PASS attestation of the exact production target
        exists; health alone is never enough (the transport enforces the same rule)."""
        from app.db.models import N8nTargetAttestation

        assert self.session_factory is not None
        try:
            async with self.session_factory() as session:
                attestation = await session.scalar(
                    select(N8nTargetAttestation)
                    .where(
                        N8nTargetAttestation.target_identity == self.settings.n8n_production_target_identity,
                        N8nTargetAttestation.target_environment == "production",
                        N8nTargetAttestation.image_digest == self.settings.n8n_production_image_digest,
                        N8nTargetAttestation.result == "PASS",
                        N8nTargetAttestation.expires_at > datetime.now(UTC),
                    )
                    .order_by(N8nTargetAttestation.verified_at.desc())
                    .limit(1)
                )
        except Exception as exc:  # noqa: BLE001 - readiness must never raise into the kernel
            return AdapterReadiness(False, f"attestation lookup failed: {type(exc).__name__}")
        if attestation is None:
            return AdapterReadiness(False, "no fresh production target attestation")
        return AdapterReadiness(True, f"target attested until {attestation.expires_at.isoformat()}")

    async def execute(self, command: CommandEnvelope, context: AdapterContext) -> AdapterResult:
        if command.command_type != SUBMIT:
            return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="unsupported_command_type")
        missing = [key for key in REQUIRED_PAYLOAD if key not in command.payload]
        if missing:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="payload_incomplete", safe_details={"missing": ",".join(missing)})
        envelope = command.payload["envelope"]
        if not isinstance(envelope, dict) or "payload" not in envelope or "correlation_id" not in envelope or "event_id" not in envelope:
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="envelope_invalid")
        refused = _transport_error_type()
        assert self.session_factory is not None
        try:
            async with self.session_factory() as session:
                event = await self._load_event(session, command.payload["event_id"])
                if event is None:
                    return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code="event_not_found")
                delivery, duplicate = await self.transport.reserve_delivery(
                    session,
                    event=event,
                    workflow_id=str(command.payload["workflow_id"]),
                    workflow_version=str(command.payload["workflow_version"]),
                    policy_hash=str(command.payload["policy_hash"]),
                )
                if duplicate and delivery.status != "RESERVED":
                    # The one attempt already happened (or is in flight): report its state.
                    return self._from_delivery(delivery)
                accepted = await self.transport.submit_reserved(session, delivery.delivery_id, envelope, client=context.http)
        except refused as exc:
            # Pre-send refusals and post-send response refusals alike leave the
            # reservation consumed; the transport allows one attempt, nothing is retried.
            return AdapterResult(Outcome.REJECTED, error_class=ErrorClass.NON_RETRYABLE, safe_error_code=_error_code(exc))
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            logger.warning("n8n transport error around send: %s", type(exc).__name__)
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        except Exception as exc:  # noqa: BLE001 - outcome unknown; the kernel reconciles from the reservation
            logger.warning("n8n adapter raised %s", type(exc).__name__)
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        result = self.normalize_result(accepted)
        details = dict(result.safe_details)
        details.update({"delivery_id": str(delivery.delivery_id), "workflow_id": str(delivery.workflow_id), "workflow_version": str(delivery.workflow_version)})
        return AdapterResult(result.outcome, provider_operation_id=result.provider_operation_id, error_class=result.error_class, safe_error_code=result.safe_error_code, safe_details=details)

    async def status(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        delivery = await self._delivery_for(context)
        if delivery is None:
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="reservation_not_found")
        return self._from_delivery(delivery)

    async def readback(self, operation: CommandOperation, context: AdapterContext) -> ReadbackResult:
        """The durable reservation is the source of truth: it is read, never re-sent."""
        try:
            delivery = await self._delivery_for(context)
        except Exception as exc:  # noqa: BLE001 - still unknown; the kernel keeps the operation open
            return ReadbackResult(ReadbackStatus.UNAVAILABLE, safe_error_code=type(exc).__name__)
        if delivery is None:
            return ReadbackResult(ReadbackStatus.NOT_FOUND, safe_error_code="reservation_not_found")
        status = _RESERVATION_READBACK.get(str(delivery.status), ReadbackStatus.UNAVAILABLE)
        if delivery.error_class == CANCELLED_ERROR_CLASS:
            status = ReadbackStatus.MISMATCH
        return ReadbackResult(
            status,
            provider_operation_id=str(delivery.delivery_id),
            evidence={"reservation_status": str(delivery.status), "workflow_id": str(delivery.workflow_id), "workflow_version": str(delivery.workflow_version)},
            safe_error_code=None if status is ReadbackStatus.MATCHED else f"reservation_{str(delivery.status).lower()}",
        )

    async def cancel(self, operation: CommandOperation, context: AdapterContext) -> AdapterResult:
        """Only a reservation that was never sent can be cancelled; N8N exposes no cancel."""
        assert self.session_factory is not None
        try:
            async with self.session_factory() as session:
                delivery = await self._load_delivery(session, context.payload, for_update=True)
                if delivery is None or delivery.status != "RESERVED":
                    return AdapterResult(Outcome.UNSUPPORTED, error_class=ErrorClass.UNSUPPORTED, safe_error_code="cancel_unsupported_after_send")
                delivery.status = "FAILED"
                delivery.error_class = CANCELLED_ERROR_CLASS
                delivery.failed_at = datetime.now(UTC)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code=type(exc).__name__)
        return AdapterResult(Outcome.CANCELLED, safe_details={"delivery_id": str(delivery.delivery_id)})

    def normalize_result(self, raw: Any) -> AdapterResult:
        if isinstance(raw, AdapterResult):
            return raw
        if not isinstance(raw, Mapping) or not raw.get("registration_id"):
            return AdapterResult(Outcome.UNKNOWN, error_class=ErrorClass.AMBIGUOUS, safe_error_code="unnormalizable_result")
        details: dict[str, str | int | bool] = {}
        for key in ("delivery_id", "event_id", "workflow_id", "workflow_version"):
            if isinstance(raw.get(key), (str, int, bool)):
                details[key] = raw[key]
        return AdapterResult(Outcome.ACCEPTED, provider_operation_id=str(raw["registration_id"]), safe_details=details)

    # --- helpers --------------------------------------------------------------------------
    async def _delivery_for(self, context: AdapterContext) -> Any:
        assert self.session_factory is not None
        async with self.session_factory() as session:
            return await self._load_delivery(session, context.payload)

    async def _load_event(self, session: AsyncSession, event_id: Any) -> Any:
        from app.db.models import IntegrationEvent

        try:
            key = int(event_id)
        except (TypeError, ValueError):
            return None
        return await session.get(IntegrationEvent, key)

    async def _load_delivery(self, session: AsyncSession, payload: Mapping[str, Any], *, for_update: bool = False) -> Any:
        from app.db.models import BroadEventDelivery

        raw_event_id = payload.get("event_id")
        try:
            event_key = int(raw_event_id) if raw_event_id is not None else None
        except (TypeError, ValueError):
            return None
        if event_key is None:
            return None
        statement = select(BroadEventDelivery).where(
            BroadEventDelivery.event_id == event_key,
            BroadEventDelivery.workflow_id == str(payload.get("workflow_id")),
            BroadEventDelivery.workflow_version == str(payload.get("workflow_version")),
        )
        if for_update:
            statement = statement.with_for_update()
        return await session.scalar(statement.limit(1))

    def _from_delivery(self, delivery: Any) -> AdapterResult:
        outcome = _RESERVATION_OUTCOMES.get(str(delivery.status), Outcome.UNKNOWN)
        details: dict[str, str | int | bool] = {
            "delivery_id": str(delivery.delivery_id),
            "reservation_status": str(delivery.status),
            "workflow_id": str(delivery.workflow_id),
            "workflow_version": str(delivery.workflow_version),
        }
        if delivery.error_class:
            details["error_class"] = str(delivery.error_class)
        if delivery.error_class == CANCELLED_ERROR_CLASS:
            outcome = Outcome.CANCELLED
        return AdapterResult(
            outcome,
            provider_operation_id=str(delivery.delivery_id),
            error_class=None if outcome is Outcome.ACCEPTED else ErrorClass.AMBIGUOUS if outcome is Outcome.UNKNOWN else ErrorClass.NON_RETRYABLE,
            safe_error_code=None if outcome is Outcome.ACCEPTED else f"reservation_{str(delivery.error_class or delivery.status).lower()}",
            safe_details=details,
        )


def _error_code(exc: BaseException) -> str:
    text = str(exc).strip().lower().replace(" ", "_")
    return text[:64] or type(exc).__name__


def n8n_adapter(settings: Any, session_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]]) -> N8nWorkflowAdapter | None:
    """The production N8N adapter, registered only when its configuration validates."""
    adapter = N8nWorkflowAdapter(settings=settings, session_factory=session_factory)
    try:
        adapter.validate_config()
    except AdapterConfigurationError as exc:
        logger.info("n8n adapter not registered: %s", exc)
        return None
    return adapter
