"""Odoo campaign-control saga: outbox event -> adapter -> actual-state readback.

Every accepted Odoo outbox event whose type is on the catalog allowlist gets
exactly one ``odoo_campaign_saga`` row (enforced by the unique constraint on
``integration_event_id``). A worker claims a saga with a lease, verifies the
command is not stale against Odoo's desired state, runs the adapter, and
reports the observed actual state back to Odoo with a durable idempotency
key. Middleware never holds the campaign-control write scope; the only write
is ``campaign.actual_state.write``.

``attempts`` counts dispatches and is incremented only by :func:`claim_saga`.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
)
from sqlalchemy import Select, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.odoo.campaign_control import (
    STALE_CONFIGURATION_VERSION,
    ActualStateReadback,
    CampaignOperation,
    DesiredState,
    EffectiveState,
    OdooCampaignAdapterError,
    OdooCampaignAdapterUnavailable,
    OdooCampaignStaleVersion,
    load_catalog,
    read_desired_state,
    report_actual_state,
)
from app.adapters.odoo.client import OdooDeliveryClient
from app.adapters.odoo.results import OdooServiceClient, _build_odoo_client
from app.core.automation import canonical_hash
from app.core.config import settings
from app.core.endpoint_registry import RegistryDependencyUnavailable, ResolutionDenied
from app.db.models import AuditEvent, IntegrationEvent, OdooCampaignSaga

logger = logging.getLogger("codestra.odoo_campaign_saga")

_CATALOG = load_catalog()
ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(_CATALOG["outbox_events"]["allowlist"])
OPERATION_BY_EVENT_TYPE: dict[str, CampaignOperation] = TypeAdapter(
    dict[str, CampaignOperation]
).validate_python(_CATALOG["outbox_events"]["operation_by_event_type"])
RESULT_STATE_BY_OPERATION: dict[str, EffectiveState | None] = TypeAdapter(
    dict[str, EffectiveState | None]
).validate_python(_CATALOG["synthetic_adapter_result_state"])

# Per-environment write binding from the catalog (None = unscoped). In an
# environment with a binding, events for any other scope triple are
# dead-lettered at enrollment: no Odoo read, no adapter, no readback.
WRITE_BINDING_BY_ENVIRONMENT: dict[str, tuple[str, str, str] | None] = {
    environment: (
        (
            policy["write_binding"]["organization_public_id"],
            policy["write_binding"]["business_unit_public_id"],
            policy["write_binding"]["campaign_public_id"],
        )
        if policy.get("write_binding")
        else None
    )
    for environment, policy in _CATALOG["registry_policy_0066"].items()
}

OUTBOX_SOURCE_SYSTEM = "odoo"
CLAIMABLE_STATUSES = ("PENDING", "RETRY")
# Retryable dependency failures. A saga whose last failure is one of these and
# that already holds an observation resends the same readback (same key, same
# attempt) instead of observing again.
TRANSPORT_RETRY_ERROR_CLASSES = frozenset(
    {"ODOO_TRANSPORT_ERROR", "ODOO_UPSTREAM_UNAVAILABLE", "ODOO_ROUTE_UNRESOLVED"}
)
# Two Odoo calls per dispatch (desired-state read, readback) at the registry's
# 10 s request + 3 s connect timeout each, plus a margin.
MINIMUM_LEASE_SECONDS = 2 * (10 + 3) + 15
SYNTHETIC_ADAPTER = "synthetic"
# Odoo answering with an error, and the dependency faults around the call.
_DEPENDENCY_ERRORS = (
    OdooCampaignAdapterError,
    httpx.TransportError,
    ResolutionDenied,
    RegistryDependencyUnavailable,
)


class SagaError(RuntimeError):
    pass


class SagaConfigurationError(SagaError):
    """The saga worker is misconfigured; fail closed before any dispatch."""


class CampaignControlEvent(BaseModel):
    """Payload of an allowlisted Odoo outbox event (``IntegrationEvent.payload_json``)."""

    model_config = ConfigDict(extra="ignore")

    command_id: str = Field(min_length=1, max_length=128)
    organization_public_id: str = Field(min_length=1, max_length=128)
    business_unit_public_id: str = Field(min_length=1, max_length=128)
    campaign_public_id: str = Field(min_length=1, max_length=128)
    configuration_version: int = Field(ge=0)
    manifest_ref: str = Field(min_length=1, max_length=256)
    manifest_hash: str = Field(min_length=1, max_length=80)


class AdapterObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    effective_state: EffectiveState
    evidence: dict[str, Any]
    observed_at: AwareDatetime


class CampaignAdapter(Protocol):
    async def apply(
        self, saga: OdooCampaignSaga, desired: DesiredState
    ) -> AdapterObservation: ...


class SyntheticCampaignAdapter:
    """Observes the catalog's synthetic result state; never contacts a provider."""

    async def apply(
        self, saga: OdooCampaignSaga, desired: DesiredState
    ) -> AdapterObservation:
        if saga.operation not in RESULT_STATE_BY_OPERATION:
            raise SagaError(f"unsupported campaign operation {saga.operation!r}")
        state = RESULT_STATE_BY_OPERATION[saga.operation]
        if state is None:
            # reconcile: the observed state is whatever Odoo currently desires.
            state = desired.desired_state
        return AdapterObservation(
            effective_state=state,
            evidence={
                "adapter": SYNTHETIC_ADAPTER,
                "operation": saga.operation,
                "manifest_ref": saga.manifest_ref,
                "manifest_hash": saga.manifest_hash,
                "configuration_version": saga.configuration_version,
                "provider_writes": "disabled",
            },
            observed_at=datetime.now(UTC),
        )


def adapter_for(config: Any = settings) -> SyntheticCampaignAdapter:
    if config.odoo_campaign_saga_adapter != SYNTHETIC_ADAPTER:
        raise SagaConfigurationError(
            "odoo_campaign_saga_adapter must be 'synthetic'; no provider adapter exists"
        )
    return SyntheticCampaignAdapter()


def validate_worker_settings(config: Any = settings) -> None:
    if config.odoo_campaign_saga_lease_seconds < MINIMUM_LEASE_SECONDS:
        raise SagaConfigurationError(
            f"odoo_campaign_saga_lease_seconds must be >= {MINIMUM_LEASE_SECONDS}"
        )
    if config.odoo_campaign_saga_retry_limit < 1:
        raise SagaConfigurationError("odoo_campaign_saga_retry_limit must be >= 1")
    adapter_for(config)


def pending_events_statement(limit: int) -> Select[tuple[IntegrationEvent]]:
    """Accepted, allowlisted Odoo outbox events with no saga row yet."""
    enrolled = (
        select(OdooCampaignSaga.saga_id)
        .where(OdooCampaignSaga.integration_event_id == IntegrationEvent.id)
        .exists()
    )
    return (
        select(IntegrationEvent)
        .where(
            IntegrationEvent.source_system == OUTBOX_SOURCE_SYSTEM,
            IntegrationEvent.event_type.in_(sorted(ALLOWED_EVENT_TYPES)),
            IntegrationEvent.state == "accepted",
            ~enrolled,
        )
        .order_by(IntegrationEvent.id)
        .limit(limit)
    )


def claimable_saga_statement(
    now: datetime | None = None,
) -> Select[tuple[OdooCampaignSaga]]:
    now = now or datetime.now(UTC)
    return (
        select(OdooCampaignSaga)
        .where(
            OdooCampaignSaga.status.in_(CLAIMABLE_STATUSES),
            (OdooCampaignSaga.next_attempt_at.is_(None))
            | (OdooCampaignSaga.next_attempt_at <= now),
        )
        .order_by(OdooCampaignSaga.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )


def saga_for_event(event: IntegrationEvent) -> OdooCampaignSaga:
    """Build the one saga row for an allowlisted event; invalid payloads dead-letter."""
    operation = OPERATION_BY_EVENT_TYPE.get(event.event_type)
    if operation is None:
        raise SagaError(f"event type {event.event_type!r} is not allowlisted")
    identity = {
        "integration_event_id": event.id,
        "event_uuid": event.original_event_id,
        "event_type": event.event_type,
        "operation": operation,
        "correlation_id": event.correlation_id,
        "attempts": 0,
    }
    try:
        control = CampaignControlEvent.model_validate(event.payload_json)
    except ValidationError:
        raw = event.payload_json if isinstance(event.payload_json, dict) else {}
        return OdooCampaignSaga(
            **identity,
            command_id=_text(raw, "command_id", 128),
            organization_public_id=_text(raw, "organization_public_id", 128),
            business_unit_public_id=_text(raw, "business_unit_public_id", 128),
            campaign_public_id=_text(raw, "campaign_public_id", 128),
            configuration_version=_version(raw),
            manifest_ref=_text(raw, "manifest_ref", 256),
            manifest_hash=_text(raw, "manifest_hash", 80),
            status="DEAD_LETTER",
            last_error_class="INVALID_CONTROL_EVENT",
        )
    binding = WRITE_BINDING_BY_ENVIRONMENT.get(settings.environment)
    scope = (
        control.organization_public_id,
        control.business_unit_public_id,
        control.campaign_public_id,
    )
    allowed = binding is None or scope == binding
    return OdooCampaignSaga(
        **identity,
        command_id=control.command_id,
        organization_public_id=control.organization_public_id,
        business_unit_public_id=control.business_unit_public_id,
        campaign_public_id=control.campaign_public_id,
        configuration_version=control.configuration_version,
        manifest_ref=control.manifest_ref,
        manifest_hash=control.manifest_hash,
        status="PENDING" if allowed else "DEAD_LETTER",
        last_error_class=None if allowed else "SCOPE_NOT_ALLOWED",
    )


async def enroll_pending_sagas(session: AsyncSession, *, limit: int = 50) -> int:
    """Insert one saga per unenrolled event; return the number of rows inserted."""
    events = (await session.scalars(pending_events_statement(limit))).all()
    # Build every row before the first commit: a rollback expires loaded events
    # and re-reading them would require implicit IO.
    rows = [saga_for_event(event) for event in events]
    enrolled = 0
    for saga in rows:
        session.add(saga)
        session.add(
            AuditEvent(
                action="odoo.campaign_saga.enrolled",
                subject=saga.event_uuid,
                correlation_id=saga.correlation_id,
                decision=saga.status,
                redacted_payload={
                    "event_type": saga.event_type,
                    "operation": saga.operation,
                    "campaign_public_id": saga.campaign_public_id,
                    "configuration_version": saga.configuration_version,
                    "error_class": saga.last_error_class,
                },
            )
        )
        try:
            await session.commit()
        except IntegrityError:
            # Another worker inserted this event's saga first
            # (uq_odoo_campaign_saga_event).
            await session.rollback()
            continue
        enrolled += 1
    return enrolled


async def claim_saga(
    session: AsyncSession, *, lease_seconds: int
) -> OdooCampaignSaga | None:
    if lease_seconds < 1:
        raise ValueError("lease_seconds must be positive")
    now = datetime.now(UTC)
    saga = await session.scalar(claimable_saga_statement(now))
    if saga is None:
        return None
    saga.status = "RESERVED"
    saga.attempts += 1
    saga.reserved_at = now
    saga.lease_expires_at = now + timedelta(seconds=lease_seconds)
    saga.next_attempt_at = None
    saga.updated_at = now
    await session.commit()
    return saga


async def recover_expired_leases(session: AsyncSession, *, retry_limit: int) -> int:
    """Release expired reservations without counting a new dispatch."""
    if retry_limit < 1:
        raise ValueError("retry_limit must be positive")
    now = datetime.now(UTC)
    expired = update(OdooCampaignSaga).where(
        OdooCampaignSaga.status == "RESERVED",
        OdooCampaignSaga.lease_expires_at <= now,
    )
    released = {
        "reserved_at": None,
        "lease_expires_at": None,
        "updated_at": now,
    }
    dead = await session.execute(
        expired.where(OdooCampaignSaga.attempts >= retry_limit)
        .values(
            status="DEAD_LETTER",
            next_attempt_at=None,
            last_error_class="LEASE_EXPIRED",
            **released,
        )
        .execution_options(synchronize_session="fetch")
    )
    retried = await session.execute(
        expired.where(OdooCampaignSaga.attempts < retry_limit)
        .values(
            status="RETRY",
            next_attempt_at=now,
            last_error_class="LEASE_EXPIRED_RECOVERED",
            **released,
        )
        .execution_options(synchronize_session="fetch")
    )
    await session.commit()
    return int(dead.rowcount or 0) + int(retried.rowcount or 0)


async def process_saga(
    session: AsyncSession,
    saga_id: UUID,
    *,
    client: OdooServiceClient | None = None,
    adapter: CampaignAdapter | None = None,
) -> dict[str, Any]:
    """Dispatch one RESERVED saga. Never increments ``attempts``."""
    # populate_existing: the worker reuses one session across claim and
    # dispatch, so the identity map would otherwise hand back the in-memory
    # RESERVED copy without ever reading the row lease recovery may have
    # changed. attempts + reserved_at loaded here identify this claim; every
    # later write is conditional on them (see _guarded_update).
    saga = await session.get(
        OdooCampaignSaga, saga_id, with_for_update=True, populate_existing=True
    )
    if saga is None or saga.status != "RESERVED":
        raise SagaError("saga is not reserved")
    scope = {
        "organization_public_id": saga.organization_public_id,
        "business_unit_public_id": saga.business_unit_public_id,
        "campaign_public_id": saga.campaign_public_id,
    }
    campaign_adapter = adapter or adapter_for(settings)
    owns_client = client is None
    # campaign_control is typed on the concrete client; the protocol is
    # structurally sufficient for everything it calls.
    service_client = cast(
        OdooDeliveryClient, client or _build_odoo_client(session, scope)
    )
    try:
        return await _dispatch(session, saga, scope, service_client, campaign_adapter)
    finally:
        if owns_client:
            await service_client.aclose()


async def _dispatch(
    session: AsyncSession,
    saga: OdooCampaignSaga,
    scope: dict[str, str],
    client: OdooDeliveryClient,
    adapter: CampaignAdapter,
) -> dict[str, Any]:
    # Stale-command protection precedes every adapter call.
    try:
        desired = DesiredState.model_validate(
            await read_desired_state(
                client,
                scope,
                request_id=f"REQ-{uuid4()}",
                correlation_id=saga.correlation_id,
                traceparent=_traceparent(saga.correlation_id, scope),
            )
        )
    except _DEPENDENCY_ERRORS as exc:
        return await _fail(session, saga, exc, rejected_class="DESIRED_STATE_REJECTED")
    except ValidationError:
        return await _terminate(session, saga, "DEAD_LETTER", "DESIRED_STATE_REJECTED")
    if desired.campaign_public_id != saga.campaign_public_id:
        return await _terminate(session, saga, "DEAD_LETTER", "DESIRED_STATE_REJECTED")
    if saga.configuration_version < desired.configuration_version:
        return await _terminate(session, saga, "DEAD_LETTER", STALE_CONFIGURATION_VERSION)
    if (
        saga.configuration_version > desired.configuration_version
        or saga.manifest_hash != desired.manifest_hash
    ):
        return await _terminate(
            session, saga, "DEAD_LETTER", "CONFIGURATION_VERSION_MISMATCH"
        )
    now = datetime.now(UTC)
    # Renewal is conditional on still owning the reservation: if lease recovery
    # already re-queued this saga, abort before any adapter side effect.
    await _guarded_update(
        session,
        saga,
        lease_expires_at=now + timedelta(seconds=settings.odoo_campaign_saga_lease_seconds),
        updated_at=now,
    )

    if not _has_reusable_observation(saga):
        observation = await adapter.apply(saga, desired)
        # The key must be durable (and ours) before the request that carries it.
        await _guarded_update(
            session,
            saga,
            effective_state=observation.effective_state,
            evidence_json=observation.evidence,
            observed_at=observation.observed_at,
            readback_idempotency_key=f"actual-state:{saga.event_uuid}:{uuid4()}",
            readback_attempt=saga.attempts,
            updated_at=datetime.now(UTC),
        )

    readback = ActualStateReadback.model_validate(
        {
            "event_uuid": saga.event_uuid,
            "command_id": saga.command_id,
            "idempotency_key": saga.readback_idempotency_key,
            "attempt": saga.readback_attempt,
            "organization_public_id": saga.organization_public_id,
            "business_unit_public_id": saga.business_unit_public_id,
            "campaign_public_id": saga.campaign_public_id,
            "configuration_version": saga.configuration_version,
            "operation": saga.operation,
            "effective_state": saga.effective_state,
            "manifest_ref": saga.manifest_ref,
            "manifest_hash": saga.manifest_hash,
            "evidence": saga.evidence_json or {},
            "observed_at": saga.observed_at,
            "correlation_id": saga.correlation_id,
            "causation_id": saga.event_uuid,
        }
    )
    try:
        body = await report_actual_state(
            client,
            readback,
            request_id=f"REQ-{uuid4()}",
            traceparent=_traceparent(
                saga.correlation_id, {"idempotency_key": readback.idempotency_key}
            ),
        )
    except _DEPENDENCY_ERRORS as exc:
        return await _fail(session, saga, exc, rejected_class="READBACK_REJECTED")
    return await _terminate(
        session, saga, "COMPLETED", None, readback_id=str(body["readback_id"])
    )


async def _fail(
    session: AsyncSession,
    saga: OdooCampaignSaga,
    exc: BaseException,
    *,
    rejected_class: str,
) -> dict[str, Any]:
    if isinstance(exc, OdooCampaignStaleVersion):
        # Odoo already moved past this configuration version: never retried.
        return await _terminate(session, saga, "DEAD_LETTER", STALE_CONFIGURATION_VERSION)
    retryable = _retryable_error_class(exc)
    if retryable is not None:
        return await _retry_or_dead_letter(session, saga, retryable)
    return await _terminate(session, saga, "DEAD_LETTER", rejected_class)


def _has_reusable_observation(saga: OdooCampaignSaga) -> bool:
    return bool(
        saga.readback_idempotency_key
        and saga.effective_state
        and saga.observed_at
        and saga.last_error_class in TRANSPORT_RETRY_ERROR_CLASSES
    )


def _retryable_error_class(exc: BaseException) -> str | None:
    if isinstance(exc, OdooCampaignAdapterUnavailable):
        return "ODOO_UPSTREAM_UNAVAILABLE"
    if isinstance(exc, httpx.TransportError):
        return "ODOO_TRANSPORT_ERROR"
    if isinstance(exc, (ResolutionDenied, RegistryDependencyUnavailable)):
        return "ODOO_ROUTE_UNRESOLVED"
    return None


async def _retry_or_dead_letter(
    session: AsyncSession, saga: OdooCampaignSaga, error_class: str
) -> dict[str, Any]:
    if saga.attempts >= settings.odoo_campaign_saga_retry_limit:
        return await _terminate(session, saga, "DEAD_LETTER", error_class)
    delay = timedelta(seconds=5 * 2 ** (saga.attempts - 1))
    return await _terminate(
        session, saga, "RETRY", error_class, next_attempt_at=datetime.now(UTC) + delay
    )


async def _terminate(
    session: AsyncSession,
    saga: OdooCampaignSaga,
    status: str,
    error_class: str | None,
    *,
    next_attempt_at: datetime | None = None,
    readback_id: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "status": status,
        "last_error_class": error_class,
        "reserved_at": None,
        "lease_expires_at": None,
        "next_attempt_at": next_attempt_at,
        "updated_at": now,
    }
    if status == "COMPLETED":
        values["readback_id"] = readback_id
        values["completed_at"] = now
    outcome = _outcome(status, error_class)
    session.add(
        AuditEvent(
            action=f"odoo.campaign_saga.{outcome}",
            subject=saga.event_uuid,
            correlation_id=saga.correlation_id,
            decision=status,
            redacted_payload={
                "command_id": saga.command_id,
                "operation": saga.operation,
                "campaign_public_id": saga.campaign_public_id,
                "configuration_version": saga.configuration_version,
                "attempt": saga.attempts,
                "error_class": error_class,
                "effective_state": saga.effective_state,
                "readback_id": readback_id,
            },
        )
    )
    # Conditional on still owning the reservation, so a worker whose lease
    # expired cannot overwrite the claim another worker now holds.
    await _guarded_update(session, saga, **values)
    logger.info(
        "odoo_campaign_saga_transition",
        extra={"correlation_id": saga.correlation_id, "result": outcome},
    )
    return {"outcome": outcome, "error_class": error_class}


async def _guarded_update(
    session: AsyncSession, saga: OdooCampaignSaga, **values: Any
) -> None:
    """Write only if the row is still RESERVED by this claim; commit; mirror in memory.

    The claim is identified by (attempts, reserved_at) as loaded at dispatch
    start. A raced lease recovery or a second worker's claim changes one of
    them, so the UPDATE matches nothing and the caller must stop.
    """
    result = await session.execute(
        update(OdooCampaignSaga)
        .where(
            OdooCampaignSaga.saga_id == saga.saga_id,
            OdooCampaignSaga.status == "RESERVED",
            OdooCampaignSaga.attempts == saga.attempts,
            OdooCampaignSaga.reserved_at == saga.reserved_at,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        await session.rollback()
        raise SagaError("saga reservation was lost")
    await session.commit()
    for key, value in values.items():
        setattr(saga, key, value)


def _outcome(status: str, error_class: str | None) -> str:
    if status == "COMPLETED":
        return "completed"
    if status == "RETRY":
        return "retry"
    if error_class == STALE_CONFIGURATION_VERSION:
        return "stale"
    return "dead_letter"


def _traceparent(correlation_id: str, span_source: dict[str, Any]) -> str:
    trace_id = canonical_hash({"correlation_id": correlation_id})[:32]
    span_id = canonical_hash(span_source)[:16]
    return f"00-{trace_id}-{span_id}-01"


def _text(payload: dict[str, Any], field: str, limit: int) -> str:
    value = payload.get(field)
    return "" if value is None else str(value)[:limit]


def _version(payload: dict[str, Any]) -> int:
    value = payload.get("configuration_version")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0
