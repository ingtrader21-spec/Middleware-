"""Durable claim/dispatch/readback/finalize telephony command worker."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

import httpx
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.telephony.client import (
    TelephonyClientError,
    TelephonyReadbackPending,
)
from app.core.telephony_commands import (
    TelephonyCommandRequest,
    TelephonyCommandState,
    payload_hash,
)
from app.db.models import (
    PolicyDecision,
    TelephonyCommandJournal,
    TelephonyOperationJournal,
)

LEASE_SECONDS = 120
HEARTBEAT_SECONDS = 20
MAX_ATTEMPTS = 8


class TelephonyDispatcher(Protocol):
    async def dispatch(
        self, command_id: str, command: TelephonyCommandRequest, *, traceparent: str
    ) -> dict[str, Any]: ...

    async def readback(
        self,
        command: TelephonyCommandRequest,
        operation: dict[str, Any],
        *,
        traceparent: str,
    ) -> dict[str, Any]: ...


async def claim_authorized(
    session: AsyncSession, *, environment: str
) -> tuple[UUID, str] | None:
    now = datetime.now(UTC)
    row = await session.scalar(
        select(TelephonyCommandJournal)
        .where(
            TelephonyCommandJournal.environment == environment,
            or_(
                and_(
                    TelephonyCommandJournal.state.in_(
                        (
                            TelephonyCommandState.AUTHORIZED.value,
                            TelephonyCommandState.FAILED_TRANSIENT.value,
                            TelephonyCommandState.READBACK_PENDING.value,
                        )
                    ),
                    or_(
                        TelephonyCommandJournal.next_attempt_at.is_(None),
                        TelephonyCommandJournal.next_attempt_at <= now,
                    ),
                ),
                and_(
                    TelephonyCommandJournal.state
                    == TelephonyCommandState.SUBMITTING.value,
                    TelephonyCommandJournal.next_attempt_at <= now,
                ),
            ),
        )
        .order_by(TelephonyCommandJournal.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if row is None:
        return None
    owner = uuid4().hex
    row.state = TelephonyCommandState.SUBMITTING.value
    row.attempt_count += 1
    row.lease_owner = owner
    row.next_attempt_at = now + timedelta(seconds=LEASE_SECONDS)
    row.updated_at = now
    command_id = row.command_id
    await session.commit()
    return command_id, owner


async def _renew_lease(
    session_factory: async_sessionmaker[AsyncSession],
    command_id: UUID,
    owner: str,
) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_SECONDS)
        async with session_factory() as session:
            row = await session.get(
                TelephonyCommandJournal, command_id, with_for_update=True
            )
            if (
                row is None
                or row.state != TelephonyCommandState.SUBMITTING.value
                or row.lease_owner != owner
            ):
                return
            row.next_attempt_at = datetime.now(UTC) + timedelta(seconds=LEASE_SECONDS)
            row.updated_at = datetime.now(UTC)
            await session.commit()


async def _run_while_lease(
    operation: Awaitable[dict[str, Any]], heartbeat: asyncio.Task[None]
) -> dict[str, Any]:
    """Abort external work if durable lease renewal stops or fails."""
    operation_task: asyncio.Future[dict[str, Any]] = asyncio.ensure_future(operation)

    async def lease_guard() -> dict[str, Any]:
        try:
            await asyncio.shield(heartbeat)
        except asyncio.CancelledError:
            if heartbeat.cancelled():
                raise RuntimeError(
                    "telephony command lease renewal was cancelled"
                ) from None
            raise
        raise RuntimeError("telephony command lease renewal stopped")

    guard_task = asyncio.create_task(lease_guard())
    done, _ = await asyncio.wait(
        {operation_task, guard_task}, return_when=asyncio.FIRST_COMPLETED
    )
    if operation_task in done:
        guard_task.cancel()
        with suppress(asyncio.CancelledError):
            await guard_task
        return operation_task.result()
    operation_task.cancel()
    with suppress(asyncio.CancelledError):
        await operation_task
    return guard_task.result()


def _permanent(exc: Exception) -> bool:
    if isinstance(exc, TelephonyReadbackPending):
        return False
    if isinstance(exc, TelephonyClientError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return 400 <= status < 500 and status not in {408, 409, 425, 429}
    return False


def _validate_policy_for_dispatch(
    command: TelephonyCommandRequest, decision: PolicyDecision | None
) -> None:
    if decision is None:
        raise TelephonyClientError("telephony policy decision is unavailable")
    if decision.correlation_id != command.correlation_id:
        raise TelephonyClientError("telephony policy correlation changed")
    if payload_hash(decision.context) != command.policy_decision_hash:
        raise TelephonyClientError("telephony policy decision changed")
    if decision.context.get("authorization_scope") != command.policy_scope():
        raise TelephonyClientError("telephony policy scope changed")
    if not decision.allowed or decision.context.get("enforced") is not True:
        raise TelephonyClientError("telephony policy no longer authorizes dispatch")
    expiration = decision.context.get("expiration")
    if not isinstance(expiration, str):
        raise TelephonyClientError("telephony policy expiration is invalid")
    try:
        expires_at = datetime.fromisoformat(expiration)
    except ValueError:
        raise TelephonyClientError("telephony policy expiration is invalid") from None
    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
        raise TelephonyClientError("telephony policy authorization expired")


async def _record_failure(
    session_factory: async_sessionmaker[AsyncSession],
    command_id: UUID,
    owner: str,
    exc: Exception,
) -> None:
    async with session_factory() as session:
        row = await session.get(
            TelephonyCommandJournal, command_id, with_for_update=True
        )
        if (
            row is None
            or row.state != TelephonyCommandState.SUBMITTING.value
            or row.lease_owner != owner
        ):
            return
        permanent = _permanent(exc) or row.attempt_count >= MAX_ATTEMPTS
        row.state = (
            TelephonyCommandState.FAILED_PERMANENT.value
            if permanent
            else TelephonyCommandState.FAILED_TRANSIENT.value
        )
        row.next_attempt_at = (
            None
            if permanent
            else datetime.now(UTC)
            + timedelta(seconds=min(300, 2 ** min(row.attempt_count, 8)))
        )
        row.lease_owner = None
        row.updated_at = datetime.now(UTC)
        await session.commit()


async def _persist_submission(
    session_factory: async_sessionmaker[AsyncSession],
    command_id: UUID,
    owner: str,
    command: TelephonyCommandRequest,
    operation: dict[str, Any],
) -> None:
    async with session_factory() as session:
        row = await session.get(
            TelephonyCommandJournal, command_id, with_for_update=True
        )
        if (
            row is None
            or row.state != TelephonyCommandState.SUBMITTING.value
            or row.lease_owner != owner
        ):
            raise RuntimeError("telephony command submission ownership conflict")
        operation_public_id = str(operation["operation_public_id"])
        existing_for_command = await session.scalar(
            select(TelephonyOperationJournal).where(
                TelephonyOperationJournal.command_id == command_id
            )
        )
        if existing_for_command is None:
            session.add(
                TelephonyOperationJournal(
                    operation_id=uuid4(),
                    operation_public_id=operation_public_id,
                    command_id=command_id,
                    state=(
                        "AMBIGUOUS"
                        if operation.get("ambiguous")
                        else TelephonyCommandState.SUBMITTED.value
                    ),
                    endpoint_key=operation["endpoint_key"],
                    readback_endpoint_key=operation["readback_endpoint_key"],
                    target_configuration_checksum=operation[
                        "target_configuration_checksum"
                    ],
                    target_attested=operation["target_attested"],
                    adapter_service_key=operation["adapter_service_key"],
                    adapter_operation_id=operation["adapter_operation_id"],
                    target_system=(
                        "ASTERISK"
                        if command.command_type.value.startswith("telephony.asterisk.")
                        else "VICIDIAL"
                    ),
                    target_resource_type=(
                        "ENDPOINT"
                        if command.payload.endpoint_public_id
                        else "PHONE"
                        if command.payload.phone_public_id
                        else "USER"
                    ),
                    target_public_id=(
                        command.payload.endpoint_public_id
                        or command.payload.phone_public_id
                        or command.payload.agent_public_id
                        or command.aggregate_public_id
                    ),
                    desired_state_version=command.payload.desired_state_version,
                    idempotency_hash=payload_hash(
                        {
                            "command_public_id": command.command_public_id
                            or str(command_id),
                            "resolved_endpoint_id": operation["endpoint_id"],
                            "endpoint_configuration_version": operation[
                                "endpoint_version_id"
                            ],
                        }
                    ),
                    desired_hash=operation["desired_hash"],
                    correlation_id=command.correlation_id,
                    response_json={},
                )
            )
        elif existing_for_command.operation_public_id != operation_public_id:
            raise RuntimeError("adapter operation idempotency conflict")
        # Keep the submitting worker's lease across the durable
        # submission-to-readback handoff. Exposing READBACK_PENDING here would
        # allow another worker to claim the row before this worker begins
        # readback, producing duplicate readbacks and an ownership conflict.
        now = datetime.now(UTC)
        row.state = TelephonyCommandState.SUBMITTING.value
        row.next_attempt_at = now + timedelta(seconds=LEASE_SECONDS)
        row.lease_owner = owner
        row.updated_at = now
        await session.commit()


async def dispatch_one(
    session_factory: async_sessionmaker[AsyncSession],
    client_factory: Callable[[], TelephonyDispatcher],
    *,
    environment: str,
    traceparent_factory: Callable[[], str],
) -> dict[str, Any]:
    async with session_factory() as session:
        claim = await claim_authorized(session, environment=environment)
    if claim is None:
        return {"claimed": 0}
    command_id, owner = claim

    async with session_factory() as session:
        row = await session.get(TelephonyCommandJournal, command_id)
        if row is None:
            raise RuntimeError("claimed telephony command disappeared")
        command = TelephonyCommandRequest.model_validate(row.request_json)
        existing = await session.scalar(
            select(TelephonyOperationJournal).where(
                TelephonyOperationJournal.command_id == command_id
            )
        )
        operation = (
            {
                "operation_id": existing.operation_public_id,
                "operation_public_id": existing.operation_public_id,
                "adapter_operation_id": existing.adapter_operation_id,
                "endpoint_key": existing.endpoint_key,
                "readback_endpoint_key": existing.readback_endpoint_key,
                "target_configuration_checksum": (
                    existing.target_configuration_checksum
                ),
                "target_attested": existing.target_attested,
                "desired_hash": existing.desired_hash,
            }
            if existing
            else None
        )
        decision = (
            await session.get(PolicyDecision, UUID(command.policy_decision_id))
            if operation is None
            else None
        )

    client = client_factory()
    heartbeat = asyncio.create_task(_renew_lease(session_factory, command_id, owner))
    try:
        if operation is None:
            _validate_policy_for_dispatch(command, decision)
            operation = await _run_while_lease(
                client.dispatch(
                    str(command_id), command, traceparent=traceparent_factory()
                ),
                heartbeat,
            )
            await _persist_submission(
                session_factory, command_id, owner, command, operation
            )
        readback = await _run_while_lease(
            client.readback(command, operation, traceparent=traceparent_factory()),
            heartbeat,
        )
    except Exception as exc:
        await _record_failure(session_factory, command_id, owner, exc)
        raise
    finally:
        heartbeat.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat
        close = getattr(client, "aclose", None)
        if close is not None:
            await close()

    state = (
        TelephonyCommandState.ODOO_RESULT_PENDING
        if readback["readback_matches"]
        else TelephonyCommandState.RECONCILIATION_REQUIRED
    )
    async with session_factory() as session:
        row = await session.get(
            TelephonyCommandJournal, command_id, with_for_update=True
        )
        operation_row = await session.scalar(
            select(TelephonyOperationJournal).where(
                TelephonyOperationJournal.command_id == command_id
            )
        )
        if (
            row is None
            or operation_row is None
            or row.state != TelephonyCommandState.SUBMITTING.value
            or row.lease_owner != owner
        ):
            raise RuntimeError("telephony command finalization state conflict")
        operation_row.state = state.value
        operation_row.actual_hash = readback["actual_hash"]
        operation_row.readback_matches = readback["readback_matches"]
        operation_row.response_json = readback["actual"]
        operation_row.completed_at = datetime.now(UTC)
        row.state = state.value
        row.next_attempt_at = None
        row.lease_owner = None
        row.updated_at = datetime.now(UTC)
        await session.commit()
    return {
        "claimed": 1,
        "command_id": str(command_id),
        "operation_id": operation["operation_id"],
        "state": state.value,
    }
