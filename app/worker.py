from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from collections.abc import Awaitable, Callable, Mapping

from .storage import DEFAULT_MAX_OUTBOX_ATTEMPTS, OutboxRecord, PostgresOutboxStore


Handler = Callable[[OutboxRecord], Awaitable[None]]
log = logging.getLogger(__name__)


class KnownSafeRetryError(RuntimeError):
    """Handler-provided proof that no external effect could have committed.

    Provider adapters may raise this only when they can establish that the
    operation is safe to retry, for example because dispatch was rejected before
    any provider write was attempted. Ambiguous transport/provider errors must
    not use this exception; they remain quarantined for reconciliation instead.
    """


class OutboxWorker:
    """Generic bounded lease/retry/reconciliation worker.

    No provider handlers are registered on intake-runtime-v1. Immediately before
    any future provider handler is invoked, the claimed row is durably moved into
    the reconciliation-required state and its active worker lease is refreshed for
    a full lease window. A background heartbeat continues renewing that ownership
    until the provider task actually terminates, including any time spent waiting
    for a cancellation-suppressing coroutine to finish after the timeout.

    Timeout is sticky: once the configured deadline is crossed, a later normal
    return or KnownSafeRetryError from a cancellation-suppressing handler cannot
    turn that unknown outcome into an automatic complete or retry transition.
    Provider dispatch remains disabled by Settings on this branch.
    """

    def __init__(
        self,
        store: PostgresOutboxStore,
        handlers: Mapping[str, Handler],
        *,
        poll_seconds: float = 1.0,
        lease_seconds: float = 60.0,
        handler_timeout_seconds: float = 45.0,
        max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if handler_timeout_seconds <= 0 or handler_timeout_seconds >= lease_seconds:
            raise ValueError("handler timeout must be positive and strictly below lease")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.store = store
        self.handlers = handlers
        self.poll_seconds = poll_seconds
        self.lease_seconds = lease_seconds
        self.handler_timeout_seconds = handler_timeout_seconds
        self.max_attempts = max_attempts
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"

    async def _heartbeat_active_dispatch(
        self,
        record_id: int,
        stop: asyncio.Event,
    ) -> None:
        interval = max(0.01, min(5.0, self.lease_seconds / 3.0))
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                return
            except TimeoutError:
                pass
            try:
                await self.store.renew_active_dispatch(
                    record_id,
                    worker_id=self.worker_id,
                    lease_seconds=self.lease_seconds,
                )
            except Exception:
                # Keep retrying while provider code is alive. The row remains
                # reconciliation-required and therefore excluded from claims even
                # if PostgreSQL is temporarily unavailable.
                log.exception(
                    "active dispatch lease heartbeat failed; will retry",
                    extra={"outbox_id": record_id},
                )

    async def run_once(self) -> bool:
        record = await self.store.claim(
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
            max_attempts=self.max_attempts,
        )
        if record is None:
            return False

        handler = self.handlers.get(record.destination)
        if handler is None:
            await self.store.fail(
                record.id,
                worker_id=self.worker_id,
                error=f"no handler registered for destination {record.destination}",
                max_attempts=self.max_attempts,
            )
            return True

        # This final pre-provider transaction refreshes the lease from database
        # time. If it fails, the exception propagates and provider code is never run.
        await self.store.quarantine_unknown_outcome(
            record.id,
            worker_id=self.worker_id,
            error=(
                "provider dispatch reserved before handler invocation; external outcome "
                "must be explicitly confirmed before automatic release"
            ),
            lease_seconds=self.lease_seconds,
        )

        heartbeat_stop = asyncio.Event()
        heartbeat_task = asyncio.create_task(
            self._heartbeat_active_dispatch(record.id, heartbeat_stop)
        )
        handler_task = asyncio.ensure_future(handler(record))
        timed_out = False
        try:
            try:
                done, _ = await asyncio.wait(
                    {handler_task},
                    timeout=self.handler_timeout_seconds,
                )
                if handler_task not in done:
                    timed_out = True
                    handler_task.cancel()

                try:
                    await handler_task
                except asyncio.CancelledError:
                    if not timed_out:
                        raise
                except KnownSafeRetryError as exc:
                    if timed_out:
                        log.error(
                            "outbox handler crossed timeout then reported safe retry; "
                            "unknown outcome remains quarantined",
                            extra={"outbox_id": record.id},
                        )
                    else:
                        log.warning(
                            "outbox handler certified failure as safe to retry",
                            extra={"outbox_id": record.id},
                        )
                        await self.store.resolve_reconciliation(
                            record.id,
                            operator_id=f"worker:{self.worker_id}",
                            action="retry",
                            reason=f"handler certified known-safe retry: {exc}",
                            max_attempts=self.max_attempts,
                            worker_id=self.worker_id,
                        )
                except Exception:
                    if timed_out:
                        log.exception(
                            "outbox handler crossed timeout and later raised; "
                            "unknown outcome remains quarantined",
                            extra={"outbox_id": record.id},
                        )
                    else:
                        log.exception(
                            "outbox handler raised; reconciliation quarantine retained",
                            extra={"outbox_id": record.id},
                        )
                else:
                    if timed_out:
                        log.error(
                            "outbox handler crossed timeout and later returned; "
                            "unknown outcome remains quarantined",
                            extra={"outbox_id": record.id},
                        )
                    else:
                        await self.store.resolve_reconciliation(
                            record.id,
                            operator_id=f"worker:{self.worker_id}",
                            action="complete",
                            reason="handler returned successfully and confirmed delivery outcome",
                            max_attempts=self.max_attempts,
                            worker_id=self.worker_id,
                        )
            except asyncio.CancelledError:
                # A worker shutdown must not orphan live provider code while the
                # lease heartbeat is stopped. Cancel the provider task and keep
                # renewing ownership until that task actually terminates.
                if not handler_task.done():
                    handler_task.cancel()
                try:
                    await handler_task
                except (asyncio.CancelledError, Exception):
                    pass
                raise
        finally:
            heartbeat_stop.set()
            await heartbeat_task
        return True

    async def run_forever(self) -> None:
        while True:
            processed = await self.run_once()
            if not processed:
                await asyncio.sleep(self.poll_seconds)
