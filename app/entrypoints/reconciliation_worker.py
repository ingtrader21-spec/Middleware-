"""The reconciler process: the V3 kernel reconciler plus the report-only
internal outbox reconciliation and quarantine cleanup.

Every cycle drains the quarantined adapter-command rows through
:class:`app.platform.reconciler.Reconciler` (lease, adapter readback,
ledger transition, immutable audit; never a blind re-send) on the same
RuntimeContainer the API and worker use, then runs the legacy report."""

from __future__ import annotations

import logging

from app.core.config import settings
from app.core.runtime import RuntimeContainer, build_runtime_container
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.workers.reconciliation import reconcile_internal_outbox
from app.workers.quarantine import CLEANUP, cleanup_expired


# Deployed as the "middleware-reconciler" process role; the service name stays
# the compose/bootstrap contract name.
SERVICE = "middleware-reconciliation-worker"
QUEUE = "middleware.reconciliation.v1"
MAX_DECISIONS_PER_CYCLE = 200
logger = logging.getLogger("codestra.reconciler")

_runtime: RuntimeContainer | None = None


async def kernel_runtime() -> RuntimeContainer:
    """The process-lifetime container (opened on the first cycle)."""
    global _runtime
    if _runtime is None:
        _runtime = await build_runtime_container(settings, role="worker", service_id=SERVICE)
    return _runtime


async def reconcile_kernel() -> dict[str, object]:
    """Drain the kernel reconciler once (bounded per cycle)."""
    runtime = await kernel_runtime()
    platform = runtime.platform
    if platform is None or platform.reconciler is None:
        return {"status": "kernel-reconciler-unavailable", "decisions": 0}
    decisions: dict[str, int] = {}
    for _ in range(MAX_DECISIONS_PER_CYCLE):
        decision = await platform.reconciler.run_once()
        if decision is None:
            break
        decisions[decision.action] = decisions.get(decision.action, 0) + 1
    return {"status": "ok", "decisions": sum(decisions.values()), "by_action": decisions}


async def cycle() -> dict[str, object]:
    kernel = await reconcile_kernel()
    async with SessionFactory() as session:
        reconciliation = await reconcile_internal_outbox(session)
        try:
            cleanup = await cleanup_expired(session)
        except Exception:
            CLEANUP.labels("failure").inc()
            raise
        return {"kernel": kernel, "reconciliation": reconciliation, "quarantine_cleanup": cleanup}


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
