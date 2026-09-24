"""Middleware V3 command kernel.

One orchestrator (:mod:`app.platform.kernel`) over the existing command ledger
(:mod:`app.commands`), the one Policy Engine (:mod:`app.core.policy_engine`),
the Safety Gate (:mod:`app.platform.safety`), the adapter registry and SDK
(:mod:`app.platform.registry`, :mod:`app.platform.adapter`), the ExecutionBus
over the durable outbox (:mod:`app.platform.bus`) and the reconciler
(:mod:`app.platform.reconciler`). Process wiring lives in
:mod:`app.platform.runtime`; the six ``/platform/v1`` routes in
:mod:`app.platform.api`.
"""
