"""Private bounded provider-canary controller API (PAS-57).

Synthetic/no-effect only. The controller is disabled by default; every
request is evaluated against the operator caps in Settings and denied with
stable reason codes when any prerequisite is missing. No handler reaches a
provider transport, and no route releases the kill switch: release requires
an operator configuration change and restart. The surface lives under
``/internal/*`` and is therefore unreachable at the public edge.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api_inputs import authorization_header
from app.control_plane_auth import caller_for_authorization
from app.provider_canary_controller import (
    REQUIRED_EVIDENCE_KINDS,
    TARGET_BINDINGS,
    IdempotencyConflict,
    ProviderCanaryLedger,
    ProviderCanaryPlan,
    evaluate_plan,
    execute_synthetic,
    policy_caps,
)

router = APIRouter(
    prefix="/internal/v1/provider-canaries", tags=["internal-provider-canaries"]
)

READ_SCOPE = "platform.provider_canary.read"
EXECUTE_SCOPE = "platform.provider_canary.execute"
KILL_SCOPE = "platform.provider_canary.kill"


class KillSwitchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=256)


def _now() -> datetime:
    return datetime.now(UTC)


def _runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or getattr(runtime, "tokens", None) is None:
        raise HTTPException(503, "provider-canary runtime unavailable")
    return runtime


def _ledger(request: Request) -> ProviderCanaryLedger:
    ledger = getattr(request.app.state, "provider_canary_ledger", None)
    if ledger is None:
        ledger = ProviderCanaryLedger()
        request.app.state.provider_canary_ledger = ledger
    return ledger


async def _authorize(request: Request, required_scope: str) -> str:
    runtime = _runtime(request)
    authorization = authorization_header(request)
    caller = caller_for_authorization(authorization)
    await runtime.tokens.verify(
        authorization,
        expected_client_id=caller.client_id,
        required_scope=required_scope,
    )
    return caller.client_id


def _decide(request: Request, plan: ProviderCanaryPlan, now: datetime):
    ledger = _ledger(request)
    return evaluate_plan(
        plan,
        _runtime(request).settings,
        now=now,
        runtime_kill_switch_engaged=ledger.kill_switch_engaged,
        recent_runs=ledger.recent_runs(plan.tenant_id, plan.target, now),
    )


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    settings = _runtime(request).settings
    ledger = _ledger(request)
    return {
        "controller_enabled": bool(settings.provider_canary_controller_enabled),
        "execution_modes": ["synthetic"],
        "live_execution_available": False,
        "configured_kill_switch_engaged": bool(
            settings.provider_canary_kill_switch_engaged
        ),
        "runtime_kill_switch": ledger.kill_switch_state(),
        "caps": policy_caps(settings),
        "required_evidence_kinds": list(REQUIRED_EVIDENCE_KINDS),
        "target_bindings": {
            target: {"provider": provider, "capability": capability}
            for target, (provider, capability) in sorted(TARGET_BINDINGS.items())
        },
        "ledger": ledger.counts(),
        "provider_effects": 0,
    }


@router.post("/policy-check")
async def policy_check(request: Request, plan: ProviderCanaryPlan) -> dict[str, Any]:
    """Evaluate a plan without executing or recording anything."""

    await _authorize(request, READ_SCOPE)
    return _decide(request, plan, _now()).as_dict()


@router.post("/synthetic-runs", status_code=201)
async def create_synthetic_run(request: Request, plan: ProviderCanaryPlan):
    """Evaluate and, only when allowed, execute the canary synthetically."""

    await _authorize(request, EXECUTE_SCOPE)
    ledger = _ledger(request)
    try:
        existing = ledger.existing(plan)
    except IdempotencyConflict:
        raise HTTPException(
            409, "canary_id was already executed with a different plan"
        ) from None
    if existing is not None:
        return JSONResponse(
            status_code=200, content={**existing.as_dict(), "replayed": True}
        )
    now = _now()
    decision = _decide(request, plan, now)
    if not decision.allowed:
        ledger.record_denial(decision)
        return JSONResponse(status_code=403, content=decision.as_dict())
    run = execute_synthetic(
        plan,
        decision,
        now=now,
        kill_switch_engaged=lambda: ledger.kill_switch_engaged,
    )
    ledger.record_run(run)
    return {**run.as_dict(), "decision": decision.as_dict(), "replayed": False}


@router.get("/synthetic-runs/{run_id}")
async def get_synthetic_run(request: Request, run_id: str) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    run = _ledger(request).get(run_id)
    if run is None:
        raise HTTPException(404, "synthetic canary run not found")
    return run.as_dict()


@router.post("/kill-switch/engage")
async def engage_kill_switch(
    request: Request, body: KillSwitchRequest
) -> dict[str, Any]:
    """Engage the runtime kill switch; idempotent and never released by API."""

    actor = await _authorize(request, KILL_SCOPE)
    state = _ledger(request).engage_kill_switch(
        actor=actor, reason=body.reason, now=_now()
    )
    return {**state, "release": "operator configuration change and restart"}
