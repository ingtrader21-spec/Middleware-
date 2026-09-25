"""Private production GO/NO_GO decision API.

Read-only: no route changes a capability flag, a provider setting or any
runtime state. ``GET /decision`` is the authoritative readback computed from
the release controller's mounted evidence store and is ``NO_GO`` whenever that
store is unconfigured, incomplete or invalid. ``POST /decision/evaluate`` is a
non-authoritative dry run over caller-supplied evidence. The surface is
edge-denied under ``/internal/*`` and requires explicit machine scopes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from app import production_decision as engine
from app.api_inputs import authorization_header
from app.control_plane_auth import caller_for_authorization

router = APIRouter(prefix="/internal/v1/production", tags=["internal-production-decision"])

READ_SCOPE = "platform.production.decision.read"
EVALUATE_SCOPE = "platform.production.decision.evaluate"

REQUEST_FILENAME = "decision-request.json"
MAX_EVIDENCE_BYTES = 256 * 1024


def _now() -> datetime:
    return datetime.now(UTC)


def _runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or getattr(runtime, "tokens", None) is None:
        raise HTTPException(503, "authorization runtime unavailable")
    return runtime


def _require(required_scope: str):
    """Authenticate before any body validation; returns the caller client id."""

    async def dependency(request: Request) -> str:
        runtime = _runtime(request)
        authorization = authorization_header(request)
        caller = caller_for_authorization(authorization)
        await runtime.tokens.verify(
            authorization,
            expected_client_id=caller.client_id,
            required_scope=required_scope,
        )
        return caller.client_id

    return dependency


class _Unreadable(Exception):
    pass


def _read_json(path: Path) -> Any:
    """Read one evidence document; ``None`` when absent."""
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise _Unreadable("not a regular file")
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise _Unreadable("document too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _Unreadable("document is not JSON") from exc


def _store_readback(settings: Any, now: datetime) -> dict[str, Any]:
    root = str(getattr(settings, "production_decision_evidence_dir", "") or "").strip()
    if not root:
        return engine.default_no_go(now=now, reason="evidence_store_unconfigured")
    base = Path(root)
    if not base.is_dir():
        return engine.default_no_go(now=now, reason="evidence_store_unavailable")
    try:
        raw_request = _read_json(base / REQUEST_FILENAME)
    except _Unreadable:
        return engine.default_no_go(now=now, reason="decision_request_invalid")
    if raw_request is None:
        return engine.default_no_go(now=now, reason="decision_request_missing")
    if not isinstance(raw_request, dict):
        return engine.default_no_go(now=now, reason="decision_request_invalid")
    requested_by = raw_request.pop("requested_by", None)
    if not isinstance(requested_by, str) or not requested_by.strip() or len(requested_by) > 200:
        return engine.default_no_go(now=now, reason="decision_requester_invalid")

    evidence: dict[str, Any] = {}
    for kind in engine.EVIDENCE_KINDS:
        try:
            document = _read_json(base / f"{kind}.json")
        except _Unreadable:
            # A non-empty mapping that no evidence model accepts: REJECTED.
            document = {"unreadable": True}
        if document is not None and not isinstance(document, dict):
            document = {"unreadable": True}
        evidence[kind] = document
    try:
        decision_request = engine.DecisionRequest.model_validate({**raw_request, "evidence": evidence})
    except ValidationError:
        return engine.default_no_go(
            now=now, reason="decision_request_invalid", requested_by=requested_by
        )
    return engine.evaluate(
        decision_request, requested_by=requested_by, now=now, source="evidence_store"
    )


@router.get(
    "/decision/policy",
    response_model=engine.DecisionPolicy,
    dependencies=[Depends(_require(READ_SCOPE))],
)
async def decision_policy() -> dict[str, Any]:
    return engine.policy_document()


@router.get(
    "/decision",
    response_model=engine.DecisionReadback,
    dependencies=[Depends(_require(READ_SCOPE))],
)
async def decision_readback(request: Request) -> dict[str, Any]:
    return _store_readback(_runtime(request).settings, _now())


@router.post("/decision/evaluate", response_model=engine.DecisionReadback)
async def evaluate_decision(
    body: engine.DecisionRequest,
    requested_by: str = Depends(_require(EVALUATE_SCOPE)),
) -> dict[str, Any]:
    return engine.evaluate(body, requested_by=requested_by, now=_now(), source="request")
