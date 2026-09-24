"""Authenticated Odoo calling endpoints, backed by the canonical durable ledger."""
from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from .api_inputs import authorization_header, optional_header, required_header
from .calling_contract import (
    CLIENT_ID, CallPrincipal, CallingContractError, CallingGrant,
    MutationRequest, OriginateRequest, load_grant,
)
from .calling_ledger import CallingLedger, operation_response
from .commands import MemoryCommandStore
from .security import AuthorizationError, RequestValidationError
from .storage import StorageError

router = APIRouter(prefix="/v1/telephony/calls", tags=["odoo-calling"])

# Compatibility ingress for the reviewed Middleware contract. This route is
# handled by the same internal-only ledger as the canonical telephony path; it
# is never forwarded to Server B's external /v1/calls/originate endpoint.
compat_router = APIRouter(prefix="/v1/calls", tags=["odoo-calling"])


class CallingResponse(BaseModel):
    dialing: Literal["attempting", "unknown", "blocked"]
    reason: str
    operation_id: str | None = None
    correlation_id: str | None = None
    call_id: str | None = None
    operation_state: str | None = None
    call_state: str | None = None
    resource_version: int | None = None
    duplicate: bool = False
    retry_safe: bool = False
    external_dialing: Literal[False] = False
    status_url: str | None = None
    hangup_operation_id: str | None = None
    hangup_state: str | None = None


async def _principal(request: Request, action: str) -> CallPrincipal:
    claims = await request.app.state.runtime.tokens.verify(
        authorization_header(request), expected_client_id=CLIENT_ID,
        required_scope=f"telephony.calls.{action}",
    )
    try:
        principal = CallPrincipal.from_claims(claims)
    except ValidationError as exc:
        raise AuthorizationError("verified calling identity claims are incomplete") from exc
    supplied_tenant = optional_header(
        request, "X-Tenant-ID", minimum=1, maximum=128,
    )
    if supplied_tenant is not None and supplied_tenant != principal.tenant_id:
        raise AuthorizationError("calling tenant header conflicts with verified identity")
    return principal


def _headers(request: Request, key: str) -> str:
    supplied_key = required_header(
        request, "Idempotency-Key", minimum=8, maximum=180,
    )
    if supplied_key != key:
        raise RequestValidationError("Idempotency-Key must equal the request body key")
    correlation = required_header(
        request, "X-Correlation-ID", minimum=8, maximum=180,
    )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,179}", correlation) is None:
        raise RequestValidationError("a bounded X-Correlation-ID is required")
    return correlation


def _ledger(request: Request) -> CallingLedger:
    runtime = request.app.state.runtime
    if runtime.commands is None:
        raise StorageError("calling command ledger is unavailable")
    if isinstance(runtime.commands.store, MemoryCommandStore) and not runtime.settings.allow_in_memory_storage:
        raise StorageError("in-memory calling state is prohibited in this runtime")
    if not hasattr(runtime, "_calling_ledger"):
        runtime._calling_ledger = CallingLedger(runtime.commands)
    return runtime._calling_ledger


def calling_grant() -> CallingGrant | None:
    try:
        return load_grant()
    except CallingContractError as exc:
        raise AuthorizationError(str(exc)) from exc


def _json(content: dict, status: int = 200) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if content.get("status_url"):
        headers["Location"] = content["status_url"]
    return JSONResponse(status_code=status, content=content, headers=headers)


@router.post("/originate", response_model=CallingResponse, responses={202: {"model": CallingResponse}})
async def originate(body: OriginateRequest, request: Request) -> JSONResponse:
    principal = await _principal(request, "originate")
    correlation = _headers(request, body.idempotency_key)
    try:
        body.assert_principal(principal)
    except CallingContractError as exc:
        raise AuthorizationError(str(exc)) from exc
    ledger = _ledger(request)
    # Always reconcile an existing key before checking a now-closed start gate.
    # Returning "blocked" for an accepted prior request would permit a duplicate.
    previous = await ledger.replay(principal, body, correlation)
    if previous is not None:
        return _json(operation_response(previous))
    grant = calling_grant()
    if grant is None or body.destination_class != "internal_test":
        return _json({"dialing": "blocked", "reason": "internal calling is not authorized; public dialing remains disabled",
                      "correlation_id": correlation, "retry_safe": True, "external_dialing": False})
    try:
        grant.authorize(principal, body, source_sha=request.app.state.runtime.settings.source_sha)
    except CallingContractError as exc:
        raise AuthorizationError(str(exc)) from exc
    operation = await ledger.originate(principal, body, correlation, grant)
    return _json(operation_response(operation), 200 if operation.duplicate else 202)


# The external adapter also owns a /v1/calls/originate route. Keep this
# compatibility ingress local to Middleware and reuse the exact authenticated
# handler so it cannot accidentally become a PSTN bypass.
compat_router.add_api_route(
    "/originate", originate, methods=["POST"], name="middleware_internal_originate_compat",
    response_model=CallingResponse, responses={202: {"model": CallingResponse}},
)


@router.get("/requests/{operation_id}", response_model=CallingResponse)
async def call_status(operation_id: UUID, request: Request) -> JSONResponse:
    principal = await _principal(request, "read")
    document, operation = await _ledger(request).get(principal, operation_id)
    return _json(operation_response(operation, document))


@router.post("/requests/{operation_id}/reconcile", response_model=CallingResponse,
             responses={202: {"model": CallingResponse}})
async def reconcile(operation_id: UUID, body: MutationRequest, request: Request) -> JSONResponse:
    principal = await _principal(request, "reconcile")
    correlation = _headers(request, body.idempotency_key)
    ledger = _ledger(request)
    document, _ = await ledger.get(principal, operation_id)
    if correlation != document.correlation_id:
        raise RequestValidationError("reconciliation must preserve the calling correlation ID")
    operation = await ledger.reconcile(principal, operation_id, key=body.idempotency_key,
                                       expected_version=body.expected_version, reason=body.reason)
    return _json(operation_response(operation, document), 202)


@router.post("/requests/{operation_id}/hangup", response_model=CallingResponse,
             responses={202: {"model": CallingResponse}})
async def hangup(operation_id: UUID, body: MutationRequest, request: Request) -> JSONResponse:
    principal = await _principal(request, "hangup")
    correlation = _headers(request, body.idempotency_key)
    ledger = _ledger(request)
    document, current = await ledger.get(principal, operation_id)
    if correlation != document.correlation_id:
        raise RequestValidationError("hangup must preserve the calling correlation ID")
    action = await ledger.hangup(principal, operation_id, key=body.idempotency_key,
                                 expected_version=body.expected_version, reason=body.reason)
    response = operation_response(current)
    response.update({"hangup_operation_id": str(action.command_id), "hangup_state": action.state,
                     "reason": "hangup requested; terminal provider confirmation is still required",
                     "duplicate": action.duplicate})
    return _json(response, 200 if action.duplicate else 202)
