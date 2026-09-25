from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api_inputs import authorization_header, required_header
from app.commands import CommandConflict, CommandNotFound
from app.core.mcr_odoo_handoff import (
    McrOdooHandoffConflict,
    McrOdooHandoffNotFound,
    PostgresMcrOdooHandoffStore,
    expected_idempotency_key,
)
from app.security import AuthenticationError, AuthorizationError, authorize_tenant
from app.storage import StorageError

router = APIRouter(prefix="/platform/v1/crm/handoffs", tags=["mcr-odoo-handoff"])

_SCOPE = {
    "submit": "crm.handoff.write",
    "read": "crm.handoff.read",
    "reconcile": "crm.handoff.reconcile",
}


class HandoffPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    lead_id: str = Field(pattern=r"^\S(?:.*\S)?$", max_length=180)
    campaign_id: str = Field(pattern=r"^(klyrow|whatsapp):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    campaign_version: int = Field(ge=1)
    lifecycle_version: int = Field(ge=1)
    policy_version: str = Field(pattern=r"^\S(?:.*\S)?$", max_length=128)
    handoff: Literal["accepted", "engaged", "conversion"]
    lifecycle_state: Literal["ELIGIBLE", "ACTIVE_CYCLE", "ENGAGED", "CONVERTED"]
    signal: Literal["policy_accepted", "click", "reply", "conversion"]
    evidence_source: Literal["middleware", "odoo"]
    evidence_id: str = Field(pattern=r"^\S(?:.*\S)?$", max_length=180)
    evidence_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    occurred_at: datetime
    dry_run: Literal[True]
    allow_external_contact: Literal[False]

    @model_validator(mode="after")
    def validate_semantics(self):
        if self.handoff == "accepted":
            if self.lifecycle_state not in {"ELIGIBLE", "ACTIVE_CYCLE"}:
                raise ValueError("accepted handoff requires eligible/active lifecycle")
            if self.signal != "policy_accepted" or self.evidence_source != "middleware":
                raise ValueError("accepted handoff requires middleware policy evidence")
        elif self.handoff == "engaged":
            if self.lifecycle_state != "ENGAGED":
                raise ValueError("engaged handoff requires ENGAGED lifecycle")
            if self.signal not in {"click", "reply"} or self.evidence_source != "middleware":
                raise ValueError("engaged handoff requires middleware engagement evidence")
        else:
            if self.lifecycle_state != "CONVERTED":
                raise ValueError("conversion handoff requires CONVERTED lifecycle")
            if self.signal != "conversion" or self.evidence_source != "odoo":
                raise ValueError("conversion handoff requires Odoo conversion evidence")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("occurred_at must include timezone")
        return self


class HandoffCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: UUID
    command_type: Literal["crm.lifecycle.handoff"]
    command_version: Literal["1.0"]
    target: Literal["odoo-19"]
    tenant_id: str = Field(min_length=1, max_length=128)
    requested_by: str = Field(min_length=1, max_length=300)
    correlation_id: str = Field(min_length=1, max_length=180)
    idempotency_key: str = Field(pattern=r"^mcrodoo1:[a-f0-9]{64}$")
    capability: Literal["ODOO_WRITE"]
    payload: HandoffPayload


async def _authenticate(request: Request, scope: str) -> dict:
    runtime = request.app.state.runtime
    configured = [
        value.strip()
        for value in getattr(runtime.settings, "mcr_odoo_handoff_client_ids", "").split(",")
        if value.strip()
    ]
    if not configured:
        raise StorageError("MCR Odoo handoff caller authority is not configured")
    authorization = authorization_header(request)
    last_error: Exception | None = None
    for client_id in configured:
        try:
            return await runtime.tokens.verify(
                authorization,
                expected_client_id=client_id,
                required_scope=scope,
            )
        except (AuthenticationError, AuthorizationError) as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise AuthenticationError("no configured MCR Odoo caller matched")


def _store(request: Request) -> PostgresMcrOdooHandoffStore:
    pool = request.app.state.runtime.pool
    if pool is None:
        raise StorageError("MCR Odoo handoff persistence is unavailable")
    return PostgresMcrOdooHandoffStore(pool)


async def _metadata(request: Request, *, scope: str, idempotency: bool):
    claims = await _authenticate(request, scope)
    tenant_id = required_header(request, "X-Tenant-ID", minimum=1, maximum=128)
    correlation_id = required_header(request, "X-Correlation-ID", minimum=1, maximum=180)
    causation_id = required_header(request, "X-Causation-ID", minimum=1, maximum=180)
    idem = (
        required_header(request, "Idempotency-Key", minimum=8, maximum=180)
        if idempotency
        else None
    )
    authorize_tenant(claims, tenant_id)
    return tenant_id, correlation_id, causation_id, idem


def _command_doc(command: HandoffCommand) -> dict:
    return command.model_dump(mode="json")


@router.post("")
async def submit_handoff(command: HandoffCommand, request: Request) -> JSONResponse:
    tenant_id, correlation_id, causation_id, idem = await _metadata(
        request, scope=_SCOPE["submit"], idempotency=True
    )
    if tenant_id != command.tenant_id:
        raise AuthorizationError("header tenant does not match command tenant")
    if correlation_id != command.correlation_id:
        raise AuthorizationError("header correlation does not match command")
    if idem != command.idempotency_key:
        raise CommandConflict("header idempotency key does not match command")
    document = _command_doc(command)
    if command.idempotency_key != expected_idempotency_key(document):
        raise CommandConflict("MCR Odoo idempotency key does not match natural handoff identity")
    try:
        result = await _store(request).accept(document, causation_id=causation_id)
    except McrOdooHandoffConflict as exc:
        raise CommandConflict(str(exc)) from exc
    return JSONResponse(
        status_code=200 if result.duplicate else 202,
        content={
            "command_id": str(result.command_id),
            "correlation_id": result.correlation_id,
            "status": "accepted",
            "duplicate": result.duplicate,
            "crm_completed": False,
        },
        headers={"X-Correlation-ID": result.correlation_id},
    )


@router.get("/{command_id}")
async def read_handoff(command_id: UUID, request: Request) -> JSONResponse:
    tenant_id, correlation_id, _, _ = await _metadata(
        request, scope=_SCOPE["read"], idempotency=False
    )
    try:
        body = await _store(request).readback(tenant_id, command_id)
    except McrOdooHandoffNotFound as exc:
        raise CommandNotFound("handoff not found") from exc
    return JSONResponse(
        status_code=200,
        content=body,
        headers={"X-Correlation-ID": correlation_id},
    )


@router.post("/{command_id}/reconcile")
async def reconcile_handoff(command_id: UUID, request: Request) -> JSONResponse:
    tenant_id, correlation_id, causation_id, idem = await _metadata(
        request, scope=_SCOPE["reconcile"], idempotency=True
    )
    assert idem is not None
    try:
        body = await _store(request).request_reconciliation(
            tenant_id,
            command_id,
            idempotency_key=idem,
            correlation_id=correlation_id,
            causation_id=causation_id,
        )
    except McrOdooHandoffNotFound as exc:
        raise CommandNotFound("handoff not found") from exc
    except McrOdooHandoffConflict as exc:
        raise CommandConflict(str(exc)) from exc
    return JSONResponse(
        status_code=200,
        content=body,
        headers={"X-Correlation-ID": correlation_id},
    )
