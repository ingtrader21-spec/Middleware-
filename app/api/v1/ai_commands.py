"""Authenticated, tenant-isolated AI command router."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai_console import Tenant, tenant
from app.core import ai_orchestration
from app.core.ai_contracts import AICommand
from app.core.config import settings
from app.core.ai_metrics import COMMANDS, QUOTA_REJECTIONS
from app.db.session import get_session


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Decision(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


router = APIRouter(
    prefix="/api/v1/ai",
    tags=["ai-orchestration"],
    dependencies=[Depends(tenant)],
)


def correlation(value: Annotated[str, Header(alias="X-Correlation-ID")]) -> str:
    if not 8 <= len(value) <= 128:
        raise HTTPException(400, "invalid correlation ID")
    return value


@router.post("/commands", status_code=202)
async def submit_command(
    command: AICommand,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if not settings.ai_submissions_enabled or not settings.ai_orchestration_enabled:
        raise HTTPException(503, "AI_TEMPORARILY_UNAVAILABLE")
    if (
        command.tenant_id != subject.organization_id
        or command.actor_id != subject.user_id
    ):
        raise HTTPException(403, "tenant or actor mismatch")
    try:
        result = await ai_orchestration.submit(db, command, subject.workspace_id)
        COMMANDS.labels(command.command_type.value, "accepted").inc()
        return result
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except OverflowError as exc:
        QUOTA_REJECTIONS.labels(str(exc)).inc()
        raise HTTPException(429, str(exc)) from exc


@router.get("/commands/{command_id}")
async def get_command(
    command_id: UUID,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        return await ai_orchestration.get(
            db, command_id, subject.organization_id, subject.workspace_id
        )
    except LookupError as exc:
        raise HTTPException(404, "command not found") from exc


@router.post("/commands/{command_id}/cancel", status_code=202)
async def cancel_command(
    command_id: UUID,
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(correlation),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        state = await ai_orchestration.cancel(
            db,
            command_id,
            subject.organization_id,
            subject.workspace_id,
            subject.user_id,
            correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(404, "active command not found") from exc
    return {"command_id": command_id, "status": state}


@router.get("/commands/{command_id}/result")
async def get_result(
    command_id: UUID,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        return await ai_orchestration.result(
            db, command_id, subject.organization_id, subject.workspace_id
        )
    except LookupError as exc:
        if str(exc) == "result_not_ready":
            raise HTTPException(409, "result not ready") from exc
        raise HTTPException(404, "command not found") from exc


async def _decision(
    command_id: UUID,
    body: Decision,
    subject: Tenant,
    correlation_id: str,
    db: AsyncSession,
    approved: bool,
) -> dict[str, Any]:
    if not subject.roles.intersection({"codestra_ai_approver", "codestra_admin"}):
        raise HTTPException(403, "approver role required")
    try:
        state = await ai_orchestration.decide(
            db,
            command_id,
            subject.organization_id,
            subject.workspace_id,
            subject.user_id,
            correlation_id,
            approved,
            body.reason,
        )
    except LookupError as exc:
        raise HTTPException(404, "pending approval not found") from exc
    return {"command_id": command_id, "status": state, "dispatch_enabled": False}


@router.post("/commands/{command_id}/approve")
async def approve(
    command_id: UUID,
    body: Decision,
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(correlation),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await _decision(command_id, body, subject, correlation_id, db, True)


@router.post("/commands/{command_id}/reject")
async def reject(
    command_id: UUID,
    body: Decision,
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(correlation),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await _decision(command_id, body, subject, correlation_id, db, False)


@router.get("/capabilities")
async def capabilities(
    _: Tenant = Depends(tenant), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    rows = (
        (
            await db.execute(
                text("""SELECT profile,command_types,logical_model,provider,
      enabled,max_input_tokens,max_output_tokens FROM ai_model_capabilities ORDER BY profile""")
            )
        )
        .mappings()
        .all()
    )
    return {
        "capabilities": [dict(row) for row in rows],
        "external_endpoints_exposed": False,
    }


@router.get("/usage")
async def usage(
    subject: Tenant = Depends(tenant), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    row = (
        (
            await db.execute(
                text("""SELECT COALESCE(sum(tokens),0) tokens,
      COALESCE(sum(compute_units),0) compute_units FROM ai_usage_ledger
      WHERE organization_id=:tenant AND workspace_id=:workspace AND usage_date=CURRENT_DATE"""),
                {"tenant": subject.organization_id, "workspace": subject.workspace_id},
            )
        )
        .mappings()
        .one()
    )
    return {
        "tenant_id": subject.organization_id,
        "workspace_id": subject.workspace_id,
        "date": "current",
        **dict(row),
    }
