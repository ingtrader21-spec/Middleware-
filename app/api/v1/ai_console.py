"""Authenticated tenant-bound browser API for AI conversations."""

from __future__ import annotations

import asyncio
import json
from functools import lru_cache
from typing import Any
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import ai_jobs
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.db.session import get_session


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConversationRequest(StrictModel):
    title: str = Field(min_length=1, max_length=160)


class MessageRequest(StrictModel):
    content: str = Field(min_length=1)
    task_type: Literal["chat", "coding"] = "chat"
    project_key: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$"
    )


class Tenant:
    def __init__(
        self,
        organization_id: UUID,
        workspace_id: UUID,
        user_id: str,
        roles: frozenset[str],
    ):
        self.organization_id = organization_id
        self.workspace_id = workspace_id
        self.user_id = user_id
        self.roles = roles


@lru_cache(maxsize=1)
def _validator() -> KeycloakValidator:
    return KeycloakValidator(**identity_validator_kwargs(settings.identity))


def tenant(
    authorization: Annotated[str, Header(alias="Authorization")],
) -> Tenant:
    try:
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise JWTAuthError("bearer authorization required")
        claims: dict[str, Any] = _validator().validate(token)
        organization_id = UUID(str(claims["organization_id"]))
        workspace_id = UUID(str(claims["workspace_id"]))
        user_id = str(claims["sub"])
        roles = frozenset(claims.get("realm_access", {}).get("roles", []))
        if not roles.intersection(
            {"codestra_ai_user", "codestra_ai_developer", "codestra_admin"}
        ):
            raise JWTAuthError("AI role denied")
    except (JWTAuthError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(401, "authentication required") from exc
    return Tenant(organization_id, workspace_id, user_id, roles)


# Every current and future route on this router is authenticated independently
# of the outer compatibility middleware. FastAPI caches the repeated dependency
# call per request, so endpoint parameters receive the same validated principal.
router = APIRouter(
    prefix="/api/v1/ai",
    tags=["ai-console"],
    dependencies=[Depends(tenant)],
)


def request_context(value: Annotated[str, Header(alias="X-Correlation-ID")]) -> str:
    if not 1 <= len(value) <= 128:
        raise HTTPException(400, "invalid correlation ID")
    return value


def require_ai_submissions_available(_: Tenant = Depends(tenant)) -> None:
    """Fail before creating durable state while AI service is unavailable."""
    if not settings.ai_submissions_enabled:
        raise HTTPException(503, "AI_TEMPORARILY_UNAVAILABLE")


@router.post("/conversations", status_code=201)
async def create_conversation(
    body: ConversationRequest,
    _: None = Depends(require_ai_submissions_available),
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(request_context),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    return await ai_jobs.create_conversation(
        db,
        subject.organization_id,
        subject.workspace_id,
        subject.user_id,
        body.title,
        correlation_id,
    )


@router.post("/conversations/{conversation_id}/messages", status_code=202)
async def create_message(
    conversation_id: UUID,
    body: MessageRequest,
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=16, max_length=255)
    ],
    _: None = Depends(require_ai_submissions_available),
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(request_context),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    if len(body.content.encode()) > settings.ai_job_max_context_bytes:
        raise HTTPException(413, "context limit exceeded")
    if body.task_type == "coding" and not subject.roles.intersection(
        {"codestra_ai_developer", "codestra_admin"}
    ):
        raise HTTPException(403, "coding role required")
    allowed = {
        item.strip()
        for item in settings.ai_job_project_allowlist.split(",")
        if item.strip()
    }
    if body.task_type == "coding" and (
        not body.project_key or body.project_key not in allowed
    ):
        raise HTTPException(403, "project is not approved")
    try:
        return await ai_jobs.create_message_job(
            db,
            conversation_id=conversation_id,
            organization_id=subject.organization_id,
            workspace_id=subject.workspace_id,
            user_id=subject.user_id,
            content=body.content,
            task_type=body.task_type,
            project_key=body.project_key,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            max_attempts=settings.ai_job_max_attempts,
        )
    except LookupError as exc:
        raise HTTPException(404, "conversation not found") from exc
    except ValueError as exc:
        if str(exc) == "unsupported_browser_capability":
            raise HTTPException(422, "unsupported AI capability") from exc
        raise HTTPException(409, "idempotency conflict") from exc


@router.get("/jobs/{job_id}/stream")
async def stream(
    job_id: UUID,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    async def events():
        last = -1
        emitted_content = False
        for _ in range(1200):
            rows = (
                (
                    await db.execute(
                        text("""
                SELECT c.sequence,c.content,j.state FROM ai_job_chunks c
                JOIN ai_generation_jobs j ON j.id=c.job_id
                WHERE c.job_id=:job AND c.organization_id=:org AND c.workspace_id=:workspace
                  AND c.sequence>:last ORDER BY c.sequence
            """),
                        {
                            "job": job_id,
                            "org": subject.organization_id,
                            "workspace": subject.workspace_id,
                            "last": last,
                        },
                    )
                )
                .mappings()
                .all()
            )
            for row in rows:
                last = row["sequence"]
                emitted_content = True
                yield f"id: {last}\nevent: chunk\ndata: {json.dumps({'content': row['content']})}\n\n"
            terminal = (
                (
                    await db.execute(
                        text("""
                SELECT j.state,r.output FROM ai_generation_jobs j
                LEFT JOIN ai_job_results r ON r.job_id=j.id
                WHERE j.id=:job AND j.organization_id=:org
                  AND j.workspace_id=:workspace
            """),
                        {
                            "job": job_id,
                            "org": subject.organization_id,
                            "workspace": subject.workspace_id,
                        },
                    )
                )
                .mappings()
                .first()
            )
            if terminal is None:
                yield 'event: error\ndata: {"code":"not_found"}\n\n'
                return
            state = terminal["state"]
            if state in {"completed", "failed", "cancelled", "dead_letter"}:
                output = terminal["output"] or {}
                proposal = output.get("proposal") if isinstance(output, dict) else None
                if (
                    state == "completed"
                    and not emitted_content
                    and isinstance(proposal, str)
                ):
                    yield (
                        "id: result\nevent: chunk\ndata: "
                        f"{json.dumps({'content': proposal})}\n\n"
                    )
                yield f"event: terminal\ndata: {json.dumps({'state': state})}\n\n"
                return
            await asyncio.sleep(0.25)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/{job_id}/cancel", status_code=202)
async def cancel(
    job_id: UUID,
    subject: Tenant = Depends(tenant),
    correlation_id: str = Depends(request_context),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    row = (
        (
            await db.execute(
                text("""
        UPDATE ai_generation_jobs SET cancel_requested_at=COALESCE(cancel_requested_at,now()),
          state=CASE WHEN state IN ('queued','retry_wait') THEN 'cancelled' ELSE state END,
          completed_at=CASE WHEN state IN ('queued','retry_wait') THEN now() ELSE completed_at END,
          updated_at=now()
        WHERE id=:job AND organization_id=:org AND workspace_id=:workspace
          AND state NOT IN ('completed','failed','cancelled','dead_letter') RETURNING id,state
    """),
                {
                    "job": job_id,
                    "org": subject.organization_id,
                    "workspace": subject.workspace_id,
                },
            )
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(404, "active job not found")
    await ai_jobs.audit(
        db,
        "job.cancellation_requested",
        correlation_id,
        subject.user_id,
        organization_id=subject.organization_id,
        workspace_id=subject.workspace_id,
        job_id=job_id,
    )
    await db.commit()
    return {"job_id": job_id, "state": row["state"], "cancel_requested": True}
