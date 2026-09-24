"""Authenticated, tenant-bound streaming text-to-speech API."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from typing import Annotated, Protocol, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai_console import StrictModel, Tenant, tenant
from app.core import ai_jobs, tts_jobs
from app.core.config import settings
from app.core.tts_metrics import ACTIVE_STREAMS, AUDIO_BYTES, CHARACTERS
from app.core.tts_metrics import CLIENT_CANCELLATIONS, FAILURES, REJECTED, REQUESTS
from app.core.tts_metrics import STREAM_DURATION, TIME_TO_FIRST_AUDIO
from app.providers.elevenlabs_tts import (
    ElevenLabsTTSProvider,
    TTSError,
    TTSRequest,
)
from app.db.session import get_session

APPROVED_PROJECT = "codestra-ai-console"
APPROVED_PROFILE = "canary"
CONTENT_TYPES = {"mp3_44100_128": "audio/mpeg"}
USER_REQUESTS_PER_MINUTE = 10
TENANT_REQUESTS_PER_MINUTE = 20


class ClosableAsyncIterator(Protocol):
    def __aiter__(self) -> AsyncIterator[bytes]: ...

    async def __anext__(self) -> bytes: ...

    async def aclose(self) -> None: ...


class SpeechRequest(StrictModel):
    text: str = Field(min_length=1)
    voice_profile: str = Field(min_length=1, max_length=64)
    project_key: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    output_format: str = "mp3_44100_128"


class Admission:
    def __init__(self) -> None:
        self.global_lock = asyncio.Lock()
        self.guard = asyncio.Lock()
        self.user_windows: dict[str, deque[float]] = defaultdict(deque)
        self.tenant_windows: dict[str, deque[float]] = defaultdict(deque)

    async def acquire(
        self, *, subject: Tenant, idempotency_key: str, request_digest: str
    ) -> None:
        now = time.monotonic()
        async with self.guard:
            user_key = f"{subject.organization_id}:{subject.user_id}"
            tenant_key = str(subject.organization_id)
            self._check_window(
                self.user_windows[user_key], now, USER_REQUESTS_PER_MINUTE
            )
            self._check_window(
                self.tenant_windows[tenant_key], now, TENANT_REQUESTS_PER_MINUTE
            )
            if self.global_lock.locked():
                raise HTTPException(429, "tts_capacity_exhausted")
            await self.global_lock.acquire()
            self.user_windows[user_key].append(now)
            self.tenant_windows[tenant_key].append(now)

    @staticmethod
    def _check_window(window: deque[float], now: float, limit: int) -> None:
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= limit:
            raise HTTPException(429, "tts_rate_limit_exceeded")

    def release(self) -> None:
        if self.global_lock.locked():
            self.global_lock.release()


admission = Admission()
provider_readiness_failure: str | None = None
router = APIRouter(
    prefix="/api/v1/ai/tts", tags=["ai-tts"], dependencies=[Depends(tenant)]
)


def _voice_profiles() -> dict[str, str]:
    voice_id = settings.elevenlabs_canary_voice_id.strip()
    return {APPROVED_PROFILE: voice_id} if voice_id else {}


def validate_readiness() -> None:
    if not settings.elevenlabs_provider_enabled:
        raise HTTPException(503, "TTS_TEMPORARILY_UNAVAILABLE")
    if settings.elevenlabs_max_concurrency != 1:
        raise HTTPException(503, "TTS_CONFIGURATION_INVALID")
    if provider_readiness_failure is not None:
        raise HTTPException(503, "TTS_PROVIDER_NOT_READY")
    if not _voice_profiles():
        raise HTTPException(503, "TTS_VOICE_PROFILE_UNAVAILABLE")
    try:
        settings.elevenlabs_api_key
    except ValueError as exc:
        raise HTTPException(503, "TTS_CREDENTIAL_UNAVAILABLE") from exc


def _request_digest(subject: Tenant, body: SpeechRequest) -> str:
    canonical = "\n".join(
        (
            str(subject.organization_id),
            str(subject.workspace_id),
            subject.user_id,
            body.project_key,
            body.voice_profile,
            body.output_format,
            body.text,
        )
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _provider() -> ElevenLabsTTSProvider:
    return ElevenLabsTTSProvider(
        api_key=settings.elevenlabs_api_key,
        base_url=settings.elevenlabs_base_url,
        connect_timeout=settings.elevenlabs_connect_timeout_seconds,
        read_timeout=settings.elevenlabs_read_timeout_seconds,
        total_timeout=settings.elevenlabs_total_timeout_seconds,
        max_retries=settings.elevenlabs_max_retries,
        request_logging_mode=settings.elevenlabs_request_logging_mode,
    )


@router.get("/jobs/{job_id}")
async def job_status(
    job_id: UUID,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    try:
        return await tts_jobs.status(
            db,
            job_id,
            subject.organization_id,
            subject.workspace_id,
            subject.user_id,
        )
    except LookupError as exc:
        raise HTTPException(404, "TTS_JOB_NOT_FOUND") from exc


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: UUID,
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    try:
        state = await tts_jobs.cancel(
            db,
            job_id,
            subject.organization_id,
            subject.workspace_id,
            subject.user_id,
        )
    except LookupError as exc:
        raise HTTPException(404, "TTS_JOB_NOT_FOUND_OR_TERMINAL") from exc
    return {"job_id": str(job_id), "state": state}


@router.post("/stream", response_model=None)
async def stream_speech(
    body: SpeechRequest,
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=16, max_length=255)
    ],
    correlation_id: Annotated[
        str, Header(alias="X-Correlation-ID", min_length=1, max_length=128)
    ],
    subject: Tenant = Depends(tenant),
    db: AsyncSession = Depends(get_session),
) -> StreamingResponse | JSONResponse:
    validate_readiness()
    if "codestra_ai_user" not in subject.roles:
        REJECTED.labels("role").inc()
        raise HTTPException(403, "TTS_ROLE_REQUIRED")
    allowed_projects = {
        item.strip()
        for item in settings.ai_job_project_allowlist.split(",")
        if item.strip()
    }
    if body.project_key != APPROVED_PROJECT or body.project_key not in allowed_projects:
        REJECTED.labels("project").inc()
        raise HTTPException(403, "TTS_PROJECT_NOT_APPROVED")
    profiles = _voice_profiles()
    voice_id = profiles.get(body.voice_profile)
    if voice_id is None:
        REJECTED.labels("voice_profile").inc()
        raise HTTPException(422, "TTS_VOICE_PROFILE_UNKNOWN")
    if body.output_format not in CONTENT_TYPES:
        REJECTED.labels("output_format").inc()
        raise HTTPException(422, "TTS_OUTPUT_FORMAT_UNSUPPORTED")
    if len(body.text) > settings.elevenlabs_max_text_characters:
        REJECTED.labels("text_limit").inc()
        raise HTTPException(413, "TTS_TEXT_LIMIT_EXCEEDED")

    started = time.monotonic()
    digest = _request_digest(subject, body)
    try:
        durable = await tts_jobs.submit(
            db,
            organization_id=subject.organization_id,
            workspace_id=subject.workspace_id,
            requested_by=subject.user_id,
            project_key=body.project_key,
            voice_alias=body.voice_profile,
            model_alias=settings.elevenlabs_model_id,
            output_profile=body.output_format,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            request_sha256=digest,
            character_count=len(body.text),
        )
    except ValueError as exc:
        raise HTTPException(409, "TTS_IDEMPOTENCY_CONFLICT") from exc
    except Exception as exc:
        raise HTTPException(503, "TTS_QUEUE_UNAVAILABLE") from exc
    if not durable["created"]:
        return JSONResponse(
            {
                "job_id": str(durable["id"]),
                "state": durable["state"],
                "idempotent_replay": True,
            }
        )
    try:
        await admission.acquire(
            subject=subject,
            idempotency_key=(
                f"{subject.organization_id}:{subject.user_id}:{idempotency_key}"
            ),
            request_digest=digest,
        )
    except HTTPException:
        await tts_jobs.cancel(
            db,
            durable["id"],
            subject.organization_id,
            subject.workspace_id,
            subject.user_id,
        )
        raise
    worker_id = "elevenlabs-inline-01"
    claimed = await tts_jobs.claim_exact(db, durable["id"], worker_id, 60)
    if claimed is None:
        admission.release()
        raise HTTPException(409, "TTS_JOB_NOT_CLAIMABLE")
    try:
        await ai_jobs.audit(
            db,
            "tts.stream.accepted",
            correlation_id,
            subject.user_id,
            organization_id=subject.organization_id,
            workspace_id=subject.workspace_id,
            details={
                "project": APPROVED_PROJECT,
                "voice_profile": APPROVED_PROFILE,
                "model": settings.elevenlabs_model_id,
                "character_count": len(body.text),
            },
        )
        await db.commit()
    except Exception as exc:
        admission.release()
        REJECTED.labels("audit_unavailable").inc()
        raise HTTPException(503, "TTS_AUDIT_UNAVAILABLE") from exc
    ACTIVE_STREAMS.inc()
    REQUESTS.labels("accepted").inc()
    CHARACTERS.inc(len(body.text))
    iterator = cast(
        ClosableAsyncIterator,
        _provider().stream(
            TTSRequest(
                text=body.text,
                voice_id=voice_id,
                model_id=settings.elevenlabs_model_id,
                output_format=body.output_format,
            )
        ),
    )
    await tts_jobs.mark_provider_started(
        db, claimed["id"], worker_id, claimed["fencing_token"]
    )
    try:
        first_chunk = await anext(iterator)
    except (StopAsyncIteration, TTSError) as exc:
        global provider_readiness_failure
        await iterator.aclose()
        admission.release()
        code = exc.code if isinstance(exc, TTSError) else "tts_empty_stream"
        await tts_jobs.mark_ambiguous(
            db, claimed["id"], worker_id, claimed["fencing_token"], code
        )
        if code in {
            "tts_authentication_failed",
            "tts_permission_denied",
            "tts_voice_or_model_not_found",
        }:
            provider_readiness_failure = code
        ACTIVE_STREAMS.dec()
        FAILURES.labels(code).inc()
        status = 429 if code == "tts_rate_limited" else 503
        raise HTTPException(status, code) from exc
    await tts_jobs.record_chunk(
        db, claimed["id"], worker_id, claimed["fencing_token"], len(first_chunk)
    )
    TIME_TO_FIRST_AUDIO.observe(time.monotonic() - started)

    async def audio() -> AsyncIterator[bytes]:
        complete = False
        try:
            AUDIO_BYTES.inc(len(first_chunk))
            yield first_chunk
            async for chunk in iterator:
                await tts_jobs.record_chunk(
                    db,
                    claimed["id"],
                    worker_id,
                    claimed["fencing_token"],
                    len(chunk),
                )
                AUDIO_BYTES.inc(len(chunk))
                yield chunk
            if not await tts_jobs.complete(
                db, claimed["id"], worker_id, claimed["fencing_token"]
            ):
                raise TTSError("tts_completion_fence_rejected")
            complete = True
            REQUESTS.labels("completed").inc()
        except asyncio.CancelledError:
            await tts_jobs.mark_cancelled_streaming(
                db, claimed["id"], worker_id, claimed["fencing_token"]
            )
            CLIENT_CANCELLATIONS.inc()
            raise
        except TTSError as exc:
            await tts_jobs.mark_ambiguous(
                db, claimed["id"], worker_id, claimed["fencing_token"], exc.code
            )
            FAILURES.labels(exc.code).inc()
            raise
        finally:
            await iterator.aclose()
            admission.release()
            ACTIVE_STREAMS.dec()
            STREAM_DURATION.observe(time.monotonic() - started)
            if not complete:
                REQUESTS.labels("incomplete").inc()

    return StreamingResponse(
        audio(),
        media_type=CONTENT_TYPES[body.output_format],
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Codestra-TTS-Job-ID": str(claimed["id"]),
        },
    )
