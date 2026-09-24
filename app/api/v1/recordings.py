from __future__ import annotations

import hmac
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import settings
from app.recording.domain import RecordingConflict, RecordingNotFound
from app.recording.odoo import AcknowledgingOdooClient
from app.recording.security import (
    AuthenticationError,
    ExporterIdentity,
    MTLSAuthorizer,
    ReplayGuard,
)
from app.recording.service import RecordingService
from app.recording.storage import MemoryObjectStorage

router = APIRouter(prefix="/api/v1/recordings", tags=["recordings"])

# Runtime composition must replace both adapters. Defaults perform no network or file IO.
recording_service = RecordingService(MemoryObjectStorage(), AcknowledgingOdooClient())
exporter_authorizer = MTLSAuthorizer(
    {"codestra-recording-exporter-server-b": "staging"}
)
exporter_replay_guard = ReplayGuard()


def require_exporter_mtls(
    identity: Annotated[str, Header(alias="X-TLS-Client-Identity")] = "",
    environment: Annotated[str, Header(alias="X-Certificate-Environment")] = "",
    role: Annotated[str, Header(alias="X-Certificate-Role")] = "",
    audience: Annotated[str, Header(alias="X-Audience")] = "",
    not_after: Annotated[str, Header(alias="X-TLS-Client-Not-After")] = "",
    revoked: Annotated[str, Header(alias="X-TLS-Client-Revoked")] = "true",
    nonce: Annotated[str, Header(alias="X-Request-Nonce")] = "",
    timestamp: Annotated[str, Header(alias="X-Request-Timestamp")] = "",
) -> str:
    try:
        expiry = datetime.fromisoformat(not_after)
        exporter_authorizer.authorize(
            ExporterIdentity(
                identity, environment, role, audience, expiry, revoked != "false"
            )
        )
        exporter_replay_guard.consume(nonce, int(timestamp))
        return environment
    except (AuthenticationError, ValueError, TypeError) as exc:
        raise HTTPException(401, "exporter mTLS binding rejected") from exc


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReservationRecording(StrictModel):
    contract_version: Literal["1.0"]
    vicidial_recording_id: str = Field(pattern=r"^[0-9]+$")
    vicidial_call_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    asterisk_uniqueid: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    campaign_key: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    agent_key: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    started_at: str
    duration_seconds: float = Field(ge=0)
    format: Literal["mp3", "wav", "gsm"]
    codec: str = Field(pattern=r"^[A-Za-z0-9._-]{1,32}$")
    channels: int = Field(ge=1, le=2)
    sample_rate_hz: int = Field(ge=8000, le=192000)
    file_size_bytes: int = Field(gt=0, le=5_000_000_000)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: Literal["staging", "production"]
    retention_class: Literal[
        "synthetic_test", "standard", "high_compliance", "legal_hold"
    ]


class ReservationRequest(StrictModel):
    contract_version: Literal["1.0"]
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    recording: ReservationRecording


class CompletionRequest(StrictModel):
    contract_version: Literal["1.0"]
    recording_uid: str = Field(pattern=r"^REC-[0-9a-f]{32}$")
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: Literal["staging", "production"]
    campaign_key: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_size_bytes: int = Field(gt=0)
    format: Literal["mp3", "wav", "gsm"]
    duration_seconds: float = Field(ge=0)


class FailureRequest(StrictModel):
    code: str = Field(min_length=1, max_length=64)


class PlaybackRequest(StrictModel):
    requester_type: Literal["odoo", "approved_application"]
    user_level: int = Field(ge=8, le=9)
    campaign_authorized: bool
    group_authorized: bool
    ttl_seconds: int = Field(default=120, ge=1, le=120)


class AutomationResultRequest(StrictModel):
    idempotency_key: str = Field(min_length=16, max_length=255)
    result: dict[str, object]


class ReservationResponse(StrictModel):
    contract_version: Literal["1.0"]
    recording_uid: str = Field(pattern=r"^REC-[0-9a-f]{32}$")
    upload_url: str
    upload_url_expires_at: datetime
    required_checksum_header: Literal["x-amz-checksum-sha256"]
    required_content_type: Literal["audio/mpeg", "audio/wav", "audio/gsm"]
    opaque_object_identifier: str


class RecordingStateResponse(StrictModel):
    contract_version: Literal["1.0"]
    recording_uid: str = Field(pattern=r"^REC-[0-9a-f]{32}$")
    state: Literal[
        "RESERVATION_CREATED",
        "UPLOADING",
        "UPLOADED",
        "SERVER_VERIFIED",
        "ODOO_LINKED",
        "QUARANTINED",
        "FAILED",
    ]
    checksum_verified: bool
    odoo_linked: bool
    failure_code: str | None = None


class RecordingMutationResponse(RecordingStateResponse):
    duplicate: bool


class PlaybackResponse(StrictModel):
    playback_url: str
    expires_in: int = Field(ge=1, le=120)


class AutomationResultResponse(StrictModel):
    accepted: Literal[True]
    duplicate: bool


def require_internal_service_auth(
    authorization: Annotated[str, Header(alias="Authorization")] = "",
    environment: Annotated[str, Header(alias="X-Codestra-Environment")] = "",
) -> str:
    expected = f"Bearer {settings.middleware_secret}"
    if (
        not settings.middleware_secret
        or not hmac.compare_digest(authorization, expected)
        or environment not in {"staging", "production"}
    ):
        raise HTTPException(401, "recording environment binding required")
    return environment


def _assert_environment(recording_uid: str, environment: str) -> None:
    try:
        recording = recording_service.get(recording_uid)
    except RecordingNotFound as exc:
        raise _translate(exc) from exc
    if recording.environment != environment:
        raise HTTPException(403, "recording environment binding rejected")


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, RecordingNotFound):
        return HTTPException(404, "recording not found")
    if isinstance(exc, PermissionError):
        return HTTPException(403, str(exc))
    return HTTPException(409, str(exc))


@router.post("/reservations", status_code=201, response_model=ReservationResponse)
async def reserve(
    payload: ReservationRequest,
    certificate_environment: str = Depends(require_exporter_mtls),
):
    if payload.recording.environment != certificate_environment:
        raise HTTPException(403, "recording environment binding rejected")
    return recording_service.reserve(payload.model_dump())


@router.post("/{recording_uid}/complete", response_model=RecordingMutationResponse)
async def complete(
    recording_uid: str,
    payload: CompletionRequest,
    certificate_environment: str = Depends(require_exporter_mtls),
):
    try:
        if payload.environment != certificate_environment:
            raise HTTPException(403, "recording environment binding rejected")
        if payload.recording_uid != recording_uid:
            raise RecordingConflict("path and payload recording_uid differ")
        return await recording_service.complete(recording_uid, payload.model_dump())
    except (RecordingConflict, RecordingNotFound, KeyError, OSError) as exc:
        raise _translate(exc) from exc


@router.post("/{recording_uid}/failure", response_model=RecordingMutationResponse)
async def failure(
    recording_uid: str,
    payload: FailureRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    certificate_environment: str = Depends(require_exporter_mtls),
):
    try:
        _assert_environment(recording_uid, certificate_environment)
        return recording_service.failure(recording_uid, payload.code, idempotency_key)
    except (RecordingConflict, RecordingNotFound) as exc:
        raise _translate(exc) from exc


@router.get("/{recording_uid}", response_model=RecordingStateResponse)
async def status(
    recording_uid: str,
    environment: str = Depends(require_internal_service_auth),
):
    try:
        recording = recording_service.get(recording_uid)
        _assert_environment(recording_uid, environment)
    except RecordingNotFound as exc:
        raise _translate(exc) from exc
    return {
        "contract_version": "1.0",
        "recording_uid": recording.recording_uid,
        "state": recording.state.value,
        "checksum_verified": recording.verified_at is not None,
        "odoo_linked": recording.odoo_linked_at is not None,
        "failure_code": recording.failure_code,
    }


@router.post("/{recording_uid}/playback-url", response_model=PlaybackResponse)
async def playback_url(
    recording_uid: str,
    payload: PlaybackRequest,
    response: Response,
    service_identity: str = Header(default="", alias="X-Service-Identity"),
    environment: str = Depends(require_internal_service_auth),
):
    authorized_service = service_identity in {
        "codestra-odoo",
        "codestra-approved-recording-application",
    }
    scope = (
        authorized_service
        and payload.campaign_authorized
        and (payload.user_level == 9 or payload.group_authorized)
    )
    try:
        _assert_environment(recording_uid, environment)
        body = recording_service.playback_url(
            recording_uid,
            scope_authorized=scope,
            ttl_seconds=payload.ttl_seconds,
        )
    except (RecordingNotFound, PermissionError) as exc:
        raise _translate(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    return body


@router.post(
    "/{recording_uid}/automation-result",
    response_model=AutomationResultResponse,
)
async def automation_result(
    recording_uid: str,
    payload: AutomationResultRequest,
    environment: str = Depends(require_internal_service_auth),
):
    try:
        _assert_environment(recording_uid, environment)
        return recording_service.automation_result(
            recording_uid, payload.idempotency_key, payload.result
        )
    except (RecordingConflict, RecordingNotFound) as exc:
        raise _translate(exc) from exc
