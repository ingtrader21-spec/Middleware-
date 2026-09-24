from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import cast
from uuid import uuid4
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import tts
from app.api.v1.ai_console import Tenant, tenant
from app.providers.elevenlabs_tts import TTSError, TTSRequest


class FakeProvider:
    def __init__(self, chunks: list[bytes], failure: str | None = None) -> None:
        self.chunks = chunks
        self.failure = failure
        self.request: TTSRequest | None = None
        self.closed = False

    async def stream(self, request: TTSRequest) -> AsyncIterator[bytes]:
        self.request = request
        try:
            for chunk in self.chunks:
                yield chunk
            if self.failure:
                raise TTSError(self.failure)
        finally:
            self.closed = True


def subject(*roles: str) -> Tenant:
    return Tenant(uuid4(), uuid4(), "synthetic-user", frozenset(roles))


def client_for(principal: Tenant) -> TestClient:
    app = FastAPI()
    app.include_router(tts.router)
    app.dependency_overrides[tenant] = lambda: principal
    app.dependency_overrides[tts.get_session] = lambda: AsyncMock()
    return TestClient(app)


def headers(key: str = "synthetic-idempotency-0001") -> dict[str, str]:
    return {"Idempotency-Key": key, "X-Correlation-ID": "synthetic-correlation"}


def payload(**values: object) -> dict[str, object]:
    result: dict[str, object] = {
        "text": "Synthetic TTS request.",
        "voice_profile": "canary",
        "project_key": "codestra-ai-console",
        "output_format": "mp3_44100_128",
    }
    result.update(values)
    return result


@pytest.fixture(autouse=True)
def reset_admission(monkeypatch) -> None:
    tts.admission = tts.Admission()
    tts.provider_readiness_failure = None
    job_id = uuid4()
    monkeypatch.setattr(
        tts.tts_jobs,
        "submit",
        AsyncMock(return_value={"id": job_id, "state": "queued", "created": True}),
    )
    monkeypatch.setattr(
        tts.tts_jobs,
        "claim_exact",
        AsyncMock(return_value={"id": job_id, "fencing_token": 1}),
    )
    for name in (
        "mark_provider_started",
        "record_chunk",
        "mark_ambiguous",
        "mark_cancelled_streaming",
    ):
        monkeypatch.setattr(tts.tts_jobs, name, AsyncMock())
    monkeypatch.setattr(tts.tts_jobs, "complete", AsyncMock(return_value=True))


def configure(
    monkeypatch, *, enabled: bool = True, voice: str = "voice-approved"
) -> None:
    monkeypatch.setattr(tts.settings, "elevenlabs_provider_enabled", enabled)
    monkeypatch.setattr(tts.settings, "elevenlabs_canary_voice_id", voice)
    monkeypatch.setattr(tts.settings, "elevenlabs_max_concurrency", 1)
    monkeypatch.setattr(tts.settings, "elevenlabs_max_text_characters", 1000)
    monkeypatch.setattr(tts.settings, "ai_job_project_allowlist", "codestra-ai-console")
    monkeypatch.setattr(
        type(tts.settings), "elevenlabs_api_key", property(lambda _: "synthetic-key")
    )


def test_disabled_provider_fails_before_provider_call(monkeypatch) -> None:
    configure(monkeypatch, enabled=False)
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(), headers=headers()
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "TTS_TEMPORARILY_UNAVAILABLE"}


def test_enabled_provider_without_voice_fails_readiness(monkeypatch) -> None:
    configure(monkeypatch, voice="")
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(), headers=headers()
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "TTS_VOICE_PROFILE_UNAVAILABLE"}


@pytest.mark.parametrize(
    ("roles", "changes", "status", "detail"),
    [
        (("codestra_ai_developer",), {}, 403, "TTS_ROLE_REQUIRED"),
        (("codestra_admin",), {}, 403, "TTS_ROLE_REQUIRED"),
        (
            ("codestra_ai_user",),
            {"project_key": "other"},
            403,
            "TTS_PROJECT_NOT_APPROVED",
        ),
        (
            ("codestra_ai_user",),
            {"voice_profile": "arbitrary-id"},
            422,
            "TTS_VOICE_PROFILE_UNKNOWN",
        ),
        (
            ("codestra_ai_user",),
            {"output_format": "ulaw_8000"},
            422,
            "TTS_OUTPUT_FORMAT_UNSUPPORTED",
        ),
    ],
)
def test_role_project_voice_and_public_format_are_fail_closed(
    monkeypatch, roles, changes, status, detail
) -> None:
    configure(monkeypatch)
    response = client_for(subject(*roles)).post(
        "/api/v1/ai/tts/stream",
        json=payload(**changes),
        headers=headers(),
    )
    assert response.status_code == status
    assert response.json() == {"detail": detail}


def test_oversized_text_is_rejected(monkeypatch) -> None:
    configure(monkeypatch)
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(text="x" * 1001), headers=headers()
    )
    assert response.status_code == 413


def test_stream_prefetches_audio_and_uses_only_server_voice(monkeypatch) -> None:
    configure(monkeypatch)
    fake = FakeProvider([b"first", b"second"])
    monkeypatch.setattr(tts, "_provider", lambda: fake)
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(), headers=headers()
    )
    assert response.status_code == 200
    assert response.content == b"firstsecond"
    assert response.headers["content-type"].startswith("audio/mpeg")
    assert response.headers["cache-control"] == "no-store"
    assert fake.request is not None
    assert fake.request.voice_id == "voice-approved"
    assert fake.request.model_id == "eleven_flash_v2_5"
    assert fake.request.output_format == "mp3_44100_128"
    assert fake.closed
    assert not tts.admission.global_lock.locked()


def test_durable_idempotent_replay_returns_original_without_provider(
    monkeypatch,
) -> None:
    configure(monkeypatch)
    original = uuid4()
    monkeypatch.setattr(
        tts.tts_jobs,
        "submit",
        AsyncMock(
            return_value={"id": original, "state": "streaming", "created": False}
        ),
    )
    provider = AsyncMock()
    monkeypatch.setattr(tts, "_provider", provider)
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(), headers=headers()
    )
    assert response.status_code == 200
    assert response.json() == {
        "job_id": str(original),
        "state": "streaming",
        "idempotent_replay": True,
    }
    provider.assert_not_called()


def test_zero_byte_and_partial_failure_never_become_false_success(monkeypatch) -> None:
    configure(monkeypatch)
    empty = FakeProvider([], failure="tts_empty_stream")
    monkeypatch.setattr(tts, "_provider", lambda: empty)
    response = client_for(subject("codestra_ai_user")).post(
        "/api/v1/ai/tts/stream", json=payload(), headers=headers("synthetic-empty-0001")
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "tts_empty_stream"}
    assert not tts.admission.global_lock.locked()


@pytest.mark.asyncio
async def test_concurrency_one_and_idempotency_fencing() -> None:
    principal = subject("codestra_ai_user")
    await tts.admission.acquire(
        subject=principal, idempotency_key="tenant:key-one", request_digest="digest-one"
    )
    with pytest.raises(Exception) as occupied:
        await tts.admission.acquire(
            subject=principal,
            idempotency_key="tenant:key-two",
            request_digest="digest-two",
        )
    assert getattr(occupied.value, "status_code", None) == 429
    tts.admission.release()
    await tts.admission.acquire(
        subject=principal,
        idempotency_key="tenant:key-one",
        request_digest="digest-one",
    )
    tts.admission.release()


@pytest.mark.asyncio
async def test_cancellation_closes_upstream_and_releases_capacity(monkeypatch) -> None:
    configure(monkeypatch)
    fake = FakeProvider([b"first", b"second"])
    monkeypatch.setattr(tts, "_provider", lambda: fake)
    principal = subject("codestra_ai_user")
    response = await tts.stream_speech(
        tts.SpeechRequest(
            text="Synthetic TTS request.",
            voice_profile="canary",
            project_key="codestra-ai-console",
            output_format="mp3_44100_128",
        ),
        "synthetic-cancel-0001",
        "synthetic-correlation",
        principal,
        AsyncMock(),
    )
    stream_response = cast(tts.StreamingResponse, response)
    iterator = cast(tts.ClosableAsyncIterator, stream_response.body_iterator)
    assert await anext(iterator) == b"first"
    await iterator.aclose()
    await asyncio.sleep(0)
    assert fake.closed
    assert not tts.admission.global_lock.locked()


def test_metrics_are_content_free_and_named_as_governed() -> None:
    source = __import__("pathlib").Path("app/core/tts_metrics.py").read_text()
    for name in (
        "elevenlabs_tts_requests_total",
        "elevenlabs_tts_failures_total",
        "elevenlabs_tts_active_streams",
        "elevenlabs_tts_rejected_total",
        "elevenlabs_tts_audio_bytes_total",
        "elevenlabs_tts_characters_total",
        "elevenlabs_tts_time_to_first_audio_seconds",
        "elevenlabs_tts_stream_duration_seconds",
        "elevenlabs_tts_provider_status_total",
        "elevenlabs_tts_client_cancellations_total",
    ):
        assert name in source
    for forbidden in ("submitted_text", "voice_id", "xi-api-key", "user_id"):
        assert forbidden not in source
