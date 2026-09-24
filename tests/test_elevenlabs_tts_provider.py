from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator

import httpx
import pytest

from app.providers.elevenlabs_tts import (
    ElevenLabsTTSProvider,
    TTSError,
    TTSRequest,
)


class AudioStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def request() -> TTSRequest:
    return TTSRequest(
        text="Synthetic middleware test.",
        voice_id="synthetic-approved-voice",
        model_id="eleven_flash_v2_5",
        output_format="mp3_44100_128",
    )


def provider(
    client: httpx.AsyncClient,
    *,
    max_retries: int = 0,
    request_logging_mode: str = "standard",
) -> ElevenLabsTTSProvider:
    return ElevenLabsTTSProvider(
        api_key="synthetic-test-key",
        base_url="https://api.elevenlabs.io",
        connect_timeout=1,
        read_timeout=2,
        total_timeout=3,
        max_retries=max_retries,
        request_logging_mode=request_logging_mode,
        client=client,
    )


@pytest.mark.asyncio
async def test_streams_audio_incrementally_with_governed_request() -> None:
    audio = AudioStream([b"one", b"two"])

    def handler(incoming: httpx.Request) -> httpx.Response:
        assert incoming.url.host == "api.elevenlabs.io"
        assert incoming.url.path.endswith("/synthetic-approved-voice/stream")
        assert incoming.url.params["output_format"] == "mp3_44100_128"
        assert "enable_logging" not in incoming.url.params
        assert incoming.headers["xi-api-key"] == "synthetic-test-key"
        assert incoming.headers["accept"] == "audio/mpeg"
        return httpx.Response(200, stream=audio)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        chunks = [chunk async for chunk in provider(client).stream(request())]
    assert chunks == [b"one", b"two"]
    assert audio.closed


@pytest.mark.asyncio
async def test_zero_retention_is_explicit_and_not_default() -> None:
    def handler(incoming: httpx.Request) -> httpx.Response:
        assert incoming.url.params["enable_logging"] == "false"
        return httpx.Response(200, stream=AudioStream([b"audio"]))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        chunks = [
            chunk
            async for chunk in provider(
                client, request_logging_mode="zero_retention"
            ).stream(request())
        ]
    assert chunks == [b"audio"]


@pytest.mark.asyncio
async def test_empty_stream_fails_instead_of_false_success() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, stream=AudioStream([]))
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(TTSError, match="tts_empty_stream"):
            _ = [chunk async for chunk in provider(client).stream(request())]


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (400, "tts_invalid_request", False),
        (401, "tts_authentication_failed", False),
        (403, "tts_permission_denied", False),
        (404, "tts_voice_or_model_not_found", False),
        (422, "tts_invalid_request", False),
        (429, "tts_rate_limited", True),
        (503, "tts_provider_unavailable", True),
    ],
)
@pytest.mark.asyncio
async def test_provider_errors_are_sanitized(
    status: int, code: str, retryable: bool
) -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(status, text="provider-private-error-body")
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(TTSError) as caught:
            _ = [chunk async for chunk in provider(client).stream(request())]
    assert caught.value.code == code
    assert caught.value.retryable is retryable
    assert "provider-private-error-body" not in str(caught.value)


@pytest.mark.asyncio
async def test_never_retries_after_audio_is_emitted(monkeypatch) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1

        async def broken() -> AsyncGenerator[bytes, None]:
            yield b"partial"
            raise httpx.ReadError("synthetic transport failure")

        return httpx.Response(200, stream=BrokenStream(broken()))

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("app.providers.elevenlabs_tts.asyncio.sleep", no_sleep)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TTSError, match="tts_provider_unavailable"):
            _ = [
                chunk
                async for chunk in provider(client, max_retries=2).stream(request())
            ]
    assert calls == 1


@pytest.mark.asyncio
async def test_429_retry_after_is_bounded_and_honored(monkeypatch) -> None:
    calls = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, stream=AudioStream([b"audio"]))

    async def record_sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr("app.providers.elevenlabs_tts.asyncio.sleep", record_sleep)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        chunks = [
            chunk async for chunk in provider(client, max_retries=1).stream(request())
        ]
    assert chunks == [b"audio"]
    assert calls == 2
    assert delays == [3]


@pytest.mark.asyncio
async def test_private_telephony_format_is_provider_capable_but_not_api_exposed() -> (
    None
):
    observed = ""

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal observed
        observed = incoming.url.params["output_format"]
        return httpx.Response(200, stream=AudioStream([b"ulaw"]))

    telephony = request().__class__(
        text="Synthetic telephony path test.",
        voice_id="synthetic-approved-voice",
        model_id="eleven_flash_v2_5",
        output_format="ulaw_8000",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        chunks = [chunk async for chunk in provider(client).stream(telephony)]
    assert chunks == [b"ulaw"]
    assert observed == "ulaw_8000"


class BrokenStream(httpx.AsyncByteStream):
    def __init__(self, iterator: AsyncGenerator[bytes, None]) -> None:
        self.iterator = iterator

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self.iterator

    async def aclose(self) -> None:
        await self.iterator.aclose()
