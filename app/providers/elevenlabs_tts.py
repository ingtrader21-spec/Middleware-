"""Governed ElevenLabs streaming text-to-speech adapter."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from app.core.ai_provider import CircuitBreaker
from app.core.tts_metrics import PROVIDER_STATUS

TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
STATUS_CODES = {
    400: "tts_invalid_request",
    401: "tts_authentication_failed",
    403: "tts_permission_denied",
    404: "tts_voice_or_model_not_found",
    422: "tts_invalid_request",
    429: "tts_rate_limited",
}
MAX_AUDIO_CHUNK_BYTES = 64 * 1024


class TTSError(RuntimeError):
    def __init__(
        self, code: str, *, retryable: bool = False, retry_after: float | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class TTSRequest:
    text: str
    voice_id: str
    model_id: str
    output_format: str


class ElevenLabsTTSProvider:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        connect_timeout: float,
        read_timeout: float,
        total_timeout: float,
        max_retries: int,
        request_logging_mode: str,
        client: httpx.AsyncClient | None = None,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        if not api_key or not api_key.isascii() or any(c.isspace() for c in api_key):
            raise ValueError("ElevenLabs API key is unavailable")
        if base_url != "https://api.elevenlabs.io":
            raise ValueError("ElevenLabs host is not approved")
        self._key = api_key
        self._base_url = base_url
        self._timeout = httpx.Timeout(
            total_timeout, connect=connect_timeout, read=read_timeout
        )
        self._max_retries = max_retries
        self._request_logging_mode = request_logging_mode
        self._client = client
        self._breaker = breaker or CircuitBreaker()

    async def stream(self, request: TTSRequest) -> AsyncIterator[bytes]:
        if not self._breaker.allow():
            raise TTSError("tts_circuit_open", retryable=True)
        for attempt in range(self._max_retries + 1):
            emitted = False
            try:
                async for chunk in self._stream_once(request):
                    emitted = True
                    yield chunk
                if not emitted:
                    raise TTSError("tts_empty_stream")
                self._breaker.succeeded()
                return
            except TTSError as exc:
                self._breaker.failed()
                if emitted or not exc.retryable or attempt >= self._max_retries:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else 2**attempt
                await asyncio.sleep(min(max(delay, 0), 30))
        raise TTSError("tts_retry_exhausted", retryable=True)

    async def _stream_once(self, request: TTSRequest) -> AsyncIterator[bytes]:
        owned_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self._timeout)
        params: dict[str, str] = {"output_format": request.output_format}
        if self._request_logging_mode == "zero_retention":
            params["enable_logging"] = "false"
        try:
            async with client.stream(
                "POST",
                f"{self._base_url}/v1/text-to-speech/{request.voice_id}/stream",
                headers={
                    "xi-api-key": self._key,
                    "Content-Type": "application/json",
                    "Accept": "audio/mpeg",
                },
                params=params,
                json={"text": request.text, "model_id": request.model_id},
            ) as response:
                PROVIDER_STATUS.labels(str(response.status_code)).inc()
                if response.status_code >= 400:
                    code = STATUS_CODES.get(response.status_code)
                    if code is None:
                        code = (
                            "tts_provider_unavailable"
                            if response.status_code in TRANSIENT_STATUS
                            else "tts_request_rejected"
                        )
                    retry_after = None
                    if response.status_code == 429:
                        try:
                            retry_after = float(response.headers.get("retry-after", ""))
                        except ValueError:
                            retry_after = None
                    raise TTSError(
                        code,
                        retryable=response.status_code in TRANSIENT_STATUS,
                        retry_after=retry_after,
                    )
                async for chunk in response.aiter_raw():
                    for offset in range(0, len(chunk), MAX_AUDIO_CHUNK_BYTES):
                        bounded = chunk[offset : offset + MAX_AUDIO_CHUNK_BYTES]
                        if bounded:
                            yield bounded
        except httpx.TimeoutException as exc:
            raise TTSError("tts_timeout", retryable=True) from exc
        except httpx.TransportError as exc:
            raise TTSError("tts_provider_unavailable", retryable=True) from exc
        finally:
            if owned_client:
                await client.aclose()
