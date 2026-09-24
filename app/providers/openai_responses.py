"""OpenAI Responses API adapter with bounded retries and streaming."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator

import httpx

from app.core.ai_provider import AIProviderError, CircuitBreaker, ProviderEvent
from app.core.ai_provider import ProviderRequest

TRANSIENT_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})
STATUS_ERROR_CODES = {
    400: "provider_bad_request",
    401: "provider_authentication_failed",
    403: "provider_permission_denied",
    404: "provider_model_not_found",
    429: "provider_rate_limited",
}
SAFE_PROVIDER_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
STREAM_ERROR_CODES = {
    "invalid_api_key": "provider_authentication_failed",
    "model_not_found": "provider_model_not_found",
    "insufficient_quota": "provider_quota_exceeded",
    "rate_limit_exceeded": "provider_rate_limited",
}


def _safe_provider_value(value: object) -> str | None:
    if isinstance(value, str) and SAFE_PROVIDER_VALUE.fullmatch(value):
        return value
    return None


class OpenAIResponsesProvider:
    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float,
        max_retries: int,
        client: httpx.AsyncClient | None = None,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        if not api_key or "\n" in api_key or "\r" in api_key:
            raise ValueError("OpenAI API key is unavailable")
        self._key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._client = client
        self._breaker = breaker or CircuitBreaker()

    async def stream(self, request: ProviderRequest) -> AsyncIterator[ProviderEvent]:
        if not self._breaker.allow():
            raise AIProviderError("provider_circuit_open", retryable=True)
        for attempt in range(self._max_retries + 1):
            emitted = False
            try:
                async for event in self._stream_once(request):
                    emitted = emitted or event.kind == "delta"
                    yield event
                self._breaker.succeeded()
                return
            except AIProviderError as exc:
                self._breaker.failed()
                if emitted or not exc.retryable or attempt >= self._max_retries:
                    raise
                await asyncio.sleep(min(2**attempt, 4))
        raise AIProviderError("provider_retry_exhausted", retryable=True)

    async def _stream_once(
        self, request: ProviderRequest
    ) -> AsyncIterator[ProviderEvent]:
        owned_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout, connect=10.0)
        )
        try:
            async with client.stream(
                "POST",
                "https://api.openai.com/v1/responses",
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": request.model,
                    "reasoning": {"effort": request.reasoning_effort},
                    "input": request.input_text,
                    "max_output_tokens": request.max_output_tokens,
                    "safety_identifier": request.safety_identifier,
                    "store": False,
                    "stream": True,
                },
            ) as response:
                request_id = _safe_provider_value(response.headers.get("x-request-id"))
                if response.status_code >= 400:
                    code = STATUS_ERROR_CODES.get(response.status_code)
                    if code is None:
                        code = (
                            "provider_transient_error"
                            if response.status_code in TRANSIENT_STATUS
                            else "provider_request_rejected"
                        )
                    raise AIProviderError(
                        code,
                        retryable=response.status_code in TRANSIENT_STATUS,
                        http_status=response.status_code,
                        request_id=request_id,
                    )
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    value = line[5:].strip()
                    if not value or value == "[DONE]":
                        continue
                    try:
                        event = json.loads(value)
                    except json.JSONDecodeError as exc:
                        raise AIProviderError("provider_invalid_stream") from exc
                    event_type = event.get("type")
                    if event_type == "response.created":
                        continue
                    if event_type == "response.output_text.delta":
                        delta = event.get("delta")
                        if isinstance(delta, str) and delta:
                            yield ProviderEvent(kind="delta", delta=delta)
                    elif event_type == "response.completed":
                        usage = (event.get("response") or {}).get("usage") or {}
                        yield ProviderEvent(
                            kind="completed",
                            input_tokens=max(int(usage.get("input_tokens", 0)), 0),
                            output_tokens=max(int(usage.get("output_tokens", 0)), 0),
                        )
                    elif event_type in {"response.failed", "response.incomplete"}:
                        raise AIProviderError("provider_generation_failed")
                    elif event_type == "error":
                        error = event.get("error")
                        raw_code = event.get("code")
                        if isinstance(error, dict):
                            raw_code = error.get("code", raw_code)
                        provider_code = _safe_provider_value(raw_code)
                        code = STREAM_ERROR_CODES.get(
                            provider_code or "", "provider_stream_error"
                        )
                        raise AIProviderError(
                            code,
                            retryable=provider_code == "rate_limit_exceeded",
                            http_status=response.status_code,
                            provider_error_code=provider_code,
                            request_id=request_id,
                        )
        except httpx.TimeoutException as exc:
            raise AIProviderError("provider_timeout", retryable=True) from exc
        except httpx.TransportError as exc:
            raise AIProviderError("provider_unavailable", retryable=True) from exc
        finally:
            if owned_client:
                await client.aclose()
