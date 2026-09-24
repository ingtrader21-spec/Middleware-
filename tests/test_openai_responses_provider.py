from __future__ import annotations

import json

import httpx
import pytest

from app.core.ai_provider import CircuitBreaker, ProviderRequest
from app.core.ai_provider import AIProviderError
from app.core.ai_provider import redact_provider_input, safety_identifier
from app.providers.openai_responses import OpenAIResponsesProvider


def request() -> ProviderRequest:
    return ProviderRequest(
        model="gpt-5.6-terra",
        reasoning_effort="low",
        input_text="synthetic prompt",
        safety_identifier="a" * 64,
        max_output_tokens=128,
    )


@pytest.mark.asyncio
async def test_responses_stream_is_store_false_and_incremental() -> None:
    observed = {}

    def handler(value: httpx.Request) -> httpx.Response:
        observed["authorization"] = value.headers["Authorization"]
        observed["body"] = json.loads(value.content)
        return httpx.Response(
            200,
            text=(
                'data: {"type":"response.created","response":{"id":"synthetic"}}\n\n'
                'data: {"type":"response.output_text.delta","delta":"Codestra "}\n\n'
                'data: {"type":"response.output_text.delta","delta":"AI"}\n\n'
                'data: {"type":"response.completed","response":{"usage":'
                '{"input_tokens":4,"output_tokens":2}}}\n\n'
                "data: [DONE]\n\n"
            ),
            headers={"content-type": "text/event-stream"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        events = [event async for event in provider.stream(request())]
    assert [event.delta for event in events if event.kind == "delta"] == [
        "Codestra ",
        "AI",
    ]
    assert events[-1].input_tokens == 4 and events[-1].output_tokens == 2
    assert observed["authorization"] == "Bearer test-only-key"
    assert observed["body"] == {
        "model": "gpt-5.6-terra",
        "reasoning": {"effort": "low"},
        "input": "synthetic prompt",
        "max_output_tokens": 128,
        "safety_identifier": "a" * 64,
        "store": False,
        "stream": True,
    }


@pytest.mark.asyncio
async def test_transient_failure_retries_before_any_output(monkeypatch) -> None:
    calls = 0

    def handler(_value: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503)
        return httpx.Response(
            200,
            text=(
                'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
                'data: {"type":"response.completed","response":{"usage":{}}}\n\n'
            ),
        )

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr("app.providers.openai_responses.asyncio.sleep", no_wait)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=1,
            client=client,
        )
        events = [event async for event in provider.stream(request())]
    assert calls == 2
    assert events[0].delta == "ok"


@pytest.mark.asyncio
async def test_stream_failure_event_is_fail_closed() -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='data: {"type":"response.failed"}\n\n',
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        with pytest.raises(AIProviderError, match="provider_generation_failed"):
            _ = [event async for event in provider.stream(request())]


@pytest.mark.asyncio
async def test_stream_error_event_is_fail_closed() -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='data: {"type":"error"}\n\n')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        with pytest.raises(AIProviderError, match="provider_stream_error"):
            _ = [event async for event in provider.stream(request())]


@pytest.mark.asyncio
async def test_pre_chunk_stream_error_preserves_only_sanitized_diagnostics() -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=(
                'data: {"type":"response.created","response":{"id":"ignored"}}\n\n'
                'data: {"type":"error","error":{"code":"model_not_found",'
                '"message":"must not be retained","param":"model"}}\n\n'
            ),
            headers={"x-request-id": "req_safe-123"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        with pytest.raises(AIProviderError) as caught:
            _ = [event async for event in provider.stream(request())]

    assert caught.value.code == "provider_model_not_found"
    assert caught.value.safe_details() == {
        "component": "openai-responses",
        "http_status": 200,
        "provider_error_code": "model_not_found",
        "provider_request_id": "req_safe-123",
    }
    assert "message" not in repr(caught.value.safe_details())


@pytest.mark.asyncio
async def test_stream_error_rejects_untrusted_diagnostic_values() -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='data: {"type":"error","code":"bad code with secret"}\n\n',
            headers={"x-request-id": "unsafe request id"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        with pytest.raises(AIProviderError) as caught:
            _ = [event async for event in provider.stream(request())]

    assert caught.value.code == "provider_stream_error"
    assert caught.value.safe_details() == {
        "component": "openai-responses",
        "http_status": 200,
    }


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (400, "provider_bad_request", False),
        (401, "provider_authentication_failed", False),
        (403, "provider_permission_denied", False),
        (404, "provider_model_not_found", False),
        (429, "provider_rate_limited", True),
    ],
)
@pytest.mark.asyncio
async def test_http_errors_map_to_governed_codes(
    status: int, code: str, retryable: bool
) -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(status)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        with pytest.raises(AIProviderError) as caught:
            _ = [event async for event in provider.stream(request())]
    assert caught.value.code == code
    assert caught.value.retryable is retryable


@pytest.mark.asyncio
async def test_no_chunk_stream_has_no_false_delta() -> None:
    def handler(_value: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=(
                'data: {"type":"response.completed","response":{"usage":{}}}\n\n'
                "data: [DONE]\n\n"
            ),
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAIResponsesProvider(
            api_key="test-only-key",
            timeout_seconds=10,
            max_retries=0,
            client=client,
        )
        events = [event async for event in provider.stream(request())]
    assert [event for event in events if event.kind == "delta"] == []


def test_identity_redaction_and_circuit_breaker_are_fail_closed(monkeypatch) -> None:
    assert redact_provider_input("password=hunter2 sk-secretfixture123") == (
        "[REDACTED] [REDACTED]"
    )
    first = safety_identifier("user-1", b"a" * 32)
    assert first == safety_identifier("user-1", b"a" * 32)
    assert first != safety_identifier("user-2", b"a" * 32)
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=30)
    breaker.failed()
    assert breaker.allow()
    breaker.failed()
    assert not breaker.allow()
