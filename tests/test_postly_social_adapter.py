from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest

from app.core.config import ConfigurationError
from app.postly_social_adapter import (
    PostlySocialAdapter,
    PostlySocialAdapterError,
    PostlySocialUnknownOutcomeError,
)
from app.temporal_workflows import CommandExecutionRequest

BASE_URL = "https://postly.internal.invalid"
API_KEY = "synthetic-postly-api-key-0123456789ab"
TENANT = "tenant-1"
ACCOUNT = "integration-42"

ENV = {
    "POSTLY_SOCIAL_BASE_URL": BASE_URL,
    "POSTLY_SOCIAL_API_KEY": API_KEY,
}


class StubSettings:
    def __init__(self, *, app_env: str = "staging", social_enabled: bool = True) -> None:
        self.app_env = app_env
        self.social_publishing_enabled = social_enabled


def execution_request(**overrides: Any) -> CommandExecutionRequest:
    identity = str(uuid4())
    payload: dict[str, Any] = {
        "publication_id": str(uuid4()),
        "channel": "social",
        "account_reference": ACCOUNT,
        "content": {"text": "Launch day."},
        "scheduled_at": None,
        "client_reference": f"ref-{identity}",
    }
    payload.update(overrides.pop("payload_overrides", {}))
    fields: dict[str, Any] = {
        "command_id": identity,
        "command_type": "social.publication.publish.v1",
        "command_version": "1.0",
        "target": "postly-social",
        "tenant_id": TENANT,
        "requested_by": "codestra-social",
        "correlation_id": f"correlation-{identity}",
        "idempotency_key": f"idempotency-{identity}",
        "capability": "SOCIAL_PUBLISH",
        "payload": payload,
        "authenticated_client_id": "codestra-social",
    }
    fields.update(overrides)
    return CommandExecutionRequest(**fields)


@pytest.fixture(autouse=True)
def _mock_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    original = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(_mock_httpx.handler)  # type: ignore[attr-defined]
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def set_handler(handler: Any) -> None:
    _mock_httpx.handler = handler  # type: ignore[attr-defined]


def adapter(**kwargs: Any) -> PostlySocialAdapter:
    return PostlySocialAdapter(
        StubSettings(**kwargs.pop("settings", {})),  # type: ignore[arg-type]
        env=kwargs.pop("env", ENV),
    )


def listing(command_id: str, **overrides: Any) -> dict[str, Any]:
    post = {
        "id": "post-1",
        "group": command_id,
        "state": "PUBLISHED",
        "releaseURL": "https://social.example/post-1",
        "integration": {"id": ACCOUNT},
    }
    post.update(overrides)
    return {"posts": [post]}


@pytest.mark.asyncio
async def test_publish_sends_the_command_id_as_the_correlation_group() -> None:
    seen: dict[str, Any] = {}
    command = execution_request()

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"id": "post-1"})

    set_handler(handler)
    result = await adapter().execute(command)

    assert result.status == "accepted"
    assert result.provider_operation_id == "post-1"
    assert seen["request"].headers["authorization"] == API_KEY
    assert f'"group":"{command.command_id}"' in seen["body"].replace(" ", "")
    assert f'"id":"{ACCOUNT}"' in seen["body"].replace(" ", "")


@pytest.mark.asyncio
async def test_publish_is_refused_while_the_capability_is_closed() -> None:
    set_handler(lambda request: httpx.Response(200, json={"id": "post-1"}))
    with pytest.raises(PostlySocialAdapterError, match="social publishing is disabled"):
        await adapter(settings={"social_enabled": False}).execute(execution_request())


@pytest.mark.asyncio
async def test_publish_rejects_commands_it_does_not_own() -> None:
    set_handler(lambda request: httpx.Response(200, json={}))
    with pytest.raises(PostlySocialAdapterError, match="does not own"):
        await adapter().execute(execution_request(target="klyrow-email"))
    with pytest.raises(PostlySocialAdapterError, match="capability"):
        await adapter().execute(execution_request(capability="EMAIL_DELIVERY"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"content": {"text": ""}}, "canonical contract"),
        ({"account_reference": ""}, "canonical contract"),
        ({"channel": "sms"}, "canonical contract"),
        ({"provider_token": "leaked"}, "forbidden secret keys"),
    ],
)
async def test_payload_validation_is_fail_closed(
    overrides: dict[str, Any], match: str
) -> None:
    set_handler(lambda request: httpx.Response(200, json={}))
    with pytest.raises(PostlySocialAdapterError, match=match):
        await adapter().execute(execution_request(payload_overrides=overrides))


@pytest.mark.asyncio
async def test_connection_failure_before_send_is_safely_retryable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    set_handler(handler)
    # A retryable error type, not the non-retryable unknown outcome: nothing
    # can have been published if the connection never opened.
    with pytest.raises(PostlySocialAdapterError, match="before the publication"):
        await adapter().execute(execution_request())


@pytest.mark.asyncio
async def test_interrupted_publish_never_reposts_and_resolves_by_readback() -> None:
    command = execution_request()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=listing(command.command_id))

    set_handler(handler)
    result = await adapter().execute(command)

    assert result.status == "accepted"
    assert result.provider_operation_id == "post-1"
    # Exactly one POST, then a GET. A second POST would risk a duplicate post.
    assert [call.method for call in calls] == ["POST", "GET"]
    assert calls.count(calls[0]) == 1


@pytest.mark.asyncio
async def test_unresolvable_publish_is_non_retryable_and_demands_reconciliation() -> None:
    command = execution_request()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json={"posts": []})

    set_handler(handler)
    with pytest.raises(PostlySocialUnknownOutcomeError, match="reconcile"):
        await adapter().execute(command)


@pytest.mark.asyncio
async def test_gateway_5xx_is_treated_as_unknown_not_failure() -> None:
    command = execution_request()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(502, json={"msg": "bad gateway"})
        return httpx.Response(200, json=listing(command.command_id))

    set_handler(handler)
    result = await adapter().execute(command)
    assert result.status == "accepted"
    assert calls == ["POST", "GET"]


@pytest.mark.asyncio
async def test_client_rejection_is_a_deterministic_failure() -> None:
    set_handler(
        lambda request: httpx.Response(400, json={"msg": "post is too long"})
    )
    with pytest.raises(PostlySocialAdapterError, match="post is too long"):
        await adapter().execute(execution_request())


@pytest.mark.asyncio
async def test_readback_rejects_a_publication_on_the_wrong_account() -> None:
    command = execution_request()
    set_handler(
        lambda request: httpx.Response(
            200,
            json=listing(command.command_id, integration={"id": "someone-else"}),
        )
    )
    result = await adapter().readback(command)
    assert result.status == "mismatch"
    assert "different" in result.detail


@pytest.mark.asyncio
async def test_readback_rejects_a_state_that_does_not_prove_publication() -> None:
    command = execution_request()
    set_handler(
        lambda request: httpx.Response(
            200, json=listing(command.command_id, state="ERROR")
        )
    )
    result = await adapter().readback(command)
    assert result.status == "mismatch"
    assert "ERROR" in result.detail


@pytest.mark.asyncio
async def test_readback_ignores_posts_from_other_commands() -> None:
    command = execution_request()
    set_handler(lambda request: httpx.Response(200, json=listing("another-command")))
    result = await adapter().readback(command)
    assert result.status == "mismatch"
    assert "did not find" in result.detail


@pytest.mark.asyncio
async def test_readback_window_brackets_a_scheduled_publication() -> None:
    seen: dict[str, Any] = {}
    command = execution_request(
        payload_overrides={"scheduled_at": "2026-09-10T12:00:00+00:00"}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(200, json={"posts": []})

    set_handler(handler)
    await adapter().readback(command)
    assert seen["params"]["startDate"].startswith("2026-09-08")
    assert seen["params"]["endDate"].startswith("2026-09-12")


@pytest.mark.asyncio
async def test_production_requires_https() -> None:
    set_handler(lambda request: httpx.Response(200, json={}))
    insecure = dict(ENV, POSTLY_SOCIAL_BASE_URL="http://postly.internal.invalid")
    with pytest.raises(ConfigurationError, match="requires HTTPS"):
        await adapter(
            settings={"app_env": "production"}, env=insecure
        ).execute(execution_request())


@pytest.mark.asyncio
async def test_unknown_outcome_reaches_temporal_as_non_retryable() -> None:
    """The retry policy must never re-drive an ambiguous social publish."""
    from temporalio.exceptions import ApplicationError

    from app.temporal_activities import CommandLedgerWorkflowActivities

    command = execution_request()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json={"posts": []})

    set_handler(handler)
    activities = CommandLedgerWorkflowActivities(
        store=None,  # type: ignore[arg-type]
        postly_social=adapter(),
    )
    with pytest.raises(ApplicationError) as caught:
        await activities.execute_command(command)
    assert caught.value.non_retryable is True
    assert caught.value.type == "ProviderOutcomeUnknown"


@pytest.mark.asyncio
async def test_deterministic_rejection_stays_retryable_in_temporal() -> None:
    """A provider validation error is a different class from an unknown outcome."""
    from temporalio.exceptions import ApplicationError

    from app.temporal_activities import CommandLedgerWorkflowActivities

    set_handler(lambda request: httpx.Response(400, json={"msg": "post is too long"}))
    activities = CommandLedgerWorkflowActivities(
        store=None,  # type: ignore[arg-type]
        postly_social=adapter(),
    )
    with pytest.raises(ApplicationError) as caught:
        await activities.execute_command(execution_request())
    assert caught.value.type == "ProviderAdapterError"
