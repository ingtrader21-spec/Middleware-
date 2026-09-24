import hashlib

import httpx
import pytest

from app.core.endpoint_registry import ResolutionRequest
from app.core.service_client import CommonServiceClient, canonical_json
from tests.test_endpoint_registry import endpoint


class Resolver:
    async def resolve(self, request):
        value = endpoint()
        if request.service_key == "identity":
            return type(value)(
                **{
                    **value.__dict__,
                    "service_key": "identity",
                    "endpoint_key": "oauth.token",
                    "base_url": "https://identity.invalid",
                    "path": "/token",
                }
            )
        return value


class TokenManager:
    async def get_token(self, http, **kwargs):
        assert kwargs["token_url"] == "https://identity.invalid/token"
        return "issued-access-token"


@pytest.mark.asyncio
async def test_common_client_preserves_idempotency_hash_and_trace_context():
    observed = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["request"] = request
        return httpx.Response(201, json={"persisted": True})

    client = CommonServiceClient(
        Resolver(),
        TokenManager(),
        token_endpoint_key=ResolutionRequest("production", "identity", "oauth.token"),
        transport=httpx.MockTransport(handler),
    )
    payload = {"b": 2, "a": 1}
    try:
        response = await client.request(
            ResolutionRequest("production", "n8n", "events.ingest", mutation=True),
            payload,
            idempotency_key="IDM-fixed",
            request_id="REQ-fixed",
            correlation_id="COR-fixed",
            causation_id="CAU-fixed",
            traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
        )
    finally:
        await client.aclose()
    assert response.status_code == 201
    request = observed["request"]
    assert request.headers["Idempotency-Key"] == "IDM-fixed"
    assert (
        request.headers["X-Codestra-Body-SHA256"]
        == hashlib.sha256(canonical_json(payload)).hexdigest()
    )
    assert request.headers["traceparent"].startswith("00-")
    assert request.headers["Authorization"] == "Bearer issued-access-token"


@pytest.mark.asyncio
async def test_common_client_rejects_redirect():
    client = CommonServiceClient(
        Resolver(),
        TokenManager(),
        token_endpoint_key=ResolutionRequest("production", "identity", "oauth.token"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(307, headers={"location": "https://other/"})
        ),
    )
    try:
        with pytest.raises(RuntimeError, match="redirect rejected"):
            await client.request(
                ResolutionRequest("production", "n8n", "events.ingest", mutation=True),
                {},
                idempotency_key="IDM",
                request_id="REQ",
                correlation_id="COR",
                causation_id="CAU",
                traceparent="00-" + "1" * 32 + "-" + "2" * 16 + "-01",
            )
    finally:
        await client.aclose()


def test_common_client_binds_explicit_private_ca(monkeypatch, tmp_path):
    observed = {}

    class Client:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def aclose(self):
            return None

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    ca = tmp_path / "internal-ca.crt"
    ca.write_text("test certificate bytes")
    CommonServiceClient(
        Resolver(),
        TokenManager(),
        token_endpoint_key=ResolutionRequest("production", "identity", "oauth.token"),
        verify=str(ca),
    )
    assert observed["verify"] == str(ca)
    assert observed["follow_redirects"] is False
    assert observed["trust_env"] is False
