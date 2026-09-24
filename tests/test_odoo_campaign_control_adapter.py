import httpx
import pytest

from app.adapters.odoo.campaign_control import (
    OdooCampaignAdapterError,
    read_campaign,
)


class FakeOdooClient:
    def __init__(self, response: httpx.Response):
        self.response = response
        self.calls = []

    async def request(self, operation, payload, **kwargs):
        self.calls.append((operation, payload, kwargs))
        return self.response


@pytest.mark.asyncio
async def test_campaign_read_uses_typed_allowlisted_operation():
    client = FakeOdooClient(httpx.Response(200, json={"campaign_public_id": "c-1"}))

    result = await read_campaign(
        client,
        {"campaign_public_id": "c-1"},
        request_id="req-1",
        correlation_id="corr-1",
        traceparent="00-" + ("a" * 32) + "-" + ("b" * 16) + "-01",
    )

    assert result == {"campaign_public_id": "c-1"}
    assert client.calls[0][0] == "campaigns.read"
    assert client.calls[0][2]["idempotency_key"] == "read:c-1"


@pytest.mark.asyncio
async def test_campaign_read_rejects_invalid_upstream_response():
    client = FakeOdooClient(httpx.Response(200, content=b"not-json"))

    with pytest.raises(OdooCampaignAdapterError, match="invalid JSON"):
        await read_campaign(
            client,
            {"campaign_public_id": "c-1"},
            request_id="req-1",
            correlation_id="corr-1",
            traceparent="00-" + ("a" * 32) + "-" + ("b" * 16) + "-01",
        )
