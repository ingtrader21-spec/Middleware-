import hashlib
import hmac
import json

import httpx
import pytest
from pydantic import ValidationError

from app.recording.odoo import OdooRecordingClient

SECRET = "runtime-secret-from-secret-provider"
RECORDING_UID = "REC-" + "a" * 32


def acknowledgement():
    return {
        "contract_version": "1.0",
        "recording_uid": RECORDING_UID,
        "odoo_record_id": 42,
        "call_link_status": "linked",
        "lead_link_status": "not_present",
        "campaign_link_status": "linked",
        "agent_link_status": "linked",
        "storage_status": "verified",
        "retention_class": "synthetic_test",
        "retention_until": "2026-08-07T00:00:00+00:00",
        "legal_hold": False,
        "updated_at": "2026-07-31T00:00:01+00:00",
    }


def metadata():
    return {
        "contract_version": "1.0",
        "environment": "staging",
        "recording_uid": RECORDING_UID,
        "storage_status": "verified",
        "retention_class": "synthetic_test",
        "retention_until": "2026-08-07T00:00:00+00:00",
        "legal_hold": False,
    }


@pytest.mark.asyncio
async def test_odoo_hmac_headers_canonical_body_hash_and_no_bearer_fallback():
    observed_nonces = set()

    def handler(request: httpx.Request) -> httpx.Response:
        headers = request.headers
        assert "authorization" not in headers
        assert headers["x-service-identity"] == "codestra-middleware"
        assert headers["x-service-audience"] == "codestra-odoo-recording-api"
        assert headers["x-codestra-environment"] == "staging"
        body_hash = hashlib.sha256(request.content).hexdigest()
        assert headers["x-codestra-content-sha256"] == body_hash
        nonce = headers["x-codestra-nonce"]
        assert nonce not in observed_nonces
        observed_nonces.add(nonce)
        canonical = "\n".join(
            (
                request.method,
                request.url.path,
                headers["x-codestra-timestamp"],
                nonce,
                headers["idempotency-key"],
                body_hash,
            )
        ).encode()
        expected = hmac.new(SECRET.encode(), canonical, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected, headers["x-codestra-signature"])
        assert json.loads(request.content) == metadata()
        return httpx.Response(200, json=acknowledgement())

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = OdooRecordingClient(
            "https://odoo.invalid",
            SECRET,
            "staging",
            http_client,
            clock=lambda: 1_800_000_000,
        )
        first = await client.upsert(metadata(), "i" * 64)
        second = await client.upsert(metadata(), "i" * 64)
    assert first == second
    assert len(observed_nonces) == 2
    assert "acknowledged" not in first


@pytest.mark.asyncio
async def test_noncanonical_odoo_acknowledgement_is_rejected():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"acknowledged": True, "recording_uid": RECORDING_UID},
        )
    )
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = OdooRecordingClient(
            "https://odoo.invalid", SECRET, "staging", http_client
        )
        with pytest.raises(ValidationError):
            await client.upsert(metadata(), "i" * 64)
