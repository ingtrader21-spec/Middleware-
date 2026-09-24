from __future__ import annotations

from typing import Any
from unittest.mock import Mock
from app.commands import CommandService
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore


class N8nTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        assert expected_client_id == "n8n-automation"
        assert required_scope == "middleware.request.forward"
        assert authorization == "Bearer middleware.request.forward"
        return {
            "azp": "n8n-automation",
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "tenant-1",
            "sub": "n8n-service-subject",
        }

    async def ready(self) -> bool:
        return True


class RejectIfSubmitted:
    def __init__(self) -> None:
        self.called = False

    async def submit(self, *args, **kwargs):
        self.called = True
        raise AssertionError("malformed Odoo command reached durable acceptance")


def test_malformed_odoo_payload_is_rejected_before_submit(test_settings) -> None:
    commands = RejectIfSubmitted()
    runtime = Runtime(
        settings=test_settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=N8nTokenVerifier(),
        commands=Mock(spec=CommandService, wraps=commands),
    )
    body = {
        "command_id": str(uuid4()),
        "command_type": "crm.lead.upsert",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "n8n-service-subject",
        "correlation_id": "corr-malformed-odoo",
        "idempotency_key": "idem-malformed-odoo",
        "capability": "ODOO_WRITE",
        "payload": {"source_record_id": "source-only"},
    }
    # The deprecated /v1/integrations/n8n/commands alias exists only on the monolith.
    app = create_app(settings=test_settings, runtime=runtime, legacy_monolith=True)
    with TestClient(app) as client:
        response = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers={
                "Authorization": "Bearer middleware.request.forward",
                "X-Tenant-ID": str(body["tenant_id"]),
                "X-Correlation-ID": str(body["correlation_id"]),
                "Idempotency-Key": str(body["idempotency_key"]),
            },
        )
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "invalid_request"
    assert commands.called is False
