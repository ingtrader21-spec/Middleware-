from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock
from app.core.config import Settings
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.commands import CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.main import create_app
from app.odoo_provider_adapter import OdooProviderAdapter, OdooProviderAdapterError
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore
from app.temporal_workflows import ActivityResult, CommandExecutionRequest


ROOT = Path(__file__).resolve().parents[1]
HMAC_VECTOR = json.loads(
    (ROOT / "contracts" / "odoo-hmac-test-vector.v1.json").read_text(
        encoding="utf-8"
    )
)


class N8nTokenVerifier:
    async def verify(
        self,
        authorization: str,
        *,
        expected_client_id: str,
        required_scope: str,
    ) -> dict[str, Any]:
        assert expected_client_id == "n8n-automation"
        if authorization != f"Bearer {required_scope}":
            from app.security import AuthenticationError

            raise AuthenticationError("invalid n8n token")
        return {
            "azp": "n8n-automation",
            "scope": required_scope,
            "aud": "middleware-api",
            "tenant_id": "tenant-1",
            "sub": "n8n-service-subject",
        }

    async def ready(self) -> bool:
        return True


def _policy() -> CommandPolicyRegistry:
    return CommandPolicyRegistry(
        (
            CommandPolicy(
                prefix="crm.",
                target="odoo-19",
                capability="ODOO_WRITE",
                readback_required=True,
            ),
        ),
        {"ODOO_WRITE": True},
    )


def _payload(source_record_id: str = "lead-platform-control-plane") -> dict[str, Any]:
    return {
        "lead_source": "synthetic-form",
        "source_record_id": source_record_id,
        "initial_stage": "review_pending",
        "review_required": True,
        "allow_external_contact": False,
        "provenance": {
            "method": "submitted_by_person",
            "captured_by": "test-suite",
            "source_reference": "synthetic://platform-control-plane",
            "legal_basis": "unknown_review_required",
            "content_digest": "a" * 64,
        },
        "consent": {
            "status": "unknown",
            "captured_at": "2026-08-30T16:00:00+00:00",
            "policy_version": "test-v1",
            "channels": {"email": False, "sms": False, "phone": False},
        },
        "lead": {
            "name": "CODESTRA-INTEGRATION-TEST-Lead",
            "description": "Synthetic integration test only.",
            "contact": {
                "name": "Synthetic Contact",
                "email": "synthetic@example.invalid",
                "phone": "+18095550199",
                "preferred_language": "en",
            },
            "company": {
                "name": "Synthetic Company",
                "domain": "example.invalid",
                "industry": "Testing",
            },
            "campaign_code": None,
            "tags": [],
        },
    }


def _body() -> dict[str, Any]:
    return {
        "command_id": str(uuid4()),
        "command_type": "crm.lead.upsert",
        "command_version": "1.0",
        "target": "odoo-19",
        "tenant_id": "tenant-1",
        "requested_by": "n8n-service-subject",
        "correlation_id": "corr-platform-control-plane",
        "idempotency_key": "idem-platform-control-plane",
        "capability": "ODOO_WRITE",
        "payload": _payload(),
    }


def test_legacy_n8n_control_plane_submit_and_status_remain_tenant_scoped(
    test_settings,
) -> None:
    settings = test_settings.replace(umbrella_n8n_external_provider_writes=True)
    runtime = Runtime(
        settings=settings,
        inbox=MemoryInboxStore(),
        replay=MemoryReplayGuard(),
        tokens=N8nTokenVerifier(),
        commands=CommandService(MemoryCommandStore(), _policy()),
    )
    body = _body()
    # The deprecated /v1/integrations/n8n/* aliases exist only on the monolith.
    app = create_app(settings=settings, runtime=runtime, legacy_monolith=True)
    with TestClient(app) as client:
        submitted = client.post(
            "/v1/integrations/n8n/commands",
            json=body,
            headers={
                "Authorization": "Bearer middleware.request.forward",
                "X-Tenant-ID": body["tenant_id"],
                "X-Correlation-ID": body["correlation_id"],
                "Idempotency-Key": body["idempotency_key"],
            },
        )
        assert submitted.status_code == 202, submitted.text
        assert submitted.headers["deprecation"] == "true"
        assert submitted.headers["location"] == (
            f"/v1/integrations/n8n/operations/{body['command_id']}"
        )
        assert "/v2/automation/commands" in submitted.headers["link"]
        status = client.get(
            f"/v1/integrations/n8n/operations/{body['command_id']}",
            headers={
                "Authorization": "Bearer middleware.status.read",
                "X-Tenant-ID": "tenant-1",
            },
        )
        assert status.status_code == 200, status.text
        assert status.json()["state"] == "persisted"
        assert status.headers["deprecation"] == "true"


def _request(command_type: str = "crm.lead.upsert") -> CommandExecutionRequest:
    return CommandExecutionRequest(
        command_id="00000000-0000-4000-8000-000000000001",
        command_type=command_type,
        command_version="1.0",
        target="odoo-19",
        tenant_id="tenant-1",
        requested_by="n8n-service-subject",
        correlation_id="corr-platform-control-plane",
        idempotency_key="idem-platform-control-plane",
        capability="ODOO_WRITE",
        payload=_payload(),
        authenticated_client_id="n8n-automation",
    )


def _adapter() -> OdooProviderAdapter:
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": True},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": True},
        odoo_source_delivery_enabled=lambda method: method == "submitted_by_person",
    )
    return OdooProviderAdapter(
        settings,
        {
            "ODOO_INTEGRATION_BASE_URL": "http://odoo.test",
            "ODOO_INBOUND_HMAC_SECRET": "test-secret-not-production",
        },
    )


def test_odoo_adapter_fails_closed_when_write_capability_is_off() -> None:
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": False},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": True},
        odoo_source_delivery_enabled=lambda method: False,
    )
    adapter = OdooProviderAdapter(settings, {})
    with pytest.raises(OdooProviderAdapterError, match="ODOO_WRITE is disabled"):
        adapter._require_active(_request())


def test_odoo_adapter_rechecks_n8n_kill_switch_at_execution() -> None:
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": True},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": False},
        odoo_source_delivery_enabled=lambda method: method == "submitted_by_person",
    )
    adapter = OdooProviderAdapter(settings, {})
    with pytest.raises(
        OdooProviderAdapterError,
        match="N8N_EXTERNAL_PROVIDER_WRITES is disabled",
    ):
        adapter._require_active(_request())

    adapter._require_active(
        replace(_request(), authenticated_client_id="moneybee-backend")
    )


def test_odoo_adapter_rejects_legacy_workflow_without_client_provenance() -> None:
    with pytest.raises(
        OdooProviderAdapterError,
        match="authenticated client provenance is missing or invalid",
    ):
        _adapter()._require_active(
            replace(_request(), authenticated_client_id="")
        )


def test_odoo_adapter_enforces_canonical_source_gate_on_legacy_temporal_rows() -> None:
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": True},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": True},
        odoo_source_delivery_enabled=lambda method: method == "submitted_by_person",
    )
    adapter = OdooProviderAdapter(settings, {})
    crawler = replace(
        _request(),
        payload={**_payload(), "provenance": {"method": "crawler_discovery"}},
    )
    with pytest.raises(OdooProviderAdapterError, match="source-scoped delivery"):
        adapter._require_active(crawler)


def test_odoo_readback_identity_validation_does_not_require_write_gate() -> None:
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": False},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": True},
        odoo_source_delivery_enabled=lambda method: False,
    )
    adapter = OdooProviderAdapter(settings, {})
    adapter._validate_identity(_request())


def test_odoo_adapter_maps_only_canonical_crm_upsert() -> None:
    adapter = _adapter()
    method, path, document = adapter._write_request(_request())
    assert method == "POST"
    assert path == "/codestra/middleware/v1/commands/crm.lead.upsert"
    assert document["command_type"] == "crm.lead.upsert"
    assert document["command_version"] == "1.0"
    assert document["payload"]["source_record_id"] == "lead-platform-control-plane"
    assert adapter.STATUS_PATH.format(command_id="command-id") == (
        "/codestra/middleware/v1/commands/command-id/status"
    )

    with pytest.raises(OdooProviderAdapterError, match="unsupported Odoo command type"):
        adapter._require_active(_request("crm.lead.create.v1"))


def test_odoo_adapter_validates_complete_specialized_payload_before_dispatch() -> None:
    adapter = _adapter()
    malformed = replace(
        _request(),
        payload={"source_record_id": "source-only"},
    )
    with pytest.raises(
        OdooProviderAdapterError,
        match="canonical Odoo command rejected payload",
    ):
        adapter._write_request(malformed)


def test_odoo_adapter_accepts_schema_maximum_source_record_id() -> None:
    adapter = _adapter()
    maximum = replace(_request(), payload=_payload("x" * 255))
    _, _, document = adapter._write_request(maximum)
    assert document["payload"]["source_record_id"] == "x" * 255

    too_long = replace(_request(), payload=_payload("x" * 256))
    with pytest.raises(OdooProviderAdapterError, match="canonical Odoo command rejected"):
        adapter._write_request(too_long)


def test_odoo_adapter_reconciles_timeout_before_returning(monkeypatch) -> None:
    adapter = _adapter()
    reconciled: list[str] = []

    class TimeoutClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def request(self, *args, **kwargs):
            raise httpx.ReadTimeout("synthetic timeout")

    async def matched(request: CommandExecutionRequest) -> ActivityResult:
        reconciled.append(request.command_id)
        return ActivityResult(
            status="matched",
            detail="synthetic status match",
            provider_operation_id=request.command_id,
        )

    monkeypatch.setattr(
        "app.odoo_provider_adapter.httpx.AsyncClient",
        lambda timeout: TimeoutClient(),
    )
    monkeypatch.setattr(adapter, "readback", matched)

    result = asyncio.run(adapter.execute(_request()))
    assert result.status == "accepted"
    assert reconciled == [_request().command_id]
    assert "reconciliation confirmed" in result.detail


def test_odoo_adapter_keeps_timeout_unknown_when_status_mismatches(monkeypatch) -> None:
    adapter = _adapter()

    class TimeoutClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def request(self, *args, **kwargs):
            raise httpx.ReadTimeout("synthetic timeout")

    async def mismatch(request: CommandExecutionRequest) -> ActivityResult:
        return ActivityResult(
            status="mismatch",
            detail="synthetic status mismatch",
            provider_operation_id=request.command_id,
        )

    monkeypatch.setattr(
        "app.odoo_provider_adapter.httpx.AsyncClient",
        lambda timeout: TimeoutClient(),
    )
    monkeypatch.setattr(adapter, "readback", mismatch)

    with pytest.raises(OdooProviderAdapterError, match="remains unknown"):
        asyncio.run(adapter.execute(_request()))


def test_odoo_hmac_matches_cross_repository_golden_vector() -> None:
    document = json.loads(HMAC_VECTOR["body_utf8"])
    settings = Mock(spec=Settings,
        app_env="test",
        external_effects={"ODOO_WRITE": True},
        umbrella_controls={"N8N_EXTERNAL_PROVIDER_WRITES": True},
        odoo_source_delivery_enabled=lambda method: method == "submitted_by_person",
    )
    adapter = OdooProviderAdapter(
        settings,
        {
            "ODOO_INTEGRATION_BASE_URL": "http://odoo.test",
            "ODOO_INBOUND_HMAC_SECRET": HMAC_VECTOR["secret"],
        },
    )
    request = CommandExecutionRequest(
        command_id=document["command_id"],
        command_type=document["command_type"],
        command_version=document["command_version"],
        target=document["target"],
        tenant_id=document["tenant_id"],
        requested_by=document["requested_by"],
        correlation_id=document["correlation_id"],
        idempotency_key=document["idempotency_key"],
        capability=document["capability"],
        payload=document["payload"],
        authenticated_client_id="n8n-automation",
    )
    body = adapter._canonical_body(document)
    assert body.decode("utf-8") == HMAC_VECTOR["body_utf8"]
    headers = adapter._headers(
        method=HMAC_VECTOR["method"],
        path=HMAC_VECTOR["path"],
        body=body,
        request=request,
        timestamp=HMAC_VECTOR["timestamp"],
    )
    assert headers["X-Codestra-Signature"] == (
        "sha256=" + HMAC_VECTOR["expected_hmac_sha256_hex"]
    )
    assert headers["X-Tenant-ID"] == document["tenant_id"]
    assert headers["X-Correlation-ID"] == document["correlation_id"]
    assert headers["Idempotency-Key"] == document["idempotency_key"]
