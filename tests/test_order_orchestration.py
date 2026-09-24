import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.order_orchestration import (
    Approval,
    OrderEnvelope,
    OrderStatus,
    OrderStore,
    content_hash,
    validate_for_dispatch,
    verify_body_integrity,
)


def envelope(**overrides) -> OrderEnvelope:
    now = datetime.now(UTC)
    values = {
        "schema_version": "codestra.order.command.v1",
        "command_id": "cmd-test-001",
        "event_id": "event-test-001",
        "order_id": "CODESTRA-INTEGRATION-TEST-ORDER-001",
        "order_type": "shipping_order",
        "source_system": "odoo",
        "organization_id": "org-test",
        "customer_reference": "customer-opaque-001",
        "workflow_code": "CDST-ORDER-SHIPPING-V1",
        "approval": {"required": True, "status": "approved", "content_hash": "0" * 64},
        "payload": {"destination_reference": "warehouse-test"},
        "requested_actions": ["create_fulfillment_task"],
        "constraints": {"synthetic": True},
        "idempotency_key": "CODESTRA-INTEGRATION-TEST-IDEMP-001",
        "correlation_id": "corr-test-001",
        "trace_id": "trace-test-001",
        "requested_at": now,
        "expires_at": now + timedelta(minutes=10),
    }
    values.update(overrides)
    order = OrderEnvelope.model_validate(values)
    order.approval = Approval(status="approved", content_hash=content_hash(order))
    return order


def test_order_lifecycle_and_duplicate_suppression():
    store = OrderStore()
    order = envelope()
    first = store.create(order)
    second = store.create(order)
    assert first["status"] == OrderStatus.APPROVAL_REQUIRED.value
    assert second["duplicate"] is True
    assert len(store.orders) == 1


def test_dispatch_rejects_expired_order():
    expired = datetime.now(UTC) - timedelta(seconds=1)
    order = envelope(
        requested_at=expired - timedelta(minutes=10),
        expires_at=expired,
    )
    with pytest.raises(HTTPException, match="expired"):
        validate_for_dispatch(order)


def test_dispatch_rejects_unknown_workflow_and_blocked_action():
    unknown = envelope(workflow_code="CUSTOMER_TEXT_SELECTED_WORKFLOW")
    with pytest.raises(HTTPException, match="allowlisted"):
        validate_for_dispatch(unknown)
    blocked = envelope(requested_actions=["send_customer_message"])
    with pytest.raises(HTTPException, match="blocked"):
        validate_for_dispatch(blocked)


def test_n8n_exports_have_only_middleware_urls_and_are_inactive():
    root = Path(__file__).parents[1] / "integrations/n8n/approved-orders"
    exports = list(root.glob("CdstOrder*.json"))
    assert len(exports) == 14
    for export in exports:
        text = export.read_text()
        document = json.loads(text)
        assert '"active":false' in text
        assert document["id"].startswith("cdst-order-")
        assert all("position" in node for node in document["nodes"])
        assert "CODESTRA_MIDDLEWARE_BASE_URL" in text
        assert "odoo.com" not in text.lower()
        assert "vicidial" not in text.lower()
        assert "postiz" not in text.lower()


def test_workflow_registry_maps_every_export_and_core_codes():
    import json

    root = Path(__file__).parents[1] / "integrations/n8n/approved-orders"
    registry = json.loads((root / "workflow-registry.json").read_text())
    exports = {json.loads(path.read_text())["name"] for path in root.glob("CdstOrder*.json")}
    entries = registry["workflows"]
    assert len(entries) == len(exports)
    assert {entry["n8n_workflow_id"] for entry in entries} == exports
    assert {entry["workflow_code"] for entry in entries} >= {
        "CDST-ORDER-VALIDATE-V1", "CDST-ORDER-ROUTER-V1", "CDST-ORDER-EXECUTE-V1",
        "CDST-ORDER-RESULT-V1", "CDST-ORDER-FAILURE-V1", "CDST-ORDER-DEAD-LETTER-V1",
        "CDST-ORDER-RECONCILIATION-V1",
    }
    internal = next(entry for entry in entries if entry["workflow_code"] == "CDST-ORDER-INTERNAL-REPORT-V1")
    assert "generate_internal_report" in internal["allowed_actions"]


def test_flags_default_disabled():
    from app.core.config import Settings

    settings = Settings()
    assert settings.order_orchestration_enabled is False
    assert settings.n8n_order_dispatch_enabled is False


def test_modified_body_and_bad_signature_are_rejected(monkeypatch):
    order = envelope()
    from app.core.config import settings
    monkeypatch.setattr(settings, "middleware_secret", "test-secret")
    import hashlib
    import json
    body_hash = hashlib.sha256(json.dumps(order.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(HTTPException, match="signature invalid"):
        verify_body_integrity(order, "1700000000", "nonce-1", "bad", body_hash)
    with pytest.raises(HTTPException, match="body hash mismatch"):
        verify_body_integrity(order, "1700000000", "nonce-1", "bad", "0" * 64)


def test_retry_exhaustion_security_no_retry_dead_letter_and_audit():
    store = OrderStore()
    order = envelope(command_id="cmd-retry-001", order_id="CODESTRA-INTEGRATION-TEST-RETRY-001")
    store.create(order)
    store.command(order.command_id, order.order_id)
    first = store.record_failure(order.command_id, "TEMPORARY_PROVIDER_ERROR", True, max_attempts=2)
    assert first["status"] == OrderStatus.RETRY_SCHEDULED.value
    final = store.record_failure(order.command_id, "TEMPORARY_PROVIDER_ERROR", True, max_attempts=2)
    assert final["status"] == OrderStatus.DEAD_LETTER.value
    security = store.record_failure(order.command_id, "AUTHORIZATION_FAILURE", True, max_attempts=3)
    assert security["status"] == OrderStatus.DEAD_LETTER.value
    assert store.metrics["orders_retried_total"] == 1
    assert store.metrics["orders_dead_lettered_total"] >= 1
    assert store.metrics["security_failure_retry_total"] == 1
    assert {event["event"] for event in store.audit_events} >= {
        "order_received", "command_created", "command_failure"
    }


def test_duplicate_command_and_result_are_canonical():
    store = OrderStore()
    order = envelope(command_id="cmd-dupe-001", order_id="CODESTRA-INTEGRATION-TEST-DUPE-001")
    store.create(order)
    first = store.command(order.command_id, order.order_id)
    second = store.command(order.command_id, order.order_id)
    assert first is second
    store.record_result(order.command_id, "completed")
    store.record_result(order.command_id, "completed")
    assert store.metrics["orders_completed_total"] == 1
    assert sum(event["event"] == "command_created" for event in store.audit_events) == 1


def test_synthetic_internal_report_end_to_end_in_process():
    store = OrderStore()
    order = envelope(
        command_id="cmd-report-001",
        order_id="CODESTRA-INTEGRATION-TEST-ORDER-001",
        workflow_code="CDST-ORDER-INTERNAL-REPORT-V1",
        requested_actions=["generate_internal_report"],
    )
    store.create(order)
    duplicate = store.create(order)
    assert duplicate["duplicate"] is True
    command = store.command(order.command_id, order.order_id)
    assert command["workflow_code"] == "CDST-ORDER-INTERNAL-REPORT-V1"
    store.record_result(order.command_id, "completed")
    assert store.get(order.order_id)["status"] == OrderStatus.COMPLETED.value
    assert store.metrics["orders_received_total"] == 1
    assert any(event["event"] == "command_result" for event in store.audit_events)
