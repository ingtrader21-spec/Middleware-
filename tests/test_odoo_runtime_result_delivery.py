import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
from sqlalchemy.dialects import postgresql

from app.adapters.odoo.results import (
    STALE_LEASE_MARGIN_SECONDS,
    OdooResultError,
    _build_odoo_client,
    _record_delivery_failure,
    deliver_result,
    recover_stale_result_deliveries,
    stale_recovery_statements,
)
from app.core.config import settings
from app.core.endpoint_registry import ResolutionDenied
from app.db.models import (
    IntegrationEvent,
    N8nRuntimeExecution,
    N8nRuntimeResult,
    OdooResultDelivery,
)


EXECUTION_ID = UUID("11111111-1111-1111-1111-111111111111")
RESULT_ID = UUID("22222222-2222-2222-2222-222222222222")
DELIVERY_ID = UUID("33333333-3333-3333-3333-333333333333")
PUBLIC_ID = UUID("44444444-4444-4444-4444-444444444444")


def configure_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "environment": "staging",
        "test_syn_odoo_result_delivery_enabled": True,
        "test_syn_odoo_event_type": "test.synthetic.requested",
        "test_syn_odoo_event_id": "TEST_SYN_EVENT_001",
        "test_syn_odoo_correlation_id": "TEST_SYN_CORRELATION_001",
        "test_syn_odoo_organization_public_id": "ORG-TEST-SYN",
        "test_syn_odoo_business_unit_public_id": "BU-TEST-SYN",
        "test_syn_odoo_campaign_public_id": "CAMPAIGN-TEST-SYN",
        "test_syn_odoo_outbox_public_id": "OUTBOX-TEST-SYN",
    }
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)


def records():
    execution = N8nRuntimeExecution(
        execution_id=EXECUTION_ID,
        tenant_id="TEST_SYN_TENANT",
        event_id="TEST_SYN_EVENT_001",
        event_type="test.synthetic.requested",
        source_event_id="TEST_SYN_SOURCE_001",
        workflow_code="TEST_SYN_ROUTER",
        workflow_version="1",
        correlation_id="TEST_SYN_CORRELATION_001",
        causation_id="TEST_SYN_CAUSATION_001",
        trace_id="0123456789abcdef0123456789abcdef",
        idempotency_key_hash="a" * 64,
        payload_hash="b" * 64,
        payload_json={"synthetic": True},
        status="COMPLETED",
        timeout_at=datetime.now(UTC),
    )
    runtime_result = N8nRuntimeResult(
        result_id=RESULT_ID,
        execution_id=EXECUTION_ID,
        tenant_id="TEST_SYN_TENANT",
        workflow_code="TEST_SYN_ROUTER",
        result_hash="c" * 64,
        status="COMPLETED",
        result_json={
            "schema_version": "codestra.n8n.result.v1",
            "status": "completed",
            "result": {"synthetic": True, "event_id": "TEST_SYN_EVENT_001"},
        },
        occurred_at=datetime.now(UTC),
        persisted_at=datetime.now(UTC),
    )
    delivery = OdooResultDelivery(
        result_delivery_id=DELIVERY_ID,
        runtime_result_id=RESULT_ID,
        result_public_id=PUBLIC_ID,
        originating_outbox_public_id="OUTBOX-TEST-SYN",
        request_hash="d" * 64,
        status="PENDING",
        attempts=0,
    )
    return execution, runtime_result, delivery


class SequenceClient:
    def __init__(
        self,
        responses: list[httpx.Response | Exception],
        operation: str = "results.create",
    ) -> None:
        self.responses = responses
        self.operation = operation

    async def request(self, operation, payload, **kwargs):
        assert operation == self.operation
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        return None


def session_for(execution, runtime_result, delivery):
    session = AsyncMock()

    async def get(model, identity, **kwargs):
        if model is OdooResultDelivery and identity == DELIVERY_ID:
            return delivery
        if model is N8nRuntimeResult and identity == RESULT_ID:
            return runtime_result
        if model is N8nRuntimeExecution and identity == EXECUTION_ID:
            return execution
        return None

    session.get.side_effect = get
    session.scalar.return_value = None
    return session


def accepted_response(execution) -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "persisted": True,
            "idempotency_status": "NEW",
            "result_public_id": str(PUBLIC_ID),
            "correlation_id": execution.correlation_id,
        },
    )


def recovery_session(
    slowest_route_ms: int | None, rowcounts: list[int]
) -> tuple[AsyncMock, list]:
    """Fake session recording the recovery UPDATEs; scalar() answers the registry max."""
    session = AsyncMock()
    session.scalar.return_value = slowest_route_ms
    executed: list = []

    async def execute(statement):
        executed.append(statement)
        result = MagicMock()
        result.rowcount = rowcounts[len(executed) - 1]
        return result

    session.execute.side_effect = execute
    return session, executed


def compiled_sql(statement) -> tuple[str, dict]:
    compiled = statement.compile(dialect=postgresql.dialect())
    return str(compiled), dict(compiled.params)


def test_runtime_odoo_client_fails_closed_without_internal_ca(monkeypatch, tmp_path):
    secret = tmp_path / "client-secret"
    secret.write_text("s" * 64)
    secret.chmod(0o600)
    monkeypatch.setattr(settings, "odoo_results_client_secret_file", str(secret))
    monkeypatch.setattr(settings, "odoo_results_ca_file", "")
    with pytest.raises(OdooResultError, match="internal CA"):
        _build_odoo_client(AsyncMock(), {"organization_public_id": "ORG"})


def test_runtime_odoo_client_rejects_world_writable_internal_ca(monkeypatch, tmp_path):
    secret = tmp_path / "client-secret"
    secret.write_text("s" * 64)
    secret.chmod(0o600)
    ca = tmp_path / "ca.crt"
    ca.write_text("certificate")
    ca.chmod(0o666)
    monkeypatch.setattr(settings, "odoo_results_client_secret_file", str(secret))
    monkeypatch.setattr(settings, "odoo_results_ca_file", str(ca))
    with pytest.raises(OdooResultError, match="internal CA"):
        _build_odoo_client(AsyncMock(), {"organization_public_id": "ORG"})


@pytest.mark.asyncio
async def test_temporary_odoo_failure_retries_then_delivers_once(monkeypatch):
    configure_mapping(monkeypatch)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    client = SequenceClient(
        [
            httpx.Response(503),
            httpx.Response(
                201,
                json={
                    "persisted": True,
                    "idempotency_status": "NEW",
                    "result_public_id": str(PUBLIC_ID),
                    "correlation_id": execution.correlation_id,
                },
            ),
        ]
    )

    with pytest.raises(OdooResultError, match="rejected"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.status == "RETRY"
    assert delivery.attempts == 1

    delivery.next_attempt_at = None
    accepted = await deliver_result(session, DELIVERY_ID, client=client)
    assert accepted["idempotency_status"] == "NEW"
    assert delivery.status == "DELIVERED"
    # attempts counts dispatches, so the successful second dispatch is attempt 2.
    assert delivery.attempts == 2
    assert delivery.last_error_class is None
    assert delivery.odoo_result_inbox_id == str(PUBLIC_ID)


@pytest.mark.asyncio
async def test_transport_failure_retains_durable_retry(monkeypatch):
    configure_mapping(monkeypatch)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    client = SequenceClient([httpx.ConnectError("synthetic outage")])

    with pytest.raises(OdooResultError, match="unavailable"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.status == "RETRY"
    assert delivery.attempts == 1
    assert delivery.reserved_at is None
    assert delivery.last_error_class == "ODOO_TRANSPORT_ERROR"


@pytest.mark.asyncio
async def test_unresolved_registry_route_is_a_retryable_failure_not_a_stuck_reservation(
    monkeypatch,
):
    configure_mapping(monkeypatch)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    client = SequenceClient([ResolutionDenied("NO_ACTIVE_ROUTE")])

    with pytest.raises(OdooResultError, match="route resolution"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.status == "RETRY"
    assert delivery.reserved_at is None
    assert delivery.last_error_class == "ODOO_ROUTE_UNRESOLVED"


@pytest.mark.asyncio
async def test_standard_campaign_actions_deliver_with_bound_receipt(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "odoo_result_delivery_enabled", True)
    event = IntegrationEvent(
        id=17,
        idempotency_key="result:event-1:1",
        event_type="followup.due",
        original_event_id="event-1",
        source_system="odoo",
        correlation_id="correlation-1",
        payload_hash="a" * 64,
        state="delivered",
        payload_json={
            "business_unit_id": "MBL",
            "campaign_id": "MBL-NEW-LOAN-OUT",
            "actor_type": "SYSTEM",
            "actor_id": "middleware",
        },
    )
    delivery = OdooResultDelivery(
        result_delivery_id=DELIVERY_ID,
        integration_event_id=17,
        result_public_id=PUBLIC_ID,
        originating_outbox_public_id="event-1",
        request_hash="d" * 64,
        status="PENDING",
        attempts=0,
        standard_result_json={
            "event_id": "event-1",
            "correlation_id": "correlation-1",
            "idempotency_key": "result:event-1:1",
            "workflow_key": "moneybee_offer_sent",
            "execution_id": "execution-1",
            "status": "COMPLETED",
            "completed_at": "2026-08-22T18:00:00Z",
            "actions": [
                {
                    "action_type": "CREATE_INTERNAL_SUMMARY",
                    "entity_type": "crm.lead",
                    "entity_id": "17",
                    "values": {"body": "Bound summary"},
                }
            ],
        },
    )
    session = AsyncMock()

    async def get(model, identity, **kwargs):
        if model is OdooResultDelivery and identity == DELIVERY_ID:
            return delivery
        if model is IntegrationEvent and identity == 17:
            return event
        return None

    session.get.side_effect = get
    session.scalar.return_value = None
    client = SequenceClient(
        [
            httpx.Response(
                200,
                json={
                    "status": "APPLIED",
                    "event_id": "event-1",
                    "execution_id": "execution-1",
                    "correlation_id": "correlation-1",
                    "applied_actions": [{"position": 0}],
                    "receipt_id": "receipt-1",
                },
            )
        ],
        operation="automation_results.apply",
    )
    accepted = await deliver_result(session, DELIVERY_ID, client=client)
    assert accepted["receipt_id"] == "receipt-1"
    assert delivery.status == "DELIVERED"
    assert delivery.odoo_result_inbox_id == "receipt-1"


@pytest.mark.asyncio
async def test_provider_activity_delivers_to_bound_odoo_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "odoo_result_delivery_enabled", True)
    monkeypatch.setattr(
        settings, "test_syn_odoo_organization_public_id", "ORG-TEST-SYN"
    )
    monkeypatch.setattr(
        settings, "test_syn_odoo_business_unit_public_id", "BU-TEST-SYN"
    )
    monkeypatch.setattr(
        settings, "test_syn_odoo_campaign_public_id", "CAMPAIGN-TEST-SYN"
    )
    event = IntegrationEvent(
        id=18,
        idempotency_key="provider:event-1",
        event_type="call_disposition_updated",
        original_event_id="vicidial:stage2-test-001",
        source_system="vicidial",
        correlation_id="vicidial:stage2-test-001",
        payload_hash="a" * 64,
        state="accepted",
        payload_json={},
    )
    delivery = OdooResultDelivery(
        result_delivery_id=DELIVERY_ID,
        integration_event_id=18,
        result_public_id=PUBLIC_ID,
        originating_outbox_public_id=event.original_event_id,
        request_hash="d" * 64,
        status="PENDING",
        attempts=0,
        standard_result_json={
            "operation": "log_call_result",
            "call_id": "stage2-test-001",
            "phone_number": "+15555550199",
            "disposition": "answered",
            "call_time": 67,
            "campaign_id": "TEST_SYN",
            "comments": "Stage 2 activation test",
        },
    )
    session = AsyncMock()

    async def get(model, identity, **kwargs):
        if model is OdooResultDelivery and identity == DELIVERY_ID:
            return delivery
        if model is IntegrationEvent and identity == 18:
            return event
        return None

    session.get.side_effect = get
    session.scalar.return_value = None
    client = SequenceClient(
        [
            httpx.Response(
                201,
                json={
                    "status": "APPLIED",
                    "event_id": event.original_event_id,
                    "operation": "log_call_result",
                    "partner_id": 42,
                    "message_id": 84,
                    "duplicate": False,
                    "correlation_id": event.correlation_id,
                },
            )
        ],
        operation="provider_activities.create",
    )
    accepted = await deliver_result(session, DELIVERY_ID, client=client)
    assert accepted["partner_id"] == 42
    assert delivery.status == "DELIVERED"
    assert delivery.odoo_result_inbox_id == "84"


@pytest.mark.asyncio
async def test_successful_delivery_counts_one_attempt(monkeypatch):
    configure_mapping(monkeypatch)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    client = SequenceClient([accepted_response(execution)])

    await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.status == "DELIVERED"
    assert delivery.attempts == 1
    assert delivery.reserved_at is None


@pytest.mark.asyncio
async def test_attempts_count_dispatches_until_retry_limit_dead_letters(monkeypatch):
    configure_mapping(monkeypatch)
    monkeypatch.setattr(settings, "odoo_result_delivery_retry_limit", 3)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    client = SequenceClient([httpx.ConnectError("outage")] * 3)

    with pytest.raises(OdooResultError, match="unavailable"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.attempts == 1
    assert delivery.status == "RETRY"
    first_backoff = delivery.next_attempt_at

    with pytest.raises(OdooResultError, match="unavailable"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.attempts == 2
    assert delivery.status == "RETRY"
    assert delivery.next_attempt_at is not None and first_backoff is not None
    assert delivery.next_attempt_at - first_backoff >= timedelta(seconds=4)

    with pytest.raises(OdooResultError, match="unavailable"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.attempts == 3
    assert delivery.status == "DEAD_LETTER"
    assert delivery.next_attempt_at is None
    assert delivery.reserved_at is None
    assert delivery.last_error_class == "ODOO_TRANSPORT_ERROR"

    with pytest.raises(OdooResultError, match="not claimable"):
        await deliver_result(session, DELIVERY_ID, client=client)
    assert delivery.attempts == 3


@pytest.mark.asyncio
async def test_record_delivery_failure_never_changes_attempts(monkeypatch):
    monkeypatch.setattr(settings, "odoo_result_delivery_retry_limit", 3)
    execution, runtime_result, delivery = records()
    session = session_for(execution, runtime_result, delivery)
    delivery.status = "RESERVED"
    delivery.reserved_at = datetime.now(UTC)
    delivery.attempts = 2

    await _record_delivery_failure(
        session, DELIVERY_ID, error_class="HTTP_503", retryable=True
    )
    assert delivery.attempts == 2
    assert delivery.status == "RETRY"
    assert delivery.reserved_at is None
    assert delivery.next_attempt_at is not None

    delivery.status = "RESERVED"
    delivery.attempts = 3
    await _record_delivery_failure(
        session, DELIVERY_ID, error_class="HTTP_503", retryable=True
    )
    assert delivery.attempts == 3
    assert delivery.status == "DEAD_LETTER"
    assert delivery.next_attempt_at is None

    delivery.status = "RESERVED"
    delivery.attempts = 1
    await _record_delivery_failure(
        session, DELIVERY_ID, error_class="HTTP_400", retryable=False
    )
    assert delivery.attempts == 1
    assert delivery.status == "DEAD_LETTER"


def test_stale_recovery_statements_split_on_retry_limit_without_counting():
    now = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
    exhausted, requeued = stale_recovery_statements(now, 90, 3)

    sql, params = compiled_sql(exhausted)
    assert "attempts >=" in sql
    assert "attempts + 1" not in sql
    assert "SET attempts" not in sql and ", attempts=" not in sql
    assert params["status"] == "DEAD_LETTER"
    assert params["status_1"] == "RESERVED"
    assert params["attempts_1"] == 3
    assert params["reserved_at"] is None
    assert params["next_attempt_at"] is None
    assert params["last_error_class"] == "STALE_RESERVATION_EXHAUSTED"
    assert params["reserved_at_1"] == now - timedelta(seconds=90)

    sql, params = compiled_sql(requeued)
    assert "attempts <" in sql
    assert "attempts + 1" not in sql
    assert "SET attempts" not in sql and ", attempts=" not in sql
    assert params["status"] == "RETRY"
    assert params["status_1"] == "RESERVED"
    assert params["attempts_1"] == 3
    assert params["reserved_at"] is None
    assert params["next_attempt_at"] == now
    assert params["last_error_class"] == "STALE_RESERVATION_RECOVERED"
    assert params["reserved_at_1"] == now - timedelta(seconds=90)


@pytest.mark.asyncio
async def test_stale_reservation_recovery_is_durable(monkeypatch):
    monkeypatch.setattr(settings, "odoo_result_delivery_retry_limit", 3)
    session, executed = recovery_session(None, [1, 2])

    assert await recover_stale_result_deliveries(session, lease_seconds=30) == 3
    session.commit.assert_awaited_once()
    assert len(executed) == 2

    exhausted_sql, exhausted = compiled_sql(executed[0])
    requeued_sql, requeued = compiled_sql(executed[1])
    assert "attempts >=" in exhausted_sql and "attempts <" in requeued_sql
    assert "attempts + 1" not in exhausted_sql + requeued_sql
    assert exhausted["status"] == "DEAD_LETTER"
    assert exhausted["last_error_class"] == "STALE_RESERVATION_EXHAUSTED"
    assert exhausted["next_attempt_at"] is None
    assert requeued["status"] == "RETRY"
    assert requeued["last_error_class"] == "STALE_RESERVATION_RECOVERED"
    assert exhausted["attempts_1"] == requeued["attempts_1"] == 3
    assert exhausted["reserved_at"] is None and requeued["reserved_at"] is None
    # Without registry routes the configured lease is applied unchanged.
    assert requeued["next_attempt_at"] - requeued["reserved_at_1"] == timedelta(
        seconds=30
    )


@pytest.mark.asyncio
async def test_stale_recovery_defaults_to_configured_lease(monkeypatch):
    monkeypatch.setattr(settings, "odoo_result_delivery_lease_seconds", 75)
    session, executed = recovery_session(None, [0, 0])

    assert await recover_stale_result_deliveries(session) == 0
    _, requeued = compiled_sql(executed[1])
    assert requeued["next_attempt_at"] - requeued["reserved_at_1"] == timedelta(
        seconds=75
    )


@pytest.mark.asyncio
async def test_stale_recovery_lease_is_raised_to_registry_minimum(monkeypatch, caplog):
    monkeypatch.setattr(settings, "odoo_result_delivery_lease_seconds", 30)
    # Slowest enabled Odoo route: 100.5s connect + request -> ceil to 101s.
    session, executed = recovery_session(100_500, [0, 0])
    expected = 101 + STALE_LEASE_MARGIN_SECONDS

    with caplog.at_level(logging.WARNING, logger="codestra.odoo_results"):
        assert await recover_stale_result_deliveries(session) == 0
    session.scalar.assert_awaited_once()
    _, requeued = compiled_sql(executed[1])
    assert requeued["next_attempt_at"] - requeued["reserved_at_1"] == timedelta(
        seconds=expected
    )
    warnings = [
        record for record in caplog.records if record.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "30s" in warnings[0].getMessage()
    assert f"{expected}s" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_stale_recovery_keeps_larger_configured_lease(monkeypatch, caplog):
    session, executed = recovery_session(10_000, [0, 0])

    with caplog.at_level(logging.WARNING, logger="codestra.odoo_results"):
        assert await recover_stale_result_deliveries(session, lease_seconds=120) == 0
    _, requeued = compiled_sql(executed[1])
    assert requeued["next_attempt_at"] - requeued["reserved_at_1"] == timedelta(
        seconds=120
    )
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


@pytest.mark.asyncio
async def test_stale_recovery_rejects_non_positive_lease():
    session, _ = recovery_session(None, [0, 0])
    with pytest.raises(ValueError, match="positive"):
        await recover_stale_result_deliveries(session, lease_seconds=0)
    session.execute.assert_not_awaited()
    session.commit.assert_not_awaited()
