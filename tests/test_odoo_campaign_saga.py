from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

from app import odoo_campaign_saga as saga_module
from app.core.config import settings
from app.core.endpoint_registry import ResolutionDenied
from app.db.models import AuditEvent, Base, IntegrationEvent, OdooCampaignSaga
from app.entrypoints import odoo_campaign_saga_worker as worker
from app.odoo_campaign_saga import (
    ALLOWED_EVENT_TYPES,
    MINIMUM_LEASE_SECONDS,
    OPERATION_BY_EVENT_TYPE,
    RESULT_STATE_BY_OPERATION,
    SagaConfigurationError,
    SagaError,
    WRITE_BINDING_BY_ENVIRONMENT,
    SyntheticCampaignAdapter,
    adapter_for,
    claim_saga,
    claimable_saga_statement,
    enroll_pending_sagas,
    pending_events_statement,
    process_saga,
    recover_expired_leases,
)


@compiles(JSONB, "sqlite")
def _render_jsonb_on_sqlite(type_, compiler, **kwargs):
    return "JSON"


MANIFEST_HASH = "sha256:" + "a" * 64
PAYLOAD = {
    "command_id": "cmd-1",
    "organization_public_id": "ORG-1",
    "business_unit_public_id": "BU-1",
    "campaign_public_id": "CMP-1",
    "configuration_version": 3,
    "manifest_ref": "manifests/cmp-1/v3",
    "manifest_hash": MANIFEST_HASH,
}


def desired_state(version: int = 3, manifest_hash: str = MANIFEST_HASH) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "campaign_public_id": "CMP-1",
            "configuration_version": version,
            "desired_state": "active",
            "manifest_ref": "manifests/cmp-1/v3",
            "manifest_hash": manifest_hash,
        },
    )


def readback_accepted(
    saga: OdooCampaignSaga,
    readback_id: str = "rb-1",
    effective_state: str | None = None,
) -> httpx.Response:
    return httpx.Response(
        201,
        json={
            "status": "APPLIED",
            "event_uuid": saga.event_uuid,
            "command_id": saga.command_id,
            "configuration_version": saga.configuration_version,
            "effective_state": effective_state
            or RESULT_STATE_BY_OPERATION[saga.operation],
            "correlation_id": saga.correlation_id,
            "readback_id": readback_id,
        },
    )


def event(
    event_id: int,
    *,
    event_type: str = "campaign.activate.requested.v1",
    source_system: str = "odoo",
    state: str = "accepted",
    payload: dict | None = None,
) -> IntegrationEvent:
    return IntegrationEvent(
        id=event_id,
        idempotency_key=f"odoo:{event_id}",
        event_type=event_type,
        original_event_id=f"evt-{event_id}",
        source_system=source_system,
        correlation_id=f"corr-{event_id}",
        payload_json=PAYLOAD if payload is None else payload,
        payload_hash="h" * 64,
        state=state,
    )


class SequenceClient:
    """Pops queued responses/exceptions and records every call."""

    def __init__(self, responses: list[httpx.Response | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict, dict]] = []
        self.closed = False

    async def request(self, operation, payload, **kwargs):
        self.calls.append((operation, payload, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        self.closed = True

    def operations(self) -> list[str]:
        return [operation for operation, _payload, _kwargs in self.calls]


class CountingAdapter(SyntheticCampaignAdapter):
    def __init__(self) -> None:
        self.calls = 0

    async def apply(self, saga, desired):
        self.calls += 1
        return await super().apply(saga, desired)


@pytest_asyncio.fixture
async def factory(tmp_path):
    # File-backed so concurrent sessions get their own connections, as with
    # PostgreSQL; the in-memory engine shares one connection across sessions.
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'saga.db').as_posix()}")
    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all,
            tables=[IntegrationEvent.__table__, OdooCampaignSaga.__table__, AuditEvent.__table__],
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def saga_settings(monkeypatch):
    monkeypatch.setattr(settings, "odoo_campaign_saga_enabled", True)
    monkeypatch.setattr(settings, "odoo_campaign_saga_adapter", "synthetic")
    monkeypatch.setattr(settings, "odoo_campaign_saga_lease_seconds", 90)
    monkeypatch.setattr(settings, "odoo_campaign_saga_retry_limit", 3)
    return settings


async def seed(session, *events: IntegrationEvent) -> None:
    session.add_all(events)
    await session.commit()


async def reserved_saga(session, *, attempts: int = 1, **overrides) -> OdooCampaignSaga:
    await seed(session, event(1))
    assert await enroll_pending_sagas(session) == 1
    saga = await claim_saga(session, lease_seconds=90)
    assert saga is not None
    saga.attempts = attempts
    for key, value in overrides.items():
        setattr(saga, key, value)
    await session.commit()
    return saga


async def run_saga(session, saga, responses, adapter=None):
    client = SequenceClient(responses)
    adapter = adapter or CountingAdapter()
    outcome = await process_saga(session, saga.saga_id, client=client, adapter=adapter)
    return outcome, client, adapter


def test_catalog_constants_come_from_the_contract():
    assert ALLOWED_EVENT_TYPES == frozenset(OPERATION_BY_EVENT_TYPE)
    assert all(kind.startswith("campaign.") for kind in ALLOWED_EVENT_TYPES)
    assert set(OPERATION_BY_EVENT_TYPE.values()) == set(RESULT_STATE_BY_OPERATION)
    assert RESULT_STATE_BY_OPERATION["reconcile"] is None
    assert MINIMUM_LEASE_SECONDS == 41


def test_statements_compile_to_anti_join_allowlist_and_skip_locked():
    dialect = postgresql.dialect()
    pending = pending_events_statement(50).compile(
        dialect=dialect, compile_kwargs={"render_postcompile": True}
    )
    pending_sql = str(pending)
    assert "NOT (EXISTS" in pending_sql or "NOT EXISTS" in pending_sql
    assert "integration_event.event_type IN (" in pending_sql
    assert "LIKE" not in pending_sql
    assert "odoo_campaign_saga.integration_event_id = integration_event.id" in pending_sql
    bound = {
        value for key, value in pending.params.items() if key.startswith("event_type")
    }
    assert bound == set(ALLOWED_EVENT_TYPES)
    assert pending.params["source_system_1"] == "odoo"
    assert pending.params["state_1"] == "accepted"

    claim_sql = str(claimable_saga_statement(datetime.now(UTC)).compile(dialect=dialect))
    assert "FOR UPDATE SKIP LOCKED" in claim_sql
    assert "odoo_campaign_saga.status IN" in claim_sql
    assert "next_attempt_at IS NULL" in claim_sql
    assert "LIMIT" in claim_sql


@pytest.mark.asyncio
async def test_enrollment_ignores_non_allowlisted_and_already_enrolled_events(factory):
    async with factory() as session:
        await seed(
            session,
            event(1),
            event(2, event_type="campaign.reconcile.requested.v1"),
            event(3, event_type="campaign.deleted.v1"),
            event(4, event_type="lead.created.v1"),
            event(5, source_system="vicidial"),
            event(6, state="queued"),
        )
        assert await enroll_pending_sagas(session) == 2
        assert await enroll_pending_sagas(session) == 0
    async with factory() as session:
        rows = (await session.scalars(saga_module.select(OdooCampaignSaga))).all()
        assert sorted(row.integration_event_id for row in rows) == [1, 2]
        by_event = {row.integration_event_id: row for row in rows}
        assert by_event[1].operation == "activate"
        assert by_event[2].operation == "reconcile"
        assert all(row.status == "PENDING" and row.attempts == 0 for row in rows)
        assert by_event[1].event_uuid == "evt-1"
        assert by_event[1].correlation_id == "corr-1"
        assert by_event[1].command_id == "cmd-1"
        assert by_event[1].configuration_version == 3


@pytest.mark.asyncio
async def test_enrollment_swallows_integrity_error_from_a_concurrent_worker():
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = [event(1), event(2)]
    session.scalars.return_value = scalars
    session.add = MagicMock()
    session.commit.side_effect = [
        IntegrityError("INSERT", {}, Exception("uq_odoo_campaign_saga_event")),
        None,
    ]

    assert await enroll_pending_sagas(session) == 1

    session.rollback.assert_awaited_once()
    assert session.commit.await_count == 2
    added = [call.args[0] for call in session.add.call_args_list]
    sagas = [row for row in added if isinstance(row, OdooCampaignSaga)]
    audits = [row for row in added if isinstance(row, AuditEvent)]
    assert [row.integration_event_id for row in sagas] == [1, 2]
    assert [row.action for row in audits] == ["odoo.campaign_saga.enrolled"] * 2


@pytest.mark.asyncio
async def test_invalid_payload_enrolls_a_dead_letter_row(factory):
    async with factory() as session:
        await seed(
            session,
            event(1, payload={"command_id": "cmd-1", "configuration_version": -1}),
            event(2, payload={**PAYLOAD, "manifest_hash": ""}),
        )
        assert await enroll_pending_sagas(session) == 2
        assert await enroll_pending_sagas(session) == 0
        assert await claim_saga(session, lease_seconds=90) is None
    async with factory() as session:
        rows = (await session.scalars(saga_module.select(OdooCampaignSaga))).all()
        assert len(rows) == 2
        assert {row.status for row in rows} == {"DEAD_LETTER"}
        assert {row.last_error_class for row in rows} == {"INVALID_CONTROL_EVENT"}
        by_event = {row.integration_event_id: row for row in rows}
        assert by_event[1].command_id == "cmd-1"
        assert by_event[1].configuration_version == 0
        assert by_event[2].manifest_hash == ""


@pytest.mark.asyncio
async def test_claim_increments_attempts_once_and_sets_lease(factory):
    async with factory() as session:
        await seed(session, event(1))
        await enroll_pending_sagas(session)
        before = datetime.now(UTC)
        saga = await claim_saga(session, lease_seconds=90)
        assert saga is not None
        assert saga.status == "RESERVED"
        assert saga.attempts == 1
        assert saga.reserved_at is not None and saga.reserved_at >= before
        assert saga.lease_expires_at == saga.reserved_at + timedelta(seconds=90)
        assert saga.next_attempt_at is None
        # A reserved saga is not claimable again.
        assert await claim_saga(session, lease_seconds=90) is None
    async with factory() as session:
        stored = await session.get(OdooCampaignSaga, saga.saga_id)
        assert stored.attempts == 1
        assert stored.status == "RESERVED"


@pytest.mark.asyncio
async def test_claim_respects_next_attempt_at(factory):
    async with factory() as session:
        await seed(session, event(1))
        await enroll_pending_sagas(session)
        saga = await session.scalar(saga_module.select(OdooCampaignSaga))
        saga.status = "RETRY"
        saga.next_attempt_at = datetime.now(UTC) + timedelta(minutes=5)
        await session.commit()
        assert await claim_saga(session, lease_seconds=90) is None
        saga.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
        claimed = await claim_saga(session, lease_seconds=90)
        assert claimed is not None and claimed.attempts == 1


@pytest.mark.asyncio
async def test_stale_configuration_version_dead_letters_before_any_adapter_call(
    factory, saga_settings
):
    async with factory() as session:
        saga = await reserved_saga(session)
        outcome, client, adapter = await run_saga(session, saga, [desired_state(version=4)])
        assert outcome == {"outcome": "stale", "error_class": "STALE_CONFIGURATION_VERSION"}
        assert client.operations() == ["desired_state.read"]
        assert adapter.calls == 0
        assert saga.status == "DEAD_LETTER"
        assert saga.last_error_class == "STALE_CONFIGURATION_VERSION"
        assert saga.reserved_at is None and saga.lease_expires_at is None
        assert saga.attempts == 1
        assert saga.readback_idempotency_key is None
        assert client.calls[0][1] == {
            "organization_public_id": "ORG-1",
            "business_unit_public_id": "BU-1",
            "campaign_public_id": "CMP-1",
        }
        assert client.calls[0][2]["correlation_id"] == "corr-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [desired_state(version=2), desired_state(manifest_hash="sha256:" + "b" * 64)],
)
async def test_version_mismatch_dead_letters_without_dispatch(factory, saga_settings, response):
    async with factory() as session:
        saga = await reserved_saga(session)
        outcome, client, adapter = await run_saga(session, saga, [response])
        assert outcome == {
            "outcome": "dead_letter",
            "error_class": "CONFIGURATION_VERSION_MISMATCH",
        }
        assert adapter.calls == 0
        assert client.operations() == ["desired_state.read"]
        assert saga.status == "DEAD_LETTER"


@pytest.mark.asyncio
async def test_readback_409_is_a_non_retryable_dead_letter(factory, saga_settings):
    async with factory() as session:
        saga = await reserved_saga(session, attempts=1)
        outcome, client, adapter = await run_saga(
            session, saga, [desired_state(), httpx.Response(409, json={})]
        )
        assert outcome["outcome"] == "stale"
        assert saga.status == "DEAD_LETTER"
        assert saga.last_error_class == "STALE_CONFIGURATION_VERSION"
        assert saga.attempts == 1 < settings.odoo_campaign_saga_retry_limit
        assert saga.next_attempt_at is None
        assert adapter.calls == 1
        assert client.operations() == ["desired_state.read", "campaign.actual_state.write"]
        assert await claim_saga(session, lease_seconds=90) is None


@pytest.mark.asyncio
async def test_transport_retry_reuses_the_persisted_observation_and_key(
    factory, saga_settings
):
    async with factory() as session:
        saga = await reserved_saga(session)
        adapter = CountingAdapter()
        outcome, first, _ = await run_saga(
            session,
            saga,
            [desired_state(), httpx.ConnectError("synthetic outage")],
            adapter=adapter,
        )
        assert outcome == {"outcome": "retry", "error_class": "ODOO_TRANSPORT_ERROR"}
        assert saga.status == "RETRY"
        assert saga.attempts == 1
        assert saga.reserved_at is None and saga.lease_expires_at is None
        assert saga.next_attempt_at is not None
        first_key = saga.readback_idempotency_key
        assert first_key.startswith(f"actual-state:{saga.event_uuid}:")
        UUID(first_key.rsplit(":", 1)[1])
        assert saga.readback_attempt == 1
        assert saga.effective_state == "active"
        assert saga.evidence_json["provider_writes"] == "disabled"
        assert first.calls[1][2]["idempotency_key"] == first_key

        saga.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
        claimed = await claim_saga(session, lease_seconds=90)
        assert claimed is saga and saga.attempts == 2

        outcome, second, _ = await run_saga(
            session, saga, [desired_state(), readback_accepted(saga)], adapter=adapter
        )
        assert outcome == {"outcome": "completed", "error_class": None}
        assert adapter.calls == 1
        assert saga.readback_idempotency_key == first_key
        assert saga.readback_attempt == 1
        assert saga.attempts == 2
        readback_payload = second.calls[1][1]
        assert readback_payload["idempotency_key"] == first_key
        assert readback_payload["attempt"] == 1
        assert second.calls[1][2]["idempotency_key"] == first_key
        assert saga.status == "COMPLETED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,error_class",
    [
        (httpx.ConnectError("synthetic outage"), "ODOO_TRANSPORT_ERROR"),
        (httpx.Response(503), "ODOO_UPSTREAM_UNAVAILABLE"),
        (ResolutionDenied("NO_ACTIVE_ROUTE"), "ODOO_ROUTE_UNRESOLVED"),
    ],
)
async def test_retry_limit_exhaustion_dead_letters(factory, saga_settings, failure, error_class):
    async with factory() as session:
        saga = await reserved_saga(session, attempts=settings.odoo_campaign_saga_retry_limit)
        outcome, _, _ = await run_saga(session, saga, [desired_state(), failure])
        assert outcome == {"outcome": "dead_letter", "error_class": error_class}
        assert saga.status == "DEAD_LETTER"
        assert saga.attempts == settings.odoo_campaign_saga_retry_limit
        assert saga.next_attempt_at is None


@pytest.mark.asyncio
async def test_retry_backoff_grows_with_attempts(factory, saga_settings):
    async with factory() as session:
        saga = await reserved_saga(session, attempts=2)
        before = datetime.now(UTC)
        outcome, _, _ = await run_saga(session, saga, [httpx.Response(503)])
        assert outcome == {"outcome": "retry", "error_class": "ODOO_UPSTREAM_UNAVAILABLE"}
        assert saga.next_attempt_at >= before + timedelta(seconds=10)
        assert saga.attempts == 2
        # No observation was taken, so the next dispatch observes afresh.
        assert saga.readback_idempotency_key is None


@pytest.mark.asyncio
async def test_rejected_readback_dead_letters(factory, saga_settings):
    async with factory() as session:
        saga = await reserved_saga(session)
        outcome, _, _ = await run_saga(
            session, saga, [desired_state(), httpx.Response(422, json={})]
        )
        assert outcome == {"outcome": "dead_letter", "error_class": "READBACK_REJECTED"}
        assert saga.status == "DEAD_LETTER"


@pytest.mark.asyncio
async def test_success_completes_with_receipt_and_matching_idempotency_header(
    factory, saga_settings
):
    async with factory() as session:
        saga = await reserved_saga(session)
        outcome, client, adapter = await run_saga(
            session, saga, [desired_state(), readback_accepted(saga, "rb-42")]
        )
        assert outcome == {"outcome": "completed", "error_class": None}
        assert saga.status == "COMPLETED"
        assert saga.readback_id == "rb-42"
        assert saga.completed_at is not None
        assert saga.reserved_at is None and saga.lease_expires_at is None
        assert saga.attempts == 1 and saga.readback_attempt == 1
        assert adapter.calls == 1
        operation, payload, kwargs = client.calls[1]
        assert operation == "campaign.actual_state.write"
        assert kwargs["idempotency_key"] == payload["idempotency_key"]
        assert payload["idempotency_key"] == saga.readback_idempotency_key
        assert payload["attempt"] == 1
        assert payload["effective_state"] == "active"
        assert payload["causation_id"] == saga.event_uuid
        assert payload["evidence"]["adapter"] == "synthetic"
        assert kwargs["correlation_id"] == "corr-1"
        assert kwargs["traceparent"].startswith("00-")
        assert client.closed is False


@pytest.mark.asyncio
async def test_reconcile_observes_the_desired_state(factory, saga_settings):
    async with factory() as session:
        await seed(session, event(1, event_type="campaign.reconcile.requested.v1"))
        await enroll_pending_sagas(session)
        saga = await claim_saga(session, lease_seconds=90)
        assert saga.operation == "reconcile"
        outcome, client, _ = await run_saga(
            session,
            saga,
            [desired_state(), readback_accepted(saga, effective_state="active")],
        )
        assert outcome["outcome"] == "completed"
        assert saga.effective_state == "active"
        assert client.calls[1][1]["effective_state"] == "active"


@pytest.mark.asyncio
async def test_process_saga_requires_a_reservation(factory, saga_settings):
    async with factory() as session:
        await seed(session, event(1))
        await enroll_pending_sagas(session)
        pending = await session.scalar(saga_module.select(OdooCampaignSaga))
        with pytest.raises(SagaError, match="not reserved"):
            await process_saga(session, pending.saga_id, client=SequenceClient([]))
        with pytest.raises(SagaError, match="not reserved"):
            await process_saga(
                session,
                UUID("00000000-0000-0000-0000-000000000000"),
                client=SequenceClient([]),
            )


@pytest.mark.asyncio
async def test_recover_expired_leases_never_increments_attempts(factory):
    async with factory() as session:
        await seed(session, event(1), event(2), event(3))
        await enroll_pending_sagas(session)
        rows = (await session.scalars(saga_module.select(OdooCampaignSaga))).all()
        expired = datetime.now(UTC) - timedelta(seconds=1)
        live = datetime.now(UTC) + timedelta(minutes=5)
        fixtures = {1: (1, expired), 2: (3, expired), 3: (1, live)}
        for row in rows:
            attempts, lease = fixtures[row.integration_event_id]
            row.status = "RESERVED"
            row.attempts = attempts
            row.reserved_at = datetime.now(UTC)
            row.lease_expires_at = lease
        await session.commit()
        assert await recover_expired_leases(session, retry_limit=3) == 2
    async with factory() as session:
        rows = (await session.scalars(saga_module.select(OdooCampaignSaga))).all()
        by_event = {row.integration_event_id: row for row in rows}
        assert by_event[1].status == "RETRY"
        assert by_event[1].attempts == 1
        assert by_event[1].last_error_class == "LEASE_EXPIRED_RECOVERED"
        assert by_event[1].next_attempt_at is not None
        assert by_event[1].reserved_at is None and by_event[1].lease_expires_at is None
        assert by_event[2].status == "DEAD_LETTER"
        assert by_event[2].attempts == 3
        assert by_event[2].last_error_class == "LEASE_EXPIRED"
        assert by_event[2].reserved_at is None and by_event[2].lease_expires_at is None
        assert by_event[3].status == "RESERVED"
        assert by_event[3].attempts == 1
        assert by_event[3].lease_expires_at is not None


def test_adapter_for_fails_closed_for_unknown_adapters():
    assert isinstance(
        adapter_for(SimpleNamespace(odoo_campaign_saga_adapter="synthetic")),
        SyntheticCampaignAdapter,
    )
    with pytest.raises(SagaConfigurationError):
        adapter_for(SimpleNamespace(odoo_campaign_saga_adapter="vicidial"))
    with pytest.raises(SagaConfigurationError):
        adapter_for(SimpleNamespace(odoo_campaign_saga_adapter=""))


@pytest.mark.asyncio
async def test_synthetic_adapter_never_contacts_a_provider():
    saga = SimpleNamespace(
        operation="provision",
        manifest_ref="manifests/cmp-1/v3",
        manifest_hash=MANIFEST_HASH,
        configuration_version=3,
    )
    desired = saga_module.DesiredState.model_validate(desired_state().json())
    observation = await SyntheticCampaignAdapter().apply(saga, desired)
    assert observation.effective_state == "provisioned_disabled"
    assert observation.observed_at.tzinfo is not None
    assert observation.evidence == {
        "adapter": "synthetic",
        "operation": "provision",
        "manifest_ref": "manifests/cmp-1/v3",
        "manifest_hash": MANIFEST_HASH,
        "configuration_version": 3,
        "provider_writes": "disabled",
    }
    with pytest.raises(SagaError, match="unsupported"):
        await SyntheticCampaignAdapter().apply(
            SimpleNamespace(**{**saga.__dict__, "operation": "delete"}), desired
        )


@pytest.mark.asyncio
async def test_worker_cycle_is_disabled_by_default_and_never_touches_the_session(
    monkeypatch,
):
    monkeypatch.setattr(settings, "odoo_campaign_saga_enabled", False)
    session_factory = MagicMock()
    monkeypatch.setattr(worker, "SessionFactory", session_factory)

    assert await worker.cycle() == {"claimed": 0, "disabled": True}

    session_factory.assert_not_called()


@pytest.mark.asyncio
async def test_worker_cycle_fails_closed_on_short_lease_or_foreign_adapter(
    monkeypatch, saga_settings
):
    session_factory = MagicMock()
    monkeypatch.setattr(worker, "SessionFactory", session_factory)

    monkeypatch.setattr(settings, "odoo_campaign_saga_lease_seconds", MINIMUM_LEASE_SECONDS - 1)
    with pytest.raises(SagaConfigurationError, match="lease_seconds"):
        await worker.cycle()

    monkeypatch.setattr(settings, "odoo_campaign_saga_lease_seconds", MINIMUM_LEASE_SECONDS)
    monkeypatch.setattr(settings, "odoo_campaign_saga_adapter", "vicidial")
    with pytest.raises(SagaConfigurationError, match="synthetic"):
        await worker.cycle()

    session_factory.assert_not_called()


@pytest.mark.asyncio
async def test_worker_cycle_enrolls_claims_and_completes(factory, saga_settings, monkeypatch):
    monkeypatch.setattr(worker, "SessionFactory", factory)
    async with factory() as session:
        await seed(session, event(1))
    accepted = httpx.Response(
        201,
        json={
            "status": "APPLIED",
            "event_uuid": "evt-1",
            "command_id": "cmd-1",
            "configuration_version": 3,
            "effective_state": "active",
            "correlation_id": "corr-1",
            "readback_id": "rb-cycle",
        },
    )
    client = SequenceClient([desired_state(), accepted])
    built_for: list[dict] = []

    def build_client(session, scope):
        built_for.append(scope)
        return client

    monkeypatch.setattr(saga_module, "_build_odoo_client", build_client)

    result = await worker.cycle()

    assert result == {
        "claimed": 1,
        "recovered": 0,
        "enrolled": 1,
        "outcome": "completed",
        "error_class": None,
    }
    assert client.closed is True
    assert built_for == [
        {
            "organization_public_id": "ORG-1",
            "business_unit_public_id": "BU-1",
            "campaign_public_id": "CMP-1",
        }
    ]
    assert await worker.cycle() == {"claimed": 0, "recovered": 0, "enrolled": 0}
    async with factory() as session:
        saga = await session.scalar(saga_module.select(OdooCampaignSaga))
        assert saga.status == "COMPLETED"
        assert saga.readback_id == "rb-cycle"
        assert saga.attempts == 1


class RacingAdapter(CountingAdapter):
    """Simulates lease recovery re-queueing the saga while the adapter runs."""

    def __init__(self, factory) -> None:
        super().__init__()
        self.factory = factory

    async def apply(self, saga, desired):
        async with self.factory() as other:
            await other.execute(
                update(OdooCampaignSaga)
                .where(OdooCampaignSaga.saga_id == saga.saga_id)
                .values(status="RETRY", reserved_at=None, lease_expires_at=None,
                        last_error_class="LEASE_EXPIRED_RECOVERED", next_attempt_at=datetime.now(UTC))
            )
            await other.commit()
        return await super().apply(saga, desired)


@pytest.mark.asyncio
async def test_lost_reservation_is_detected_from_the_database_not_the_identity_map(
    factory, saga_settings
):
    """A dispatch that lost its lease must not write anything after the race."""
    async with factory() as session:
        saga = await reserved_saga(session)
        saga_id = saga.saga_id
        adapter = RacingAdapter(factory)
        client = SequenceClient([desired_state()])
        with pytest.raises(SagaError, match="reservation was lost"):
            await process_saga(session, saga_id, client=client, adapter=adapter)
        # The adapter ran once; the readback was never sent; the row keeps the
        # recovery's RETRY state instead of being overwritten.
        assert adapter.calls == 1
        assert client.operations() == ["desired_state.read"]
    async with factory() as verify:
        row = await verify.get(OdooCampaignSaga, saga_id)
        assert row.status == "RETRY"
        assert row.readback_idempotency_key is None
        assert row.effective_state is None


@pytest.mark.asyncio
async def test_lease_renewal_aborts_before_the_adapter_when_recovery_raced_the_read(
    factory, saga_settings
):
    async with factory() as session:
        saga = await reserved_saga(session)
        async with factory() as other:
            await other.execute(
                update(OdooCampaignSaga)
                .where(OdooCampaignSaga.saga_id == saga.saga_id)
                .values(status="RETRY", reserved_at=None, lease_expires_at=None)
            )
            await other.commit()
        # process_saga re-reads the row from the database, not the identity map.
        with pytest.raises(SagaError, match="not reserved"):
            await process_saga(session, saga.saga_id, client=SequenceClient([]), adapter=CountingAdapter())


@pytest.mark.asyncio
async def test_staging_enrollment_dead_letters_events_outside_the_test_syn_binding(
    factory, monkeypatch
):
    monkeypatch.setattr(settings, "environment", "staging")
    async with factory() as session:
        await seed(
            session,
            event(1),  # ORG-1 / BU-1 / CMP-1: not the TEST_SYN triple
            event(2, payload={**PAYLOAD, "organization_public_id": "TEST_SYN_TENANT",
                              "business_unit_public_id": "TEST_SYN", "campaign_public_id": "TEST_SYN"}),
        )
        assert await enroll_pending_sagas(session) == 2
        rows = (await session.scalars(select(OdooCampaignSaga).order_by(OdooCampaignSaga.integration_event_id))).all()
        assert [(r.status, r.last_error_class) for r in rows] == [
            ("DEAD_LETTER", "SCOPE_NOT_ALLOWED"),
            ("PENDING", None),
        ]
        # Dead-lettered at enrollment: nothing claimable for it, no network call ever.
        claimed = await claim_saga(session, lease_seconds=90)
        assert claimed is not None and claimed.integration_event_id == 2


def test_production_has_no_enrollment_binding_and_staging_matches_the_catalog():
    assert WRITE_BINDING_BY_ENVIRONMENT["production"] is None
    assert WRITE_BINDING_BY_ENVIRONMENT["staging"] == ("TEST_SYN_TENANT", "TEST_SYN", "TEST_SYN")
