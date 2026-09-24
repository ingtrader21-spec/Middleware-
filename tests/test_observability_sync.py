from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.adapters.odoo.results import _observability_body
from app.api.v1.observability_sync import (
    IncidentState,
    KpiSnapshot,
    _projection_hash,
    _safe_payload,
)
from app.monitoring.auth import Principal


def _principal():
    return Principal(
        subject="collector",
        tenant="tenant-a",
        roles=frozenset({"monitoring_collector"}),
        campaigns=frozenset(),
        services=frozenset({"middleware"}),
        client="prometheus",
    )


def _kpi_payload():
    value = {
        "event_id": "kpi-tenant-a-1",
        "schema_version": "kyyow.observability.kpi.v1",
        "tenant_id": "tenant-a",
        "metric_code": "sms.delivery_rate",
        "service_id": "middleware",
        "environment": "production",
        "period_reference": "2026-09-12T12:00:00Z",
        "period_start": "2026-09-12T12:00:00+00:00",
        "period_end": "2026-09-12T13:00:00+00:00",
        "value": 99.1,
        "unit": "percent",
        "dimensions": {"route": "primary"},
        "source": "prometheus",
        "source_revision": 1,
        "source_payload_hash": "sha256:" + "a" * 64,
        "observed_at": "2026-09-12T13:00:00+00:00",
        "reconciliation_state": "accepted",
        "correlation_id": "corr-kpi-1",
    }
    normalized = {
        **value,
        "period_start": "2026-09-12T12:00:00Z",
        "period_end": "2026-09-12T13:00:00Z",
        "observed_at": "2026-09-12T13:00:00Z",
    }
    value["projection_hash"] = "sha256:" + _projection_hash(normalized)
    return value


def _incident_payload():
    value = {
        "event_id": "incident-tenant-a-1",
        "schema_version": "kyyow.observability.incident.v1",
        "tenant_id": "tenant-a",
        "incident_id": "incident-1",
        "fingerprint": "fp-1",
        "alertname": "MiddlewareOdooDelivery",
        "group_key": "tenant-a/middleware",
        "severity": "critical",
        "state": "firing",
        "service_id": "middleware",
        "environment": "production",
        "host": "node-1",
        "summary": "Odoo delivery is failing",
        "labels": {"service": "middleware", "severity": "critical"},
        "first_seen_at": "2026-09-12T13:00:00+00:00",
        "last_seen_at": "2026-09-12T13:00:00+00:00",
        "resolved_at": None,
        "source_deployment": "middleware:abc123",
        "resource_version": 1,
        "source_payload_hash": "sha256:" + "b" * 64,
        "observed_at": "2026-09-12T13:00:00+00:00",
        "correlation_id": "corr-incident-1",
    }
    normalized = {
        **value,
        "first_seen_at": "2026-09-12T13:00:00Z",
        "last_seen_at": "2026-09-12T13:00:00Z",
        "observed_at": "2026-09-12T13:00:00Z",
    }
    value["projection_hash"] = "sha256:" + _projection_hash(normalized)
    return value


def test_kpi_payload_is_canonicalized_before_hash_verification():
    body = KpiSnapshot.model_validate(_kpi_payload())
    safe = _safe_payload(body, _principal(), "kpi-idempotency-key")
    assert safe["period_start"] == "2026-09-12T12:00:00Z"
    assert safe["observed_at"] == "2026-09-12T13:00:00Z"
    assert safe["projection_hash"] == body.projection_hash


def test_sensitive_observability_dimensions_are_rejected():
    payload = _kpi_payload()
    payload["dimensions"] = {"api_token": "must-not-enter-odoo"}
    with pytest.raises(ValidationError):
        KpiSnapshot.model_validate(payload)


def test_non_resolved_incident_cannot_have_resolution_time():
    payload = _incident_payload()
    payload["resolved_at"] = "2026-09-12T13:01:00Z"
    with pytest.raises(ValidationError):
        IncidentState.model_validate(payload)


def test_odoo_transport_binding_uses_durable_delivery_identity():
    delivery_id = uuid4()
    delivery = SimpleNamespace(
        standard_result_json={
            "operation": "observability.kpis.create",
            "idempotency_key": "source-key",
        },
        result_public_id=delivery_id,
    )
    event = SimpleNamespace(
        payload_json=_kpi_payload(),
        original_event_id="kpi-tenant-a-1",
    )
    payload = _observability_body(delivery, event)
    assert payload["operation"] == "odoo.observability.kpis.create"
    assert payload["idempotency_key"] == str(delivery_id)
    assert payload["causation_id"] == event.original_event_id


def test_collector_cannot_submit_for_an_unbound_service():
    from dataclasses import replace
    from fastapi import HTTPException
    body = KpiSnapshot.model_validate(_kpi_payload())
    principal = replace(_principal(), services=frozenset({'other-service'}))
    with pytest.raises(HTTPException) as error:
        _safe_payload(body, principal, 'kpi-idempotency-key')
    assert error.value.status_code == 403


def test_projection_source_requires_registered_client_and_environment():
    from fastapi import HTTPException
    from app.monitoring.routes import validate_source
    config = {'services': {'middleware': {'tenant': 'tenant-a',
        'environments': ['production'], 'observation_sources': {
            'prometheus': {'client': 'prometheus', 'environments': ['production']}}}}}
    body = SimpleNamespace(service_id='middleware', environment='production',
        source_deployment='prometheus', observed_at=datetime.now(UTC))
    validate_source(config, _principal(), body)
    config['services']['middleware']['observation_sources']['prometheus']['client'] = 'other-collector'
    with pytest.raises(HTTPException) as error:
        validate_source(config, _principal(), body)
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_postgres_projection_delivery_replay_and_stale_versions():
    import asyncio
    import os
    from dataclasses import replace
    from fastapi import HTTPException
    from sqlalchemy import select, func
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from app.db.models import IntegrationEvent, OdooResultDelivery
    from app.api.v1.observability_sync import _enqueue, INCIDENT_OPERATION, INCIDENT_EVENT_TYPE

    url = os.getenv('TEST_DATABASE_URL')
    if not url:
        pytest.skip('TEST_DATABASE_URL required for real PostgreSQL projection tests')
    url = url.replace('postgresql://', 'postgresql+asyncpg://', 1)
    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    identity = 'projection-test-' + uuid4().hex
    principal = replace(_principal(), tenant=identity)
    payload = _incident_payload()
    payload.update(tenant_id=identity, event_id=identity, incident_id=identity)

    async def enqueue(document):
        async with factory() as session:
            return await _enqueue(session, principal=principal,
                operation=INCIDENT_OPERATION, event_type=INCIDENT_EVENT_TYPE,
                payload=document, idempotency_key=document['event_id'],
                correlation_id=document['correlation_id'])

    try:
        first, second = await asyncio.gather(enqueue(payload), enqueue(payload))
        assert first['delivery_id'] == second['delivery_id']
        assert sorted([first['duplicate'], second['duplicate']]) == [False, True]
        later = {**payload, 'event_id': identity + '-v3', 'resource_version': 3}
        await enqueue(later)
        for version in (1, 2, 3):
            with pytest.raises(HTTPException) as error:
                await enqueue({**payload, 'event_id': identity + '-stale-' + str(version), 'resource_version': version})
            assert error.value.status_code == 409
        replay = await enqueue(payload)
        assert replay['duplicate'] is True
        assert replay['delivery_id'] == first['delivery_id']
        async with factory() as session:
            count = await session.scalar(select(func.count()).select_from(OdooResultDelivery).join(
                IntegrationEvent, OdooResultDelivery.integration_event_id == IntegrationEvent.id
            ).where(IntegrationEvent.entity_key == identity + ':' + identity))
            assert count == 2
    finally:
        await engine.dispose()
