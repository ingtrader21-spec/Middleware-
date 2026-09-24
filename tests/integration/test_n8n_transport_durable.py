import asyncio
import json
import os
import time
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import Response
import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

import app.api.v1.n8n_transport as transport_api
from app.adapters.odoo.results import deliver_result
from app.api.v1.n8n_transport import (
    acknowledge_execution,
    register_execution,
    transition_execution,
)
from app.core.automation import canonical_hash, sign_exact_body
from app.core.config import settings
from app.db.models import (
    BroadEventDelivery,
    IntegrationEvent,
    OdooResultDelivery,
    OutboxEvent,
)


def request_for(body: bytes) -> Request:
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "path": "/"}, receive)


def test_durable_registration_acknowledgement_and_odoo_result(monkeypatch):
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("requires an explicitly provisioned disposable database")
    assert "diag" in database_url or "rehearsal" in database_url
    monkeypatch.setattr(settings, "webhook_shared_secret", "synthetic-test-secret")

    async def allow_synthetic(request, db, *args):
        return await request.body()

    monkeypatch.setattr(transport_api, "authenticate_service", allow_synthetic)

    async def scenario():
        engine = create_async_engine(database_url, pool_pre_ping=True)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        event_public_id = f"n8n-transport-test-{uuid4()}"
        correlation_id = f"correlation-{uuid4()}"
        payload = {"operation": "reconciliation.run", "synthetic": True}
        payload_hash = canonical_hash(payload)
        policy_hash = "a" * 64
        workflow_id = "n8n-test-assigned-id"
        workflow_version = "test-version-1"
        async with session_factory() as session:
            event = IntegrationEvent(
                idempotency_key=event_public_id,
                event_type="reconciliation.run",
                schema_version="1.0",
                original_event_id=event_public_id,
                source_system="odoo",
                correlation_id=correlation_id,
                payload_json=payload,
                payload_hash=payload_hash,
                state="queued",
            )
            session.add(event)
            await session.flush()
            delivery = BroadEventDelivery(
                event_id=event.id,
                workflow_id=workflow_id,
                workflow_version=workflow_version,
                idempotency_key=event_public_id,
                target_identity="n8n-production-test",
                target_environment="production",
                payload_hash=payload_hash,
                policy_hash=policy_hash,
                attempt_number=1,
                status="SUBMITTED",
                reserved_at=datetime.now(UTC),
                submitted_at=datetime.now(UTC),
            )
            session.add(delivery)
            await session.commit()

            execution_id = f"execution-{uuid4()}"
            registration = {
                "schema_version": "1.0",
                "registration_id": str(uuid4()),
                "delivery_id": str(delivery.delivery_id),
                "event_id": event_public_id,
                "workflow_key": workflow_id,
                "workflow_version": workflow_version,
                "execution_id": execution_id,
                "payload_hash": payload_hash,
                "request_hash": "d" * 64,
                "policy_hash": policy_hash,
                "attempt_number": 1,
                "environment": "production",
                "idempotency_key": f"registration-{event_public_id}",
                "correlation_id": correlation_id,
                "received_at": datetime.now(UTC).isoformat(),
                "registered_at": datetime.now(UTC).isoformat(),
            }
            raw_registration = json.dumps(registration).encode()
            timestamp = str(int(time.time()))
            response = await register_execution(
                request_for(raw_registration),
                Response(),
                "Bearer synthetic",
                timestamp,
                uuid4().hex,
                f"sha256={sign_exact_body(raw_registration, settings.webhook_shared_secret)}",
                session,
            )
            assert response["idempotency_status"] == "NEW"

            acknowledgement_id = uuid4()
            transition = {
                "schema_version": "1.0",
                "transition_id": str(uuid4()),
                "state": "RUNNING",
                "correlation_id": correlation_id,
                "attempt_number": 1,
                "occurred_at": datetime.now(UTC).isoformat(),
            }
            raw_transition = json.dumps(transition).encode()
            transitioned = await transition_execution(
                UUID(registration["registration_id"]),
                request_for(raw_transition),
                Response(),
                "Bearer synthetic",
                timestamp,
                uuid4().hex,
                f"sha256={sign_exact_body(raw_transition, settings.webhook_shared_secret)}",
                session,
            )
            assert transitioned["state"] == "RUNNING"

            acknowledgement = {
                "schema_version": "1.0",
                "acknowledgement_id": str(acknowledgement_id),
                "registration_id": registration["registration_id"],
                "delivery_id": str(delivery.delivery_id),
                "event_id": event_public_id,
                "workflow_key": workflow_id,
                "workflow_version": workflow_version,
                "execution_id": execution_id,
                "execution_status": "SUCCEEDED",
                "result_classification": "INTERNAL_RECONCILIATION_COMPLETE",
                "result_hash": "b" * 64,
                "started_at": datetime.now(UTC).isoformat(),
                "completed_at": datetime.now(UTC).isoformat(),
                "attempt_number": 1,
                "correlation_id": correlation_id,
                "policy_hash": policy_hash,
                "metrics": {"duration_ms": 0},
            }
            raw_ack = json.dumps(acknowledgement).encode()
            persisted = await acknowledge_execution(
                request_for(raw_ack),
                Response(),
                "Bearer synthetic",
                timestamp,
                uuid4().hex,
                f"sha256={sign_exact_body(raw_ack, settings.webhook_shared_secret)}",
                session,
            )
            assert persisted["persisted"] is True
            assert persisted["idempotency_status"] == "NEW"
            duplicate = await acknowledge_execution(
                request_for(raw_ack),
                Response(),
                "Bearer synthetic",
                timestamp,
                uuid4().hex,
                f"sha256={sign_exact_body(raw_ack, settings.webhook_shared_secret)}",
                session,
            )
            assert duplicate["persisted"] is True
            assert duplicate["idempotency_status"] == "DUPLICATE"
            delivery_status = await session.scalar(
                select(BroadEventDelivery.status).where(
                    BroadEventDelivery.delivery_id == delivery.delivery_id
                )
            )
            assert delivery_status == "ACKNOWLEDGED"
            result_count = await session.scalar(
                select(text("count(*)"))
                .select_from(OutboxEvent)
                .where(
                    OutboxEvent.topic == "odoo.integration.result",
                    OutboxEvent.correlation_id == correlation_id,
                )
            )
            assert result_count == 1
            result_delivery = await session.scalar(
                select(OdooResultDelivery).where(
                    OdooResultDelivery.acknowledgement_id == acknowledgement_id
                )
            )
            assert result_delivery is not None
            monkeypatch.setattr(settings, "odoo_result_delivery_enabled", True)
            monkeypatch.setattr(settings, "odoo_staging_writes_enabled", True)
            monkeypatch.setattr(settings, "environment", "staging")

            def odoo_callback(request):
                submitted = json.loads(request.content)
                response_body = {
                    "schema_version": "1.0",
                    "persisted": True,
                    "idempotency_status": "NEW",
                    "result_public_id": submitted["result_public_id"],
                    "correlation_id": submitted["correlation_id"],
                }
                return httpx.Response(201, json=response_body)

            class SyntheticServiceClient:
                def __init__(self):
                    self.http = httpx.AsyncClient(
                        transport=httpx.MockTransport(odoo_callback),
                        follow_redirects=False,
                    )

                async def request(self, operation, payload, **kwargs):
                    assert operation == "results.create"
                    assert kwargs["idempotency_key"] == str(
                        result_delivery.result_public_id
                    )
                    return await self.http.post(
                        "https://odoo.test.invalid/api/v1/integration/results",
                        json=payload,
                    )

                async def aclose(self):
                    await self.http.aclose()

            callback_client = SyntheticServiceClient()
            try:
                callback = await deliver_result(
                    session,
                    result_delivery.result_delivery_id,
                    client=callback_client,
                )
            finally:
                await callback_client.aclose()
            assert callback["result_public_id"] == str(result_delivery.result_public_id)
            await session.refresh(result_delivery)
            assert result_delivery.status == "DELIVERED"
        await engine.dispose()

    asyncio.run(scenario())
