"""Queue one governed TEST_SYN result in the middleware transactional outbox."""

import asyncio
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from app.core.automation import canonical_hash
from app.core.config import settings
from app.db.models import (
    AuditEvent,
    BroadEventDelivery,
    IntegrationEvent,
    N8nAcknowledgement,
    N8nExecutionRegistration,
    OdooResultDelivery,
    OutboxEvent,
)
from app.db.session import SessionFactory

EVENT_ID = "4ceeed96-c1b1-5cb2-95ec-198fcad66b3b"


async def main() -> None:
    if settings.environment.lower() != "staging":
        raise RuntimeError("staging environment required")
    if not settings.odoo_staging_writes_enabled:
        raise RuntimeError("staging write gate required")
    if settings.odoo_production_writes_enabled or settings.live_writes_enabled:
        raise RuntimeError("production write gates must remain closed")
    now = datetime.now(UTC)
    delivery_id = uuid5(NAMESPACE_URL, f"TEST_SYN_DELIVERY:{EVENT_ID}")
    registration_id = uuid5(NAMESPACE_URL, f"TEST_SYN_REGISTRATION:{EVENT_ID}")
    acknowledgement_id = uuid5(NAMESPACE_URL, f"TEST_SYN_ACK:{EVENT_ID}")
    result_public_id = uuid5(NAMESPACE_URL, f"TEST_SYN_RESULT:{EVENT_ID}")
    policy_hash = canonical_hash({"policy": "TEST_SYN_STAGING_ONLY"})
    result_hash = canonical_hash({"result": "TEST_SYN_COMPLETED"})
    async with SessionFactory() as session:
        event = await session.scalar(
            select(IntegrationEvent).where(
                IntegrationEvent.original_event_id == EVENT_ID
            )
        )
        if event is None:
            raise RuntimeError("synthetic Odoo intake event is unavailable")
        existing = await session.scalar(
            select(OdooResultDelivery).where(
                OdooResultDelivery.result_public_id == result_public_id
            )
        )
        if existing:
            print(f"RESULT_DELIVERY_ID={existing.result_delivery_id}")
            print(f"RESULT_STATUS={existing.status}")
            return
        delivery = BroadEventDelivery(
            delivery_id=delivery_id,
            event_id=event.id,
            workflow_id="TEST_SYN_NORMALIZATION",
            workflow_version="1.0.0",
            idempotency_key=f"TEST_SYN_DELIVERY:{EVENT_ID}",
            target_identity="middleware-staging",
            target_environment="staging",
            payload_hash=event.payload_hash,
            policy_hash=policy_hash,
            attempt_number=1,
            status="ACKNOWLEDGED",
            reserved_at=now,
            submitted_at=now,
            response_received_at=now,
            acknowledged_at=now,
        )
        registration = N8nExecutionRegistration(
            registration_id=registration_id,
            delivery_id=delivery_id,
            event_id=EVENT_ID,
            workflow_id="TEST_SYN_NORMALIZATION",
            workflow_version="1.0.0",
            execution_id=f"TEST_SYN_EXECUTION:{EVENT_ID}",
            idempotency_key=f"TEST_SYN_REGISTRATION:{EVENT_ID}",
            correlation_id=event.correlation_id,
            payload_hash=event.payload_hash,
            request_hash=event.payload_hash,
            policy_hash=policy_hash,
            attempt_number=1,
            environment="staging",
            status="SUCCEEDED",
            received_at=now,
            registered_at=now,
            response_hash=result_hash,
        )
        acknowledgement = N8nAcknowledgement(
            acknowledgement_id=acknowledgement_id,
            registration_id=registration_id,
            delivery_id=delivery_id,
            event_id=EVENT_ID,
            workflow_id="TEST_SYN_NORMALIZATION",
            workflow_version="1.0.0",
            execution_id=f"TEST_SYN_EXECUTION:{EVENT_ID}",
            execution_status="SUCCEEDED",
            result_classification="COMPLETED",
            result_hash=result_hash,
            correlation_id=event.correlation_id,
            policy_hash=policy_hash,
            attempt_number=1,
            started_at=now,
            completed_at=now,
            metrics={"synthetic": True},
        )
        result_payload = {
            "result_public_id": str(result_public_id),
            "originating_outbox_public_id": EVENT_ID,
            "result_hash": f"sha256:{result_hash}",
        }
        session.add(delivery)
        await session.flush()
        session.add(registration)
        await session.flush()
        session.add(acknowledgement)
        await session.flush()
        session.add_all(
            [
                OutboxEvent(
                    topic="odoo.integration.result",
                    payload=result_payload,
                    correlation_id=event.correlation_id,
                    status="pending",
                    attempts=0,
                ),
                OdooResultDelivery(
                    acknowledgement_id=acknowledgement_id,
                    result_public_id=result_public_id,
                    originating_outbox_public_id=EVENT_ID,
                    request_hash=canonical_hash(result_payload),
                    status="PENDING",
                ),
                AuditEvent(
                    action="odoo.result.queued",
                    subject=str(result_public_id),
                    correlation_id=event.correlation_id,
                    decision="queued",
                    redacted_payload={
                        "source_event_id": EVENT_ID,
                        "result_hash": result_hash,
                    },
                ),
            ]
        )
        await session.commit()
        print(f"RESULT_PUBLIC_ID={result_public_id}")
        print("MIDDLEWARE_RESULT_OUTBOX=PASS")


if __name__ == "__main__":
    asyncio.run(main())
