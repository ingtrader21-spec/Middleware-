from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.sales.compliance import ComplianceSnapshot
from app.sales.odoo import FakeOdooReadOnlyAdapter, OdooLookup
from app.sales.repository import SalesRepository
from app.sales.service import SalesConflict, SalesLeadService
from tests.test_sales_lead_foundation import candidate


DATABASE_URL = os.getenv("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="isolated PostgreSQL is required"
)


def run(value):
    return asyncio.run(value)


def test_database_idempotency_tenant_isolation_audit_and_zero_writes():
    async def scenario():
        engine = create_async_engine(DATABASE_URL)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        repository = SalesRepository(sessions)
        adapter = FakeOdooReadOnlyAdapter(
            OdooLookup(
                compliance=ComplianceSnapshot(
                    "tenant-a", "campaign-a", consent="GRANTED", channel_eligible=True
                )
            )
        )
        service = SalesLeadService(adapter)
        first, replay = await repository.resolve(
            candidate(), "database-idempotency-0001", "corr-db-1", service
        )
        repeated, replay2 = await repository.resolve(
            candidate(), "database-idempotency-0001", "corr-db-2", service
        )
        assert first == repeated and not replay and replay2
        changed = candidate(
            company={**candidate().company.model_dump(), "name": "Changed Company"}
        )
        with pytest.raises(SalesConflict):
            await repository.resolve(
                changed, "database-idempotency-0001", "corr-db-3", service
            )
        foreign = candidate(tenant_id="tenant-b")
        foreign_result, _ = await repository.resolve(
            foreign, "database-idempotency-0001", "corr-db-4", service
        )
        assert foreign_result.candidate_id != first.candidate_id
        async with sessions() as session:
            counts = {
                name: await session.scalar(text(f"SELECT count(*) FROM {name}"))
                for name in (
                    "sales_lead_candidate",
                    "sales_identity_resolution",
                    "sales_idempotency",
                )
            }
            audit_count = await session.scalar(
                text(
                    "SELECT count(*) FROM audit_event WHERE action LIKE 'lead_candidate.%' "
                    "OR action IN ('identity_resolution.completed','compliance_gate.evaluated')"
                )
            )
        assert counts == {
            "sales_lead_candidate": 2,
            "sales_identity_resolution": 2,
            "sales_idempotency": 2,
        }
        assert audit_count == 6
        assert adapter.create_count == adapter.update_count == adapter.delete_count == 0
        assert service.vicidial_write_count == service.outreach_event_count == 0
        await engine.dispose()

    run(scenario())
