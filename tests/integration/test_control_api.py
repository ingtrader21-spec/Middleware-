import hashlib
import json
import os
from pathlib import Path

import asyncpg
import httpx
import pytest
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import PostgresInboxStore
from tests.test_commands import CommandTokenVerifier

pytestmark = pytest.mark.skipif(
    os.getenv("RUNTIME_INTEGRATION_TESTS") != "1", reason="disposable integration only"
)


@pytest.mark.asyncio
async def test_durable_inbox_outbox_control_api_is_tenant_scoped_and_idempotent(
    test_settings,
):
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    try:
        async with pool.acquire() as conn:
            for path in sorted(Path("migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")):
                await conn.execute(path.read_text())
            timeline_indexes = await conn.fetch(
                """SELECT indexname FROM pg_indexes
                   WHERE schemaname='public' AND indexname=ANY($1::text[])""",
                [
                    "middleware_control_audit_timeline_idx",
                    "middleware_command_audit_timeline_idx",
                ],
            )
            assert {row["indexname"] for row in timeline_indexes} == {
                "middleware_control_audit_timeline_idx",
                "middleware_command_audit_timeline_idx",
            }
            payload = {"event_id": "full-api-event-1", "tenant_id": "tenant-1"}
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            await conn.execute(
                """INSERT INTO middleware_inbox(event_id,tenant_id,source_client_id,event_type,body_sha256,semantic_sha256,idempotency_key,correlation_id,payload,status) VALUES('full-api-event-1','tenant-1','odoo-integration','codestra.odoo.lead.updated',$1,$1,'full-api-event-1','full-api-correlation',$2::jsonb,'accepted') ON CONFLICT DO NOTHING""",
                digest,
                json.dumps(payload),
            )
            await conn.execute(
                """INSERT INTO middleware_inbox(event_id,tenant_id,source_client_id,event_type,body_sha256,semantic_sha256,idempotency_key,correlation_id,payload,status,quarantined_at,quarantine_reason) VALUES('full-api-event-2','tenant-1','odoo-integration','codestra.odoo.lead.updated',$1,$1,'full-api-event-2','full-api-correlation-2',$2::jsonb,'rejected',now() - interval '1 second','operator_review') ON CONFLICT DO NOTHING""",
                digest,
                json.dumps(payload),
            )
            await conn.execute(
                """INSERT INTO middleware_event_ledger(tenant_id,tenant_sequence,event_id,event_type,event_version,source_client_id,correlation_id,causation_id,idempotency_key,semantic_sha256,previous_entry_hash,entry_hash,payload) VALUES('tenant-1',999999,'full-api-event-1','codestra.odoo.lead.updated','1.0','odoo-integration','full-api-correlation','full-api-cause','full-api-event-1',$1,$2,$2,$3::jsonb) ON CONFLICT DO NOTHING""",
                digest,
                "0" * 64,
                json.dumps(payload),
            )
            outbox_id = await conn.fetchval(
                """INSERT INTO middleware_outbox(tenant_id,destination,event_type,payload,idempotency_key) VALUES('tenant-1','nats-jetstream','full.api.test','{}','full-api-outbox') ON CONFLICT(tenant_id,destination,idempotency_key) DO UPDATE SET event_type=EXCLUDED.event_type RETURNING id"""
            )
            reconciliation_id = await conn.fetchval(
                """INSERT INTO middleware_outbox(tenant_id,destination,event_type,payload,idempotency_key,reconciliation_required_at,last_error) VALUES('tenant-1','nats-jetstream','full.api.reconcile','{}','full-api-reconcile',now(),'unknown outcome') ON CONFLICT(tenant_id,destination,idempotency_key) DO UPDATE SET reconciliation_required_at=now(),completed_at=NULL,dead_lettered_at=NULL,cancelled_at=NULL,lease_owner=NULL,lease_until=NULL,resource_version=1 RETURNING id"""
            )
            await conn.execute(
                """INSERT INTO middleware_outbox(tenant_id,destination,event_type,payload,idempotency_key,reconciliation_required_at,last_error) VALUES('tenant-1','nats-jetstream','full.api.reconcile','{}','full-api-reconcile-2',now() - interval '1 second','unknown outcome') ON CONFLICT(tenant_id,destination,idempotency_key) DO UPDATE SET reconciliation_required_at=now() - interval '1 second',completed_at=NULL,dead_lettered_at=NULL,cancelled_at=NULL,lease_owner=NULL,lease_until=NULL,resource_version=1"""
            )
        runtime = Runtime(
            settings=test_settings,
            inbox=PostgresInboxStore(pool),
            replay=MemoryReplayGuard(),
            tokens=CommandTokenVerifier(),
        )
        app = create_app(settings=test_settings, runtime=runtime)
        app.state.runtime = runtime
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            read = {
                "Authorization": "Bearer legacy-status-token",
                "X-Tenant-ID": "tenant-1",
            }
            assert (await client.get("/v1/inbox", headers=read)).status_code == 200
            assert (await client.get("/v1/outbox", headers=read)).status_code == 200
            mutation = {
                "Authorization": "Bearer legacy-command-token",
                "X-Tenant-ID": "tenant-1",
                "X-Correlation-ID": "full-api-correlation",
                "Idempotency-Key": "full-api-mutation",
            }
            first = await client.post(
                "/v1/inbox/full-api-event-1/quarantine",
                headers=mutation,
                json={"expected_version": 1, "reason": "operator_review"},
            )
            assert first.status_code == 200 and first.json()["resource_version"] == 2
            quarantine_page = await client.get(
                "/api/v1/quarantine/events?limit=1", headers=read
            )
            assert (
                quarantine_page.status_code == 200
                and quarantine_page.json()["next_cursor"]
            )
            quarantine_next = await client.get(
                "/api/v1/quarantine/events",
                headers=read,
                params={"limit": 1, "cursor": quarantine_page.json()["next_cursor"]},
            )
            assert quarantine_next.status_code == 200
            assert (
                quarantine_next.json()["items"][0]["event_id"]
                != quarantine_page.json()["items"][0]["event_id"]
            )
            replay = await client.post(
                "/v1/inbox/full-api-event-1/quarantine",
                headers=mutation,
                json={"expected_version": 1, "reason": "operator_review"},
            )
            assert replay.status_code == 200 and replay.json()["resource_version"] == 2
            changed = await client.post(
                "/v1/inbox/full-api-event-1/quarantine",
                headers=mutation,
                json={"expected_version": 1, "reason": "changed"},
            )
            assert changed.status_code == 409
            quarantine = await client.get(
                "/api/v1/quarantine/events/full-api-event-1", headers=read
            )
            assert (
                quarantine.status_code == 200
                and quarantine.json()["quarantined_at"] is not None
            )
            discarded = await client.post(
                "/api/v1/quarantine/events/full-api-event-1/discard",
                headers={**mutation, "Idempotency-Key": "full-api-discard"},
                json={"expected_version": 2, "reason": "evidence_retained_discard"},
            )
            assert (
                discarded.status_code == 200
                and discarded.json()["discarded_at"] is not None
            )
            assert discarded.json()["quarantined_at"] is None
            release = await client.post(
                "/api/v1/quarantine/events/full-api-event-1/release",
                headers={**mutation, "Idempotency-Key": "full-api-release-discarded"},
                json={"expected_version": 3, "reason": "must_not_resurrect"},
            )
            assert release.status_code == 409
            cancelled = await client.post(
                f"/v1/outbox/{outbox_id}/cancel",
                headers={**mutation, "Idempotency-Key": "full-api-outbox-cancel"},
                json={"expected_version": 1, "reason": "operator_requested"},
            )
            assert (
                cancelled.status_code == 200
                and cancelled.json()["state"] == "CANCELLED"
            )
            resolution_headers = {
                **mutation,
                "Idempotency-Key": "full-api-reconcile-resolve",
            }
            reconciliation_page = await client.get(
                "/api/v1/reconciliation/operations?limit=1", headers=read
            )
            assert (
                reconciliation_page.status_code == 200
                and reconciliation_page.json()["next_cursor"]
            )
            reconciliation_next = await client.get(
                "/api/v1/reconciliation/operations",
                headers=read,
                params={
                    "limit": 1,
                    "cursor": reconciliation_page.json()["next_cursor"],
                },
            )
            assert reconciliation_next.status_code == 200
            assert (
                reconciliation_next.json()["items"][0]["id"]
                != reconciliation_page.json()["items"][0]["id"]
            )
            resolved = await client.post(
                f"/api/v1/reconciliation/operations/{reconciliation_id}/resolve",
                headers=resolution_headers,
                json={
                    "expected_version": 1,
                    "action": "retry",
                    "reason": "operator_verified_no_effect",
                },
            )
            assert (
                resolved.status_code == 200
                and resolved.json()["state"] == "PENDING"
                and resolved.json()["resource_version"] == 2
            )
            replay = await client.post(
                f"/api/v1/reconciliation/operations/{reconciliation_id}/resolve",
                headers=resolution_headers,
                json={
                    "expected_version": 1,
                    "action": "retry",
                    "reason": "operator_verified_no_effect",
                },
            )
            assert replay.status_code == 200 and replay.json() == resolved.json()
            conflict = await client.post(
                f"/api/v1/reconciliation/operations/{reconciliation_id}/resolve",
                headers=resolution_headers,
                json={
                    "expected_version": 1,
                    "action": "complete",
                    "reason": "changed_semantics",
                },
            )
            assert conflict.status_code == 409
            audit_page = await client.get(
                "/v1/audit/events", headers=read, params={"limit": 1}
            )
            assert audit_page.status_code == 200
            assert len(audit_page.json()["items"]) == 1
            assert audit_page.json()["next_cursor"]
            audit_next = await client.get(
                "/v1/audit/events",
                headers=read,
                params={"limit": 1, "cursor": audit_page.json()["next_cursor"]},
            )
            assert audit_next.status_code == 200
            assert len(audit_next.json()["items"]) == 1
            first = audit_page.json()["items"][0]
            second = audit_next.json()["items"][0]
            assert (first["created_at"], first["authority"], first["id"]) != (
                second["created_at"],
                second["authority"],
                second["id"],
            )
            malformed_audit = await client.get(
                "/v1/audit/events", headers=read, params={"cursor": "not-a-cursor"}
            )
            assert malformed_audit.status_code == 400
            hidden = await client.get(
                f"/api/v1/reconciliation/operations/{reconciliation_id}",
                headers={
                    "Authorization": "Bearer legacy-status-token",
                    "X-Tenant-ID": "tenant-2",
                },
            )
            assert hidden.status_code == 403
        async with pool.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM middleware_reconciliation_audit WHERE tenant_id='tenant-1' AND outbox_id=$1",
                    reconciliation_id,
                )
                == 1
            )
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM middleware_control_mutations WHERE tenant_id='tenant-1' AND resource_kind='outbox' AND resource_id=$1 AND action='resolve:retry'",
                    str(reconciliation_id),
                )
                == 1
            )
    finally:
        await pool.close()
