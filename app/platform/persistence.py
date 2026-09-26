"""PostgreSQL carriers for the kernel that the existing tables already provide.

* :class:`PostgresDenialAuditSink` writes policy/safety denials to the
  immutable ``middleware_control_audit`` (runtime SQL 0005).
* :class:`PostgresReconciliationSource` leases quarantined ``adapter-command``
  rows of ``middleware_outbox`` for the reconciler, counts reconciliation
  attempts in ``middleware_control_audit`` and records every resolution in
  ``middleware_reconciliation_audit``.

No new table, no new column: this is the schema proof of the V3 design.
"""

from __future__ import annotations

import json
from uuid import UUID

import asyncpg

from app.commands import ADAPTER_COMMAND_DESTINATION
from app.platform.kernel import DenialAudit, DenialAuditSink
from app.platform.reconciler import ReconciliationClaim
from app.storage import set_connection_tenant_context

RECONCILIATION_RESOURCE_KIND = "outbox_reconciliation"


class PostgresDenialAuditSink(DenialAuditSink):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def record(self, audit: DenialAudit) -> None:
        metadata = {
            "command_type": audit.command_type,
            "target": audit.target,
            "capability": audit.capability,
            "client_id": audit.client_id,
            "correlation_id": audit.correlation_id,
            "decision_id": audit.decision_id,
            "version": audit.version,
        }
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await set_connection_tenant_context(conn, audit.tenant_id)
                await conn.execute(
                """
                INSERT INTO middleware_control_audit (
                    tenant_id, resource_kind, resource_id, action, actor_id, reason,
                    previous_state, new_state, metadata
                ) VALUES ($1,'command_submission',$2,$3,$4,$5,NULL,'denied',$6::jsonb)
                """,
                audit.tenant_id,
                str(audit.command_id),
                audit.kind,
                audit.actor_id,
                audit.reason_code[:2048],
                json.dumps(metadata, separators=(",", ":"), sort_keys=True),
            )


class PostgresReconciliationSource:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def claim(self, *, tenant_id: str, reconciler_id: str, lease_seconds: float) -> ReconciliationClaim | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await set_connection_tenant_context(conn, tenant_id)
                row = await conn.fetchrow(
                    """
                    WITH candidate AS (
                        SELECT id
                        FROM middleware_outbox
                        WHERE tenant_id=$4
                          AND destination=$3
                          AND reconciliation_required_at IS NOT NULL
                          AND completed_at IS NULL
                          AND dead_lettered_at IS NULL
                          AND cancelled_at IS NULL
                          AND command_id IS NOT NULL
                          AND (lease_until IS NULL OR lease_until < now())
                        ORDER BY reconciliation_required_at, id
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE middleware_outbox o
                    SET lease_owner=$1,
                        lease_until=now() + ($2 * interval '1 second')
                    FROM candidate
                    WHERE o.id=candidate.id
                    RETURNING o.id, o.tenant_id, o.command_id
                    """,
                    reconciler_id,
                    lease_seconds,
                    ADAPTER_COMMAND_DESTINATION,
                    tenant_id,
                )
                if row is None:
                    return None
                await conn.execute(
                    """
                    INSERT INTO middleware_control_audit (
                        tenant_id, resource_kind, resource_id, action, actor_id, reason,
                        previous_state, new_state, metadata
                    ) VALUES ($1,$2,$3,'claim',$4,'reconciliation lease acquired','reconciliation_required','reconciliation_required','{}'::jsonb)
                    """,
                    row["tenant_id"],
                    RECONCILIATION_RESOURCE_KIND,
                    str(row["id"]),
                    reconciler_id,
                )
                attempts = await conn.fetchval(
                    """
                    SELECT count(*) FROM middleware_control_audit
                    WHERE resource_kind=$1 AND resource_id=$2 AND action='claim'
                    """,
                    RECONCILIATION_RESOURCE_KIND,
                    str(row["id"]),
                )
        return ReconciliationClaim(
            outbox_id=int(row["id"]),
            tenant_id=row["tenant_id"],
            command_id=UUID(str(row["command_id"])),
            reconciliation_attempts=int(attempts or 0),
        )

    async def resolve(self, claim: ReconciliationClaim, *, reconciler_id: str, action: str, reason: str) -> None:
        if action not in {"retry", "complete", "dead_letter"}:
            raise ValueError("unsupported reconciliation action")
        safe_reason = reason.strip()[:2048] or action
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await set_connection_tenant_context(conn, claim.tenant_id)
                row = await conn.fetchrow(
                    """
                    SELECT id, tenant_id, attempt_count FROM middleware_outbox
                    WHERE id=$1 AND lease_owner=$2 AND completed_at IS NULL AND dead_lettered_at IS NULL
                    FOR UPDATE
                    """,
                    claim.outbox_id,
                    reconciler_id,
                )
                if row is None:
                    raise RuntimeError("reconciliation lease ownership lost before resolution")
                await conn.execute(
                    """
                    INSERT INTO middleware_reconciliation_audit
                      (outbox_id, tenant_id, action, operator_id, reason, attempt_count)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    claim.outbox_id,
                    row["tenant_id"],
                    action,
                    reconciler_id[:160],
                    safe_reason,
                    row["attempt_count"],
                )
                if action == "retry":
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL, lease_owner=NULL, lease_until=NULL,
                            next_attempt_at=now(), last_error='reconciliation approved retry: ' || $2
                        WHERE id=$1
                        """,
                        claim.outbox_id,
                        safe_reason,
                    )
                elif action == "complete":
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL, lease_owner=NULL, lease_until=NULL,
                            completed_at=now(), last_error='reconciliation confirmed delivery: ' || $2
                        WHERE id=$1
                        """,
                        claim.outbox_id,
                        safe_reason,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL, lease_owner=NULL, lease_until=NULL,
                            dead_lettered_at=now(), last_error='reconciliation dead-lettered: ' || $2
                        WHERE id=$1
                        """,
                        claim.outbox_id,
                        safe_reason,
                    )

    async def release(self, claim: ReconciliationClaim, *, reconciler_id: str, reason: str) -> None:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await set_connection_tenant_context(conn, claim.tenant_id)
            result = await conn.execute(
                """
                UPDATE middleware_outbox
                SET lease_owner=NULL, lease_until=NULL, last_error=$3
                WHERE id=$1 AND lease_owner=$2
                """,
                claim.outbox_id,
                reconciler_id,
                reason.strip()[:2048],
            )
            if result != "UPDATE 1":
                raise RuntimeError("reconciliation lease ownership lost before release")

    async def backlog(self, tenant_id: str) -> int:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await set_connection_tenant_context(conn, tenant_id)
            value = await conn.fetchval(
                """
                SELECT count(*) FROM middleware_outbox
                WHERE tenant_id=$2 AND destination=$1 AND reconciliation_required_at IS NOT NULL
                  AND completed_at IS NULL AND dead_lettered_at IS NULL AND cancelled_at IS NULL
                """,
                ADAPTER_COMMAND_DESTINATION,
                tenant_id,
            )
        return int(value or 0)
