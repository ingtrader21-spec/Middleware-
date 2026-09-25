"""Durable, no-effect MCR -> Odoo handoff authority.

This module persists acceptance/readback/reconciliation intent only.  It never
calls Odoo and does not register an outbound command adapter.  HTTP activation
is intentionally separate because MCR-E's service-client assignment is not yet
frozen in Keycloak.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import UUID, uuid4

import asyncpg


class McrOdooHandoffError(RuntimeError):
    pass


class McrOdooHandoffConflict(McrOdooHandoffError):
    pass


class McrOdooHandoffNotFound(McrOdooHandoffError):
    pass


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def command_payload_hash(command: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(command)).hexdigest()


def natural_key(command: Mapping[str, Any]) -> tuple[Any, ...]:
    payload = command["payload"]
    return (
        command["tenant_id"],
        payload["lead_id"],
        payload["campaign_id"],
        payload["campaign_version"],
        payload["lifecycle_version"],
        payload["policy_version"],
        payload["handoff"],
    )


def expected_idempotency_key(command: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        _canonical_json(
            {
                "tenant_id": natural_key(command)[0],
                "lead_id": natural_key(command)[1],
                "campaign_id": natural_key(command)[2],
                "campaign_version": natural_key(command)[3],
                "lifecycle_version": natural_key(command)[4],
                "policy_version": natural_key(command)[5],
                "handoff": natural_key(command)[6],
            }
        )
    ).hexdigest()
    return "mcrodoo1:" + digest


@dataclass(frozen=True)
class HandoffAcceptance:
    command_id: UUID
    correlation_id: str
    idempotency_key: str
    duplicate: bool


class PostgresMcrOdooHandoffStore:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def accept(
        self,
        command: Mapping[str, Any],
        *,
        causation_id: str,
        accepted_at: datetime | None = None,
    ) -> HandoffAcceptance:
        if command.get("command_type") != "crm.lifecycle.handoff":
            raise McrOdooHandoffConflict("unexpected command_type")
        if command.get("target") != "odoo-19":
            raise McrOdooHandoffConflict("unexpected target")
        if command.get("capability") != "ODOO_WRITE":
            raise McrOdooHandoffConflict("unexpected capability")
        payload = command.get("payload")
        if not isinstance(payload, Mapping):
            raise McrOdooHandoffConflict("payload is required")
        if payload.get("dry_run") is not True or payload.get("allow_external_contact") is not False:
            raise McrOdooHandoffConflict("handoff runtime remains no-effect")
        key = str(command.get("idempotency_key", ""))
        if key != expected_idempotency_key(command):
            raise McrOdooHandoffConflict("idempotency key does not match natural identity")
        command_id = UUID(str(command["command_id"]))
        correlation_id = str(command["correlation_id"])
        digest = command_payload_hash(command)
        now = accepted_at or datetime.now(UTC)
        nk = natural_key(command)

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO mcr_odoo_handoffs (
                      tenant_id,command_id,lead_id,campaign_id,campaign_version,
                      lifecycle_version,policy_version,handoff,idempotency_key,
                      correlation_id,causation_id,payload_hash,status,
                      odoo_record_id,observed_lifecycle_version,observed_at,
                      created_at,updated_at
                    ) VALUES (
                      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                      'accepted',NULL,NULL,$13,$13,$13
                    )
                    ON CONFLICT DO NOTHING
                    RETURNING command_id
                    """,
                    nk[0],
                    command_id,
                    *nk[1:],
                    key,
                    correlation_id,
                    causation_id,
                    digest,
                    now,
                )
                if row is not None:
                    return HandoffAcceptance(command_id, correlation_id, key, False)

                existing = await conn.fetchrow(
                    """
                    SELECT command_id,idempotency_key,correlation_id,payload_hash,
                           lead_id,campaign_id,campaign_version,lifecycle_version,
                           policy_version,handoff
                    FROM mcr_odoo_handoffs
                    WHERE tenant_id=$1 AND (
                      idempotency_key=$2 OR
                      (lead_id=$3 AND campaign_id=$4 AND campaign_version=$5
                       AND lifecycle_version=$6 AND policy_version=$7 AND handoff=$8)
                    )
                    FOR UPDATE
                    """,
                    nk[0], key, *nk[1:],
                )
                if existing is None:
                    raise McrOdooHandoffConflict("handoff conflict could not be reconciled")
                same = (
                    str(existing["command_id"]) == str(command_id)
                    and existing["idempotency_key"] == key
                    and existing["correlation_id"] == correlation_id
                    and existing["payload_hash"] == digest
                    and (
                        existing["lead_id"],
                        existing["campaign_id"],
                        existing["campaign_version"],
                        existing["lifecycle_version"],
                        existing["policy_version"],
                        existing["handoff"],
                    ) == nk[1:]
                )
                if not same:
                    raise McrOdooHandoffConflict(
                        "handoff identity was reused with different evidence"
                    )
                return HandoffAcceptance(command_id, correlation_id, key, True)

    async def readback(self, tenant_id: str, command_id: UUID) -> dict[str, Any]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT tenant_id,command_id,lead_id,campaign_id,campaign_version,
                       lifecycle_version,policy_version,handoff,idempotency_key,
                       correlation_id,payload_hash,status,odoo_record_id,
                       observed_lifecycle_version,observed_at
                FROM mcr_odoo_handoffs
                WHERE tenant_id=$1 AND command_id=$2
                """,
                tenant_id,
                command_id,
            )
        if row is None:
            raise McrOdooHandoffNotFound("handoff not found")
        return {
            "schema_version": "1.0",
            "tenant_id": row["tenant_id"],
            "lead_id": row["lead_id"],
            "campaign_id": row["campaign_id"],
            "campaign_version": row["campaign_version"],
            "lifecycle_version": row["lifecycle_version"],
            "policy_version": row["policy_version"],
            "handoff": row["handoff"],
            "command_id": str(row["command_id"]),
            "correlation_id": row["correlation_id"],
            "idempotency_key": row["idempotency_key"],
            "payload_hash": row["payload_hash"],
            "status": row["status"],
            "odoo_record_id": row["odoo_record_id"],
            "observed_lifecycle_version": row["observed_lifecycle_version"],
            "observed_at": row["observed_at"].isoformat(),
        }

    async def request_reconciliation(
        self,
        tenant_id: str,
        command_id: UUID,
        *,
        idempotency_key: str,
        correlation_id: str,
        causation_id: str,
        requested_at: datetime | None = None,
    ) -> dict[str, Any]:
        now = requested_at or datetime.now(UTC)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                exists = await conn.fetchval(
                    """
                    SELECT 1 FROM mcr_odoo_handoffs
                    WHERE tenant_id=$1 AND command_id=$2
                    """,
                    tenant_id,
                    command_id,
                )
                if not exists:
                    raise McrOdooHandoffNotFound("handoff not found")
                inserted = await conn.fetchrow(
                    """
                    INSERT INTO mcr_odoo_handoff_reconciliations (
                      reconciliation_id,tenant_id,command_id,idempotency_key,
                      correlation_id,causation_id,requested_at
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                    ON CONFLICT DO NOTHING
                    RETURNING reconciliation_id
                    """,
                    uuid4(), tenant_id, command_id, idempotency_key,
                    correlation_id, causation_id, now,
                )
                if inserted is None:
                    row = await conn.fetchrow(
                        """
                        SELECT command_id,correlation_id,causation_id
                        FROM mcr_odoo_handoff_reconciliations
                        WHERE tenant_id=$1 AND idempotency_key=$2
                        """,
                        tenant_id,
                        idempotency_key,
                    )
                    if (
                        row is None
                        or str(row["command_id"]) != str(command_id)
                        or row["correlation_id"] != correlation_id
                        or row["causation_id"] != causation_id
                    ):
                        raise McrOdooHandoffConflict(
                            "reconciliation idempotency key reused with different evidence"
                        )
        # No provider/Odoo read is performed here. The current durable readback is
        # returned; a future certified reconciler may update observed status.
        return await self.readback(tenant_id, command_id)
