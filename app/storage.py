from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

import asyncpg

from .models import EventEnvelope, IngressResult


RUNTIME_SCHEMA_VERSION = 11
DEFAULT_MAX_OUTBOX_ATTEMPTS = 8
NATS_JETSTREAM_DESTINATION = "nats-jetstream"
KLYROW_ODOO_PROJECTION_DESTINATION = "odoo-klyrow-projection-v1"
ReconciliationAction = Literal["retry", "complete", "dead_letter"]


class StorageError(RuntimeError):
    code = "dependency_unavailable"
    retryable = True


class ReplayConflict(StorageError):
    code = "idempotency_conflict"
    retryable = False


class ReconciliationError(StorageError):
    code = "reconciliation_invalid"
    retryable = False


class EventLedgerIntegrityError(StorageError):
    code = "event_ledger_integrity_error"
    retryable = False


ZERO_LEDGER_HASH = "0" * 64


def canonical_payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def event_ledger_hash(
    *,
    tenant_id: str,
    tenant_sequence: int,
    event_id: str,
    semantic_sha256: str,
    previous_entry_hash: str,
) -> str:
    value = json.dumps(
        [
            "codestra-event-ledger-v1",
            tenant_id,
            tenant_sequence,
            event_id,
            semantic_sha256,
            previous_entry_hash,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class EventLedgerRecord:
    tenant_id: str
    tenant_sequence: int
    event_id: str
    semantic_sha256: str
    previous_entry_hash: str
    entry_hash: str
    payload: dict[str, Any]


def verify_event_ledger_records(
    records: list[EventLedgerRecord],
) -> dict[str, int]:
    expected_sequence: dict[str, int] = {}
    previous_hash: dict[str, str] = {}
    counts: dict[str, int] = {}
    for record in sorted(
        records, key=lambda item: (item.tenant_id, item.tenant_sequence)
    ):
        expected = expected_sequence.get(record.tenant_id, 1)
        previous = previous_hash.get(record.tenant_id, ZERO_LEDGER_HASH)
        if record.tenant_sequence != expected:
            raise EventLedgerIntegrityError(
                f"event ledger sequence gap for tenant {record.tenant_id}"
            )
        if record.previous_entry_hash != previous:
            raise EventLedgerIntegrityError(
                f"event ledger previous hash mismatch for tenant {record.tenant_id}"
            )
        semantic = canonical_payload_sha256(record.payload)
        if semantic != record.semantic_sha256:
            raise EventLedgerIntegrityError(
                f"event ledger payload hash mismatch for tenant {record.tenant_id}"
            )
        expected_hash = event_ledger_hash(
            tenant_id=record.tenant_id,
            tenant_sequence=record.tenant_sequence,
            event_id=record.event_id,
            semantic_sha256=record.semantic_sha256,
            previous_entry_hash=record.previous_entry_hash,
        )
        if record.entry_hash != expected_hash:
            raise EventLedgerIntegrityError(
                f"event ledger entry hash mismatch for tenant {record.tenant_id}"
            )
        expected_sequence[record.tenant_id] = expected + 1
        previous_hash[record.tenant_id] = record.entry_hash
        counts[record.tenant_id] = counts.get(record.tenant_id, 0) + 1
    return counts


class InboxStore(Protocol):
    async def accept(
        self,
        envelope: EventEnvelope,
        *,
        producer_client_id: str,
        body_sha256: str,
        semantic_sha256: str,
        deduplication_sha256: str | None = None,
        destination: str = NATS_JETSTREAM_DESTINATION,
    ) -> IngressResult: ...

    async def ready(self) -> bool: ...

    async def close(self) -> None: ...


class MemoryInboxStore:
    """Test/development-only storage matching PostgreSQL identity constraints."""

    def __init__(self) -> None:
        self._event_items: dict[tuple[str, str], tuple[str, IngressResult]] = {}
        self._idempotency_items: dict[tuple[str, str], tuple[str, IngressResult]] = {}
        self.ledger_records: list[EventLedgerRecord] = []
        self._ledger_heads: dict[str, str] = {}
        self._ledger_counts: dict[str, int] = {}

    async def accept(
        self,
        envelope: EventEnvelope,
        *,
        producer_client_id: str,
        body_sha256: str,
        semantic_sha256: str,
        deduplication_sha256: str | None = None,
        destination: str = NATS_JETSTREAM_DESTINATION,
    ) -> IngressResult:
        payload = envelope.model_dump(mode="json")
        if canonical_payload_sha256(payload) != semantic_sha256:
            raise EventLedgerIntegrityError(
                "semantic hash does not match the canonical event payload"
            )
        comparison_sha256 = deduplication_sha256 or semantic_sha256
        event_key = (
            (producer_client_id, envelope.event_id)
            if deduplication_sha256 is not None
            else (envelope.tenant_id, envelope.event_id)
        )
        idempotency_key = (envelope.tenant_id, envelope.idempotency_key)
        event_existing = self._event_items.get(event_key)
        idem_existing = self._idempotency_items.get(idempotency_key)

        if (
            event_existing
            and idem_existing
            and event_existing[1].event_id != idem_existing[1].event_id
        ):
            raise ReplayConflict(
                "event and idempotency identities refer to different accepted events"
            )

        existing = event_existing or idem_existing
        if existing:
            old_comparison_hash, result = existing
            if old_comparison_hash != comparison_sha256:
                raise ReplayConflict(
                    "event/idempotency identity was reused with a different semantic payload"
                )
            return result.model_copy(update={"status": "duplicate", "duplicate": True})

        result = IngressResult(
            event_id=envelope.event_id,
            tenant_id=envelope.tenant_id,
            status="accepted",
            duplicate=False,
            correlation_id=envelope.correlation_id,
        )
        item = (comparison_sha256, result)
        self._event_items[event_key] = item
        self._idempotency_items[idempotency_key] = item
        tenant_sequence = self._ledger_counts.get(envelope.tenant_id, 0) + 1
        previous_entry_hash = self._ledger_heads.get(
            envelope.tenant_id,
            ZERO_LEDGER_HASH,
        )
        entry_hash = event_ledger_hash(
            tenant_id=envelope.tenant_id,
            tenant_sequence=tenant_sequence,
            event_id=envelope.event_id,
            semantic_sha256=semantic_sha256,
            previous_entry_hash=previous_entry_hash,
        )
        self.ledger_records.append(
            EventLedgerRecord(
                tenant_id=envelope.tenant_id,
                tenant_sequence=tenant_sequence,
                event_id=envelope.event_id,
                semantic_sha256=semantic_sha256,
                previous_entry_hash=previous_entry_hash,
                entry_hash=entry_hash,
                payload=payload,
            )
        )
        self._ledger_counts[envelope.tenant_id] = tenant_sequence
        self._ledger_heads[envelope.tenant_id] = entry_hash
        return result

    async def ready(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class PostgresInboxStore:
    REQUIRED_COLUMNS = {
        "middleware_schema_migrations": {"version", "name", "applied_at"},
        "middleware_inbox": {
            "event_id",
            "tenant_id",
            "source_client_id",
            "event_type",
            "body_sha256",
            "semantic_sha256",
            "idempotency_key",
            "correlation_id",
            "payload",
            "received_at",
            "status",
            "processed_at",
            "last_error",
            "resource_version",
            "quarantined_at",
            "quarantine_reason",
            "released_at",
            "reprocess_requested_at",
            "discarded_at",
            "discard_reason",
        },
        "middleware_outbox": {
            "id",
            "tenant_id",
            "destination",
            "event_type",
            "payload",
            "idempotency_key",
            "created_at",
            "next_attempt_at",
            "attempt_count",
            "lease_owner",
            "lease_until",
            "completed_at",
            "dead_lettered_at",
            "reconciliation_required_at",
            "last_error",
            "command_id",
            "cancelled_at",
            "resource_version",
        },
        "middleware_communication_messages": {
            "tenant_id",
            "message_id",
            "payload",
            "updated_at",
        },
        "middleware_communication_events": {
            "id",
            "tenant_id",
            "event_id",
            "message_id",
            "occurred_at",
            "payload",
        },
        "middleware_communication_idempotency": {
            "tenant_id",
            "route",
            "idempotency_key",
            "request_sha256",
            "message_id",
            "created_at",
        },
        "middleware_communication_provider_events": {
            "tenant_id",
            "provider_event_id",
            "request_sha256",
            "created_at",
        },
        "middleware_communication_suppressions": {
            "tenant_id",
            "channel",
            "subject",
            "created_at",
        },
        "middleware_communication_cancellations": {
            "tenant_id",
            "message_id",
            "idempotency_key",
            "created_at",
        },
        "middleware_reconciliation_audit": {
            "id",
            "outbox_id",
            "tenant_id",
            "action",
            "operator_id",
            "reason",
            "attempt_count",
            "created_at",
        },
        "middleware_event_ledger": {
            "ledger_id",
            "tenant_id",
            "tenant_sequence",
            "event_id",
            "event_type",
            "event_version",
            "source_client_id",
            "correlation_id",
            "causation_id",
            "idempotency_key",
            "semantic_sha256",
            "previous_entry_hash",
            "entry_hash",
            "payload",
            "recorded_at",
        },
        "middleware_operation_mutations": {
            "id",
            "tenant_id",
            "command_id",
            "action",
            "actor_id",
            "idempotency_key",
            "request_sha256",
            "response_status",
            "response_payload",
            "created_at",
        },
        "middleware_control_mutations": {
            "id",
            "tenant_id",
            "resource_kind",
            "resource_id",
            "action",
            "actor_id",
            "api_version",
            "idempotency_key",
            "request_sha256",
            "response_status",
            "response_payload",
            "created_at",
        },
        "middleware_control_audit": {
            "id",
            "tenant_id",
            "resource_kind",
            "resource_id",
            "action",
            "actor_id",
            "reason",
            "previous_state",
            "new_state",
            "metadata",
            "created_at",
        },
        "middleware_outbox_attempt_events": {
            "id",
            "outbox_id",
            "tenant_id",
            "attempt_number",
            "event_type",
            "worker_id",
            "safe_error_code",
            "created_at",
        },
    }
    REQUIRED_UDT_TYPES = {
        ("middleware_communication_messages", "tenant_id"): "text",
        ("middleware_communication_messages", "message_id"): "uuid",
        ("middleware_communication_messages", "payload"): "jsonb",
        ("middleware_communication_messages", "updated_at"): "timestamptz",
        ("middleware_communication_events", "id"): "int8",
        ("middleware_communication_events", "tenant_id"): "text",
        ("middleware_communication_events", "event_id"): "uuid",
        ("middleware_communication_events", "message_id"): "uuid",
        ("middleware_communication_events", "occurred_at"): "timestamptz",
        ("middleware_communication_events", "payload"): "jsonb",
        ("middleware_communication_idempotency", "tenant_id"): "text",
        ("middleware_communication_idempotency", "route"): "text",
        ("middleware_communication_idempotency", "idempotency_key"): "text",
        ("middleware_communication_idempotency", "request_sha256"): "bpchar",
        ("middleware_communication_idempotency", "message_id"): "uuid",
        ("middleware_communication_idempotency", "created_at"): "timestamptz",
        ("middleware_communication_provider_events", "tenant_id"): "text",
        ("middleware_communication_provider_events", "provider_event_id"): "text",
        ("middleware_communication_provider_events", "request_sha256"): "bpchar",
        ("middleware_communication_provider_events", "created_at"): "timestamptz",
        ("middleware_communication_suppressions", "tenant_id"): "text",
        ("middleware_communication_suppressions", "channel"): "text",
        ("middleware_communication_suppressions", "subject"): "text",
        ("middleware_communication_suppressions", "created_at"): "timestamptz",
        ("middleware_communication_cancellations", "tenant_id"): "text",
        ("middleware_communication_cancellations", "message_id"): "uuid",
        ("middleware_communication_cancellations", "idempotency_key"): "text",
        ("middleware_communication_cancellations", "created_at"): "timestamptz",
        ("middleware_schema_migrations", "version"): "int4",
        ("middleware_schema_migrations", "name"): "text",
        ("middleware_schema_migrations", "applied_at"): "timestamptz",
        ("middleware_inbox", "event_id"): "text",
        ("middleware_inbox", "tenant_id"): "text",
        ("middleware_inbox", "source_client_id"): "text",
        ("middleware_inbox", "event_type"): "text",
        ("middleware_inbox", "body_sha256"): "bpchar",
        ("middleware_inbox", "semantic_sha256"): "bpchar",
        ("middleware_inbox", "idempotency_key"): "text",
        ("middleware_inbox", "correlation_id"): "text",
        ("middleware_inbox", "payload"): "jsonb",
        ("middleware_inbox", "received_at"): "timestamptz",
        ("middleware_inbox", "status"): "text",
        ("middleware_inbox", "processed_at"): "timestamptz",
        ("middleware_inbox", "last_error"): "text",
        ("middleware_inbox", "resource_version"): "int8",
        ("middleware_inbox", "quarantined_at"): "timestamptz",
        ("middleware_inbox", "quarantine_reason"): "text",
        ("middleware_inbox", "released_at"): "timestamptz",
        ("middleware_inbox", "reprocess_requested_at"): "timestamptz",
        ("middleware_inbox", "discarded_at"): "timestamptz",
        ("middleware_inbox", "discard_reason"): "text",
        ("middleware_outbox", "id"): "int8",
        ("middleware_outbox", "tenant_id"): "text",
        ("middleware_outbox", "destination"): "text",
        ("middleware_outbox", "event_type"): "text",
        ("middleware_outbox", "payload"): "jsonb",
        ("middleware_outbox", "idempotency_key"): "text",
        ("middleware_outbox", "created_at"): "timestamptz",
        ("middleware_outbox", "next_attempt_at"): "timestamptz",
        ("middleware_outbox", "attempt_count"): "int4",
        ("middleware_outbox", "lease_owner"): "text",
        ("middleware_outbox", "lease_until"): "timestamptz",
        ("middleware_outbox", "completed_at"): "timestamptz",
        ("middleware_outbox", "dead_lettered_at"): "timestamptz",
        ("middleware_outbox", "reconciliation_required_at"): "timestamptz",
        ("middleware_outbox", "last_error"): "text",
        ("middleware_outbox", "command_id"): "text",
        ("middleware_outbox", "cancelled_at"): "timestamptz",
        ("middleware_outbox", "resource_version"): "int8",
        ("middleware_reconciliation_audit", "id"): "int8",
        ("middleware_reconciliation_audit", "outbox_id"): "int8",
        ("middleware_reconciliation_audit", "tenant_id"): "text",
        ("middleware_reconciliation_audit", "action"): "text",
        ("middleware_reconciliation_audit", "operator_id"): "text",
        ("middleware_reconciliation_audit", "reason"): "text",
        ("middleware_reconciliation_audit", "attempt_count"): "int4",
        ("middleware_reconciliation_audit", "created_at"): "timestamptz",
        ("middleware_event_ledger", "ledger_id"): "int8",
        ("middleware_event_ledger", "tenant_id"): "text",
        ("middleware_event_ledger", "tenant_sequence"): "int8",
        ("middleware_event_ledger", "event_id"): "text",
        ("middleware_event_ledger", "event_type"): "text",
        ("middleware_event_ledger", "event_version"): "text",
        ("middleware_event_ledger", "source_client_id"): "text",
        ("middleware_event_ledger", "correlation_id"): "text",
        ("middleware_event_ledger", "causation_id"): "text",
        ("middleware_event_ledger", "idempotency_key"): "text",
        ("middleware_event_ledger", "semantic_sha256"): "bpchar",
        ("middleware_event_ledger", "previous_entry_hash"): "bpchar",
        ("middleware_event_ledger", "entry_hash"): "bpchar",
        ("middleware_event_ledger", "payload"): "jsonb",
        ("middleware_event_ledger", "recorded_at"): "timestamptz",
        ("middleware_operation_mutations", "id"): "int8",
        ("middleware_operation_mutations", "tenant_id"): "text",
        ("middleware_operation_mutations", "command_id"): "text",
        ("middleware_operation_mutations", "action"): "text",
        ("middleware_operation_mutations", "actor_id"): "text",
        ("middleware_operation_mutations", "idempotency_key"): "text",
        ("middleware_operation_mutations", "request_sha256"): "bpchar",
        ("middleware_operation_mutations", "response_status"): "int4",
        ("middleware_operation_mutations", "response_payload"): "jsonb",
        ("middleware_operation_mutations", "created_at"): "timestamptz",
        ("middleware_control_mutations", "id"): "int8",
        ("middleware_control_mutations", "tenant_id"): "text",
        ("middleware_control_mutations", "resource_kind"): "text",
        ("middleware_control_mutations", "resource_id"): "text",
        ("middleware_control_mutations", "action"): "text",
        ("middleware_control_mutations", "actor_id"): "text",
        ("middleware_control_mutations", "api_version"): "text",
        ("middleware_control_mutations", "idempotency_key"): "text",
        ("middleware_control_mutations", "request_sha256"): "bpchar",
        ("middleware_control_mutations", "response_status"): "int4",
        ("middleware_control_mutations", "response_payload"): "jsonb",
        ("middleware_control_mutations", "created_at"): "timestamptz",
        ("middleware_control_audit", "id"): "int8",
        ("middleware_control_audit", "tenant_id"): "text",
        ("middleware_control_audit", "resource_kind"): "text",
        ("middleware_control_audit", "resource_id"): "text",
        ("middleware_control_audit", "action"): "text",
        ("middleware_control_audit", "actor_id"): "text",
        ("middleware_control_audit", "reason"): "text",
        ("middleware_control_audit", "previous_state"): "text",
        ("middleware_control_audit", "new_state"): "text",
        ("middleware_control_audit", "metadata"): "jsonb",
        ("middleware_control_audit", "created_at"): "timestamptz",
        ("middleware_outbox_attempt_events", "id"): "int8",
        ("middleware_outbox_attempt_events", "outbox_id"): "int8",
        ("middleware_outbox_attempt_events", "tenant_id"): "text",
        ("middleware_outbox_attempt_events", "attempt_number"): "int4",
        ("middleware_outbox_attempt_events", "event_type"): "text",
        ("middleware_outbox_attempt_events", "worker_id"): "text",
        ("middleware_outbox_attempt_events", "safe_error_code"): "text",
        ("middleware_outbox_attempt_events", "created_at"): "timestamptz",
    }
    REQUIRED_KEYS = {
        ("middleware_schema_migrations", "PRIMARY KEY", ("version",)),
        ("middleware_inbox", "PRIMARY KEY", ("tenant_id", "event_id")),
        ("middleware_inbox", "UNIQUE", ("tenant_id", "idempotency_key")),
        ("middleware_outbox", "PRIMARY KEY", ("id",)),
        (
            "middleware_outbox",
            "UNIQUE",
            ("tenant_id", "destination", "idempotency_key"),
        ),
        ("middleware_reconciliation_audit", "PRIMARY KEY", ("id",)),
        ("middleware_event_ledger", "PRIMARY KEY", ("ledger_id",)),
        (
            "middleware_event_ledger",
            "UNIQUE",
            ("tenant_id", "tenant_sequence"),
        ),
        ("middleware_event_ledger", "UNIQUE", ("tenant_id", "event_id")),
        (
            "middleware_event_ledger",
            "UNIQUE",
            ("tenant_id", "idempotency_key"),
        ),
        ("middleware_operation_mutations", "PRIMARY KEY", ("id",)),
        (
            "middleware_operation_mutations",
            "UNIQUE",
            ("tenant_id", "command_id", "action", "actor_id", "idempotency_key"),
        ),
        ("middleware_control_mutations", "PRIMARY KEY", ("id",)),
        (
            "middleware_control_mutations",
            "UNIQUE",
            (
                "tenant_id",
                "resource_kind",
                "resource_id",
                "action",
                "actor_id",
                "api_version",
                "idempotency_key",
            ),
        ),
        ("middleware_control_audit", "PRIMARY KEY", ("id",)),
        ("middleware_outbox_attempt_events", "PRIMARY KEY", ("id",)),
    }
    REQUIRED_TRIGGERS = {
        "middleware_event_ledger_immutable",
        "middleware_command_audit_immutable",
        "middleware_reconciliation_audit_immutable",
        "middleware_operation_mutations_immutable",
        "middleware_control_mutations_immutable",
        "middleware_control_audit_immutable",
        "middleware_outbox_attempt_events_immutable",
    }

    def __init__(self, pool: asyncpg.Pool, *, owns_pool: bool = True) -> None:
        self.pool = pool
        # A pool shared through RuntimeContainer is closed by the container.
        self.owns_pool = owns_pool

    @classmethod
    async def connect(cls, database_url: str) -> "PostgresInboxStore":
        pool = await asyncpg.create_pool(
            database_url,
            min_size=1,
            max_size=10,
            command_timeout=10,
        )
        store = cls(pool)
        try:
            await store.verify_schema()
        except Exception:
            await pool.close()
            raise
        return store

    async def verify_schema(self) -> None:
        async with self.pool.acquire() as conn:
            head = await conn.fetchval(
                "SELECT max(version) FROM middleware_schema_migrations"
            )
            if head != RUNTIME_SCHEMA_VERSION:
                raise StorageError(
                    f"runtime schema head mismatch: expected {RUNTIME_SCHEMA_VERSION}, got {head!r}"
                )
            rows = await conn.fetch(
                """
                SELECT table_name, column_name, udt_name
                FROM information_schema.columns
                WHERE table_schema='public'
                  AND table_name = ANY($1::text[])
                """,
                list(self.REQUIRED_COLUMNS),
            )
            columns: dict[str, set[str]] = {
                table: set() for table in self.REQUIRED_COLUMNS
            }
            types: dict[tuple[str, str], str] = {}
            for row in rows:
                columns[row["table_name"]].add(row["column_name"])
                types[(row["table_name"], row["column_name"])] = row["udt_name"]
            for table, required in self.REQUIRED_COLUMNS.items():
                missing = required - columns.get(table, set())
                if missing:
                    raise StorageError(
                        f"runtime schema table {table} is missing columns: {sorted(missing)}"
                    )
            for key, expected_type in self.REQUIRED_UDT_TYPES.items():
                if types.get(key) != expected_type:
                    raise StorageError(
                        f"runtime schema type mismatch for {key[0]}.{key[1]}: "
                        f"expected {expected_type}, got {types.get(key)!r}"
                    )
            key_rows = await conn.fetch(
                """
                SELECT tc.table_name,
                       tc.constraint_type,
                       array_agg(kcu.column_name ORDER BY kcu.ordinal_position) AS columns
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_schema = kcu.constraint_schema
                 AND tc.constraint_name = kcu.constraint_name
                 AND tc.table_name = kcu.table_name
                WHERE tc.table_schema='public'
                  AND tc.table_name = ANY($1::text[])
                  AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE')
                GROUP BY tc.table_name, tc.constraint_type, tc.constraint_name
                """,
                list(self.REQUIRED_COLUMNS),
            )
            found_keys = {
                (
                    row["table_name"],
                    row["constraint_type"],
                    tuple(row["columns"]),
                )
                for row in key_rows
            }
            missing_keys = self.REQUIRED_KEYS - found_keys
            if missing_keys:
                raise StorageError(
                    f"runtime schema is missing key constraints: {sorted(missing_keys)}"
                )
            trigger_rows = await conn.fetch(
                """
                SELECT tgname, tgenabled::text AS tgenabled
                FROM pg_trigger
                WHERE NOT tgisinternal AND tgname=ANY($1::text[])
                """,
                list(self.REQUIRED_TRIGGERS),
            )
            enabled_triggers = {
                row["tgname"] for row in trigger_rows if row["tgenabled"] == "O"
            }
            if enabled_triggers != self.REQUIRED_TRIGGERS:
                raise StorageError(
                    "runtime schema is missing enabled immutable-ledger triggers"
                )

    async def accept(
        self,
        envelope: EventEnvelope,
        *,
        producer_client_id: str,
        body_sha256: str,
        semantic_sha256: str,
        deduplication_sha256: str | None = None,
        destination: str = NATS_JETSTREAM_DESTINATION,
    ) -> IngressResult:
        payload = envelope.model_dump(mode="json")
        calculated_semantic_sha = canonical_payload_sha256(payload)
        if calculated_semantic_sha != semantic_sha256:
            raise EventLedgerIntegrityError(
                "semantic hash does not match the canonical event payload"
            )
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        comparison_sha256 = deduplication_sha256 or semantic_sha256
        now = datetime.now(timezone.utc)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                if deduplication_sha256 is not None:
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                        f"wire-event:{producer_client_id}:{envelope.event_id}",
                    )
                    source_existing = await conn.fetchrow(
                        """
                        SELECT event_id, tenant_id, body_sha256, correlation_id,
                               event_type, idempotency_key, payload
                        FROM middleware_inbox
                        WHERE source_client_id=$1 AND event_id=$2
                        ORDER BY received_at ASC
                        LIMIT 1
                        """,
                        producer_client_id,
                        envelope.event_id,
                    )
                    if source_existing is not None:
                        if source_existing["body_sha256"] != comparison_sha256:
                            raise ReplayConflict(
                                "source event identity was reused with a different raw payload"
                            )
                        # A matching replay is also the bounded reconciliation
                        # signal for an inbox row whose projection intent was
                        # lost or deliberately removed. Rebuild only from the
                        # authenticated, already-persisted inbox payload; the
                        # current retry has a different received_at value and
                        # must not replace durable evidence.
                        stored_payload = source_existing["payload"]
                        stored_payload_value = (
                            json.loads(stored_payload)
                            if isinstance(stored_payload, str)
                            else dict(stored_payload)
                        )
                        stored_payload_json = json.dumps(
                            stored_payload_value,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        projection_existing = await conn.fetchrow(
                            """
                            SELECT event_type, payload
                            FROM middleware_outbox
                            WHERE tenant_id=$1 AND destination=$2
                              AND idempotency_key=$3
                            FOR UPDATE
                            """,
                            source_existing["tenant_id"],
                            destination,
                            source_existing["idempotency_key"],
                        )
                        if projection_existing is None:
                            await conn.execute(
                                """
                                INSERT INTO middleware_outbox (
                                    tenant_id, destination, event_type, payload,
                                    idempotency_key
                                ) VALUES ($1,$2,$3,$4::jsonb,$5)
                                """,
                                source_existing["tenant_id"],
                                destination,
                                source_existing["event_type"],
                                stored_payload_json,
                                source_existing["idempotency_key"],
                            )
                        else:
                            projection_payload = projection_existing["payload"]
                            projection_payload_value = (
                                json.loads(projection_payload)
                                if isinstance(projection_payload, str)
                                else dict(projection_payload)
                            )
                            if (
                                projection_existing["event_type"]
                                != source_existing["event_type"]
                                or projection_payload_value != stored_payload_value
                            ):
                                raise EventLedgerIntegrityError(
                                    "durable projection does not match its accepted inbox event"
                                )
                        return IngressResult(
                            event_id=source_existing["event_id"],
                            tenant_id=source_existing["tenant_id"],
                            status="duplicate",
                            duplicate=True,
                            correlation_id=source_existing["correlation_id"],
                        )
                row = await conn.fetchrow(
                    """
                    INSERT INTO middleware_inbox (
                        event_id, tenant_id, source_client_id, event_type,
                        body_sha256, semantic_sha256, idempotency_key, correlation_id,
                        payload, received_at, status
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,'accepted')
                    ON CONFLICT DO NOTHING
                    RETURNING event_id
                    """,
                    envelope.event_id,
                    envelope.tenant_id,
                    producer_client_id,
                    envelope.event_type,
                    body_sha256,
                    semantic_sha256,
                    envelope.idempotency_key,
                    envelope.correlation_id,
                    payload_json,
                    now,
                )
                if row:
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                        envelope.tenant_id,
                    )
                    previous = await conn.fetchrow(
                        """
                        SELECT tenant_sequence, entry_hash
                        FROM middleware_event_ledger
                        WHERE tenant_id=$1
                        ORDER BY tenant_sequence DESC
                        LIMIT 1
                        """,
                        envelope.tenant_id,
                    )
                    tenant_sequence = (
                        int(previous["tenant_sequence"]) + 1 if previous else 1
                    )
                    previous_entry_hash = (
                        str(previous["entry_hash"]) if previous else ZERO_LEDGER_HASH
                    )
                    entry_hash = event_ledger_hash(
                        tenant_id=envelope.tenant_id,
                        tenant_sequence=tenant_sequence,
                        event_id=envelope.event_id,
                        semantic_sha256=semantic_sha256,
                        previous_entry_hash=previous_entry_hash,
                    )
                    await conn.execute(
                        """
                        INSERT INTO middleware_event_ledger (
                            tenant_id, tenant_sequence, event_id, event_type,
                            event_version, source_client_id, correlation_id,
                            causation_id, idempotency_key, semantic_sha256,
                            previous_entry_hash, entry_hash, payload
                        ) VALUES (
                            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb
                        )
                        """,
                        envelope.tenant_id,
                        tenant_sequence,
                        envelope.event_id,
                        envelope.event_type,
                        envelope.event_version,
                        producer_client_id,
                        envelope.correlation_id,
                        envelope.causation_id,
                        envelope.idempotency_key,
                        semantic_sha256,
                        previous_entry_hash,
                        entry_hash,
                        payload_json,
                    )
                    # Durable acceptance and publication intent are committed
                    # together with the immutable hash-chained event record.
                    await conn.execute(
                        """
                        INSERT INTO middleware_outbox (
                            tenant_id, destination, event_type, payload,
                            idempotency_key
                        ) VALUES ($1,$2,$3,$4::jsonb,$5)
                        """,
                        envelope.tenant_id,
                        destination,
                        envelope.event_type,
                        payload_json,
                        envelope.idempotency_key,
                    )
                    return IngressResult(
                        event_id=envelope.event_id,
                        tenant_id=envelope.tenant_id,
                        status="accepted",
                        duplicate=False,
                        correlation_id=envelope.correlation_id,
                    )
                existing_rows = await conn.fetch(
                    """
                    SELECT event_id, tenant_id, idempotency_key, body_sha256,
                           semantic_sha256, correlation_id
                    FROM middleware_inbox
                    WHERE (tenant_id=$1 AND event_id=$2)
                       OR (tenant_id=$1 AND idempotency_key=$3)
                    ORDER BY received_at ASC
                    """,
                    envelope.tenant_id,
                    envelope.event_id,
                    envelope.idempotency_key,
                )
                if not existing_rows:
                    raise StorageError("inbox conflict could not be reconciled")
                identities = {
                    (row["event_id"], row["idempotency_key"]) for row in existing_rows
                }
                if len(identities) > 1:
                    raise ReplayConflict(
                        "event and idempotency identities refer to different accepted events"
                    )
                existing = existing_rows[0]
                stored_comparison_sha256 = (
                    existing["body_sha256"]
                    if deduplication_sha256 is not None
                    else existing["semantic_sha256"]
                )
                if stored_comparison_sha256 != comparison_sha256:
                    raise ReplayConflict(
                        "event/idempotency identity was reused with a different semantic payload"
                    )
                return IngressResult(
                    event_id=existing["event_id"],
                    tenant_id=existing["tenant_id"],
                    status="duplicate",
                    duplicate=True,
                    correlation_id=existing["correlation_id"],
                )

    async def verify_event_ledger(
        self,
        tenant_id: str | None = None,
    ) -> dict[str, int]:
        query = """
            SELECT tenant_id, tenant_sequence, event_id, semantic_sha256,
                   previous_entry_hash, entry_hash, payload
            FROM middleware_event_ledger
        """
        values: tuple[str, ...] = ()
        if tenant_id is not None:
            query += " WHERE tenant_id=$1"
            values = (tenant_id,)
        query += " ORDER BY tenant_id, tenant_sequence"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *values)
        records = []
        for row in rows:
            raw_payload = row["payload"]
            payload = (
                json.loads(raw_payload)
                if isinstance(raw_payload, str)
                else dict(raw_payload)
            )
            records.append(
                EventLedgerRecord(
                    tenant_id=row["tenant_id"],
                    tenant_sequence=row["tenant_sequence"],
                    event_id=row["event_id"],
                    semantic_sha256=row["semantic_sha256"],
                    previous_entry_hash=row["previous_entry_hash"],
                    entry_hash=row["entry_hash"],
                    payload=payload,
                )
            )
        return verify_event_ledger_records(records)

    async def ready(self) -> bool:
        try:
            async with self.pool.acquire() as conn:
                if await conn.fetchval("SELECT 1") != 1:
                    return False
            await self.verify_schema()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self.owns_pool:
            await self.pool.close()


@dataclass(frozen=True)
class OutboxRecord:
    id: int
    tenant_id: str
    destination: str
    event_type: str
    idempotency_key: str
    payload: dict[str, Any]
    attempt_count: int


class PostgresOutboxStore:
    """Lease-based outbox with bounded retry, reconciliation, and DLQ states."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def claim(
        self,
        *,
        worker_id: str,
        lease_seconds: float = 60,
        max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS,
    ) -> OutboxRecord | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    UPDATE middleware_outbox
                    SET dead_lettered_at=now(),
                        lease_owner=NULL,
                        lease_until=NULL,
                        last_error=COALESCE(
                            last_error,
                            'maximum attempts exhausted after worker lease expiry'
                        )
                    WHERE completed_at IS NULL
                      AND cancelled_at IS NULL
                      AND dead_lettered_at IS NULL
                      AND reconciliation_required_at IS NULL
                      AND attempt_count >= $1
                      AND (lease_until IS NULL OR lease_until < now())
                    """,
                    max_attempts,
                )
                row = await conn.fetchrow(
                    """
                    WITH candidate AS (
                        SELECT id
                        FROM middleware_outbox
                        WHERE completed_at IS NULL
                          AND cancelled_at IS NULL
                          AND dead_lettered_at IS NULL
                          AND reconciliation_required_at IS NULL
                          AND attempt_count < $3
                          AND next_attempt_at <= now()
                          AND (lease_until IS NULL OR lease_until < now())
                        ORDER BY id
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE middleware_outbox o
                    SET lease_owner=$1,
                        lease_until=now() + ($2 * interval '1 second'),
                        attempt_count=o.attempt_count + 1
                    FROM candidate
                    WHERE o.id=candidate.id
                    RETURNING o.id, o.tenant_id, o.destination, o.event_type,
                              o.idempotency_key, o.payload, o.attempt_count
                    """,
                    worker_id,
                    lease_seconds,
                    max_attempts,
                )
                if row:
                    await conn.execute(
                        "INSERT INTO middleware_outbox_attempt_events(outbox_id,tenant_id,attempt_number,event_type,worker_id) VALUES($1,$2,$3,'claimed',$4)",
                        row["id"],
                        row["tenant_id"],
                        row["attempt_count"],
                        worker_id,
                    )
        if not row:
            return None
        raw_payload = row["payload"]
        payload = (
            json.loads(raw_payload)
            if isinstance(raw_payload, str)
            else dict(raw_payload)
        )
        return OutboxRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            destination=row["destination"],
            event_type=row["event_type"],
            idempotency_key=row["idempotency_key"],
            payload=payload,
            attempt_count=row["attempt_count"],
        )

    async def complete(self, record_id: int, *, worker_id: str) -> None:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                UPDATE middleware_outbox
                SET completed_at=now(), lease_owner=NULL, lease_until=NULL, last_error=NULL
                WHERE id=$1 AND lease_owner=$2 AND reconciliation_required_at IS NULL
                RETURNING tenant_id,attempt_count
                """,
                    record_id,
                    worker_id,
                )
                if row is None:
                    raise StorageError("outbox lease ownership lost before completion")
                await conn.execute(
                    "INSERT INTO middleware_outbox_attempt_events(outbox_id,tenant_id,attempt_number,event_type,worker_id) VALUES($1,$2,$3,'completed',$4)",
                    record_id,
                    row["tenant_id"],
                    row["attempt_count"],
                    worker_id,
                )

    async def quarantine_unknown_outcome(
        self,
        record_id: int,
        *,
        worker_id: str,
        error: str,
        lease_seconds: float = 60,
    ) -> None:
        """Persist unknown-on-crash state and refresh active dispatch ownership."""

        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        safe_error = error[:2048]
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE middleware_outbox
                    SET last_error=$3,
                        reconciliation_required_at=now(),
                        lease_until=now() + ($4 * interval '1 second')
                    WHERE id=$1 AND lease_owner=$2 AND lease_until IS NOT NULL
                      AND lease_until > now() AND completed_at IS NULL
                      AND dead_lettered_at IS NULL
                      AND reconciliation_required_at IS NULL
                    RETURNING tenant_id,attempt_count
                    """,
                    record_id,
                    worker_id,
                    safe_error,
                    lease_seconds,
                )
                if row is None:
                    raise StorageError(
                        "outbox lease ownership lost before reconciliation quarantine"
                    )
                await conn.execute(
                    "INSERT INTO middleware_outbox_attempt_events(outbox_id,tenant_id,attempt_number,event_type,worker_id,safe_error_code) VALUES($1,$2,$3,'unknown_outcome',$4,'unknown_provider_outcome')",
                    record_id,
                    row["tenant_id"],
                    row["attempt_count"],
                    worker_id,
                )

    async def renew_active_dispatch(
        self,
        record_id: int,
        *,
        worker_id: str,
        lease_seconds: float,
    ) -> None:
        """Refresh ownership while provider code is still alive.

        Renewal is allowed only for the exact worker that owns a quarantined,
        nonterminal dispatch. It intentionally does not require the previous
        deadline to still be in the future: claim() already excludes every
        reconciliation-required row, and renewing the same owner closes small
        scheduler/database timing gaps without creating a new claimant.
        """

        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE middleware_outbox
                SET lease_until=now() + ($3 * interval '1 second')
                WHERE id=$1
                  AND lease_owner=$2
                  AND reconciliation_required_at IS NOT NULL
                  AND completed_at IS NULL
                  AND dead_lettered_at IS NULL
                """,
                record_id,
                worker_id,
                lease_seconds,
            )
            if result != "UPDATE 1":
                raise StorageError(
                    "active dispatch ownership lost during lease renewal"
                )

    async def resolve_reconciliation(
        self,
        record_id: int,
        *,
        operator_id: str,
        action: ReconciliationAction,
        reason: str,
        max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS,
        worker_id: str | None = None,
    ) -> None:
        if action not in {"retry", "complete", "dead_letter"}:
            raise ValueError("unsupported reconciliation action")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        safe_operator = operator_id.strip()
        safe_reason = reason.strip()
        safe_worker = worker_id.strip() if worker_id is not None else None
        if not safe_operator or len(safe_operator) > 160:
            raise ValueError("operator_id must contain 1..160 characters")
        if not safe_reason or len(safe_reason) > 2048:
            raise ValueError("reason must contain 1..2048 characters")
        if worker_id is not None and (not safe_worker or len(safe_worker) > 256):
            raise ValueError("worker_id must contain 1..256 characters")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT id, tenant_id, attempt_count,
                           reconciliation_required_at, completed_at, dead_lettered_at,
                           lease_owner, lease_until,
                           (lease_until IS NOT NULL AND lease_until > now()) AS lease_active
                    FROM middleware_outbox
                    WHERE id=$1
                    FOR UPDATE
                    """,
                    record_id,
                )
                if row is None:
                    raise ReconciliationError("outbox record does not exist")
                if (
                    row["completed_at"] is not None
                    or row["dead_lettered_at"] is not None
                ):
                    raise ReconciliationError("outbox record is already terminal")
                if row["reconciliation_required_at"] is None:
                    raise ReconciliationError(
                        "outbox record is not awaiting reconciliation"
                    )

                lease_active = bool(row["lease_active"])
                if lease_active:
                    if safe_worker is None:
                        raise ReconciliationError(
                            "active dispatch cannot be manually reconciled before lease expiry"
                        )
                    if row["lease_owner"] != safe_worker:
                        raise ReconciliationError(
                            "active dispatch is owned by another worker"
                        )
                    if action == "dead_letter":
                        raise ReconciliationError(
                            "active worker may resolve only complete or known-safe retry"
                        )
                elif safe_worker is not None:
                    raise ReconciliationError(
                        "worker dispatch lease expired; manual reconciliation is required"
                    )

                if action == "retry" and row["attempt_count"] >= max_attempts:
                    raise ReconciliationError(
                        "attempt limit is exhausted; choose complete or dead_letter"
                    )

                await conn.execute(
                    """
                    INSERT INTO middleware_reconciliation_audit
                      (outbox_id, tenant_id, action, operator_id, reason, attempt_count)
                    VALUES ($1,$2,$3,$4,$5,$6)
                    """,
                    record_id,
                    row["tenant_id"],
                    action,
                    safe_operator,
                    safe_reason,
                    row["attempt_count"],
                )

                if action == "retry":
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL,
                            lease_owner=NULL,
                            lease_until=NULL,
                            next_attempt_at=now(),
                            last_error='reconciliation approved retry: ' || $2
                        WHERE id=$1
                        """,
                        record_id,
                        safe_reason,
                    )
                elif action == "complete":
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL,
                            lease_owner=NULL,
                            lease_until=NULL,
                            completed_at=now(),
                            last_error='reconciliation confirmed delivery: ' || $2
                        WHERE id=$1
                        """,
                        record_id,
                        safe_reason,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE middleware_outbox
                        SET reconciliation_required_at=NULL,
                            lease_owner=NULL,
                            lease_until=NULL,
                            dead_lettered_at=now(),
                            last_error='reconciliation dead-lettered: ' || $2
                        WHERE id=$1
                        """,
                        record_id,
                        safe_reason,
                    )

    async def fail(
        self,
        record_id: int,
        *,
        worker_id: str,
        error: str,
        max_attempts: int = DEFAULT_MAX_OUTBOX_ATTEMPTS,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        safe_error = error[:2048]
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                UPDATE middleware_outbox
                SET last_error=$3,
                    lease_owner=NULL,
                    lease_until=NULL,
                    dead_lettered_at=CASE WHEN attempt_count >= $4 THEN now() ELSE NULL END,
                    next_attempt_at=CASE
                        WHEN attempt_count >= $4 THEN next_attempt_at
                        ELSE now() + (
                            LEAST(3600, power(2, LEAST(attempt_count, 10))::int)
                            * interval '1 second'
                        )
                    END
                WHERE id=$1
                  AND lease_owner=$2
                  AND reconciliation_required_at IS NULL
                RETURNING tenant_id,attempt_count
                """,
                    record_id,
                    worker_id,
                    safe_error,
                    max_attempts,
                )
                if row is None:
                    raise StorageError(
                        "outbox lease ownership lost before retry transition"
                    )
                await conn.execute(
                    "INSERT INTO middleware_outbox_attempt_events(outbox_id,tenant_id,attempt_number,event_type,worker_id,safe_error_code) VALUES($1,$2,$3,'failed',$4,'delivery_failed')",
                    record_id,
                    row["tenant_id"],
                    row["attempt_count"],
                    worker_id,
                )
