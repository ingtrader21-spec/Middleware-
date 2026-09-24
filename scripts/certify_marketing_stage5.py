#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

schema = json.loads((ROOT / "contracts/marketing/v1/envelope.schema.json").read_text(encoding="utf-8"))
runtime_sql = (ROOT / "migrations/0001_runtime.sql").read_text(encoding="utf-8").lower()
worker = (ROOT / "workers/run_outbox.py").read_text(encoding="utf-8")

required_envelope_fields = {
    "event_id",
    "tenant_id",
    "event_type",
    "correlation_id",
    "payload",
}
required = set(schema.get("required", []))
missing = sorted(required_envelope_fields - required)
if missing:
    raise SystemExit(f"marketing envelope missing required fields: {missing}")

properties = schema.get("properties", {})
if "idempotency_key" not in properties:
    raise SystemExit("marketing envelope must expose idempotency_key for commands/replay-safe intake")
idempotency_type = properties["idempotency_key"].get("type")
if idempotency_type not in (["string", "null"], ["null", "string"]):
    raise SystemExit("raw marketing envelope idempotency_key must remain nullable until intake normalization")

sql_assertions = {
    "middleware_inbox": "create table if not exists middleware_inbox",
    "tenant_event_pk": "primary key (tenant_id, event_id)",
    "tenant_idempotency": "unique (tenant_id, idempotency_key)",
    "middleware_outbox": "create table if not exists middleware_outbox",
    "lease_owner": "lease_owner text",
    "lease_until": "lease_until timestamptz",
    "dead_letter": "dead_lettered_at timestamptz",
    "reconciliation": "reconciliation_required_at timestamptz",
    "reconciliation_audit": "create table if not exists middleware_reconciliation_audit",
}
for name, needle in sql_assertions.items():
    if needle not in runtime_sql:
        raise SystemExit(f"runtime durability assertion failed: {name}")

if "PostgresOutboxStore" not in worker or "OutboxWorker" not in worker:
    raise SystemExit("outbox worker is not backed by the canonical PostgreSQL store")

for forbidden in ("LIVE_ADVERTISING_ENABLED=true", "EXTERNAL_DELIVERY_ENABLED=true", "SOCIAL_PUBLISHING_ENABLED=true"):
    if forbidden in worker:
        raise SystemExit(f"forbidden live capability found in outbox worker: {forbidden}")

print("MARKETING_STAGE5_DURABILITY_CERTIFICATION=PASS")
