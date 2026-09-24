# 15 — Database

Alembic: ALEMBIC_HEADS=1, head 0067_service_catalog_monitoring_state (V3 adds no ORM model, no Alembic migration). Empty PostgreSQL 16 (CI digest cf78e766…): `alembic upgrade head` → 183 tables, readback 0067; `alembic downgrade -1` → 0066; `alembic upgrade head` → 0067. `alembic check` autogenerate diff is identical to main's (raw-SQL-managed tables not in ORM metadata) → V3 SCHEMA_DRIFT=0.

Runtime SQL: RUNTIME_SCHEMA_VERSION=11 unchanged (no migration 12). Proof that the existing tables carry every V3 invariant: docs/architecture/middleware-v3-command-kernel.md §7. Runtime SQL history digest and config/runtime-sql-schema.v1.json unchanged.
