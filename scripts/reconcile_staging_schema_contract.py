#!/usr/bin/env python3
"""Normalize known PostgreSQL parse-tree drift in the 0067 staging schema.

The staging database was already stamped at canonical Alembic head 0067, but
four historical CHECK constraints were created with an equivalent PostgreSQL
parse-tree representation that no longer matches the protected
runtime-sql-schema.v1.json structure digests.

This reconciler:
- is staging-only and requires database name middleware_staging;
- requires exact Alembic head 0067_service_catalog_monitoring_state;
- performs no mutation unless --apply is supplied;
- changes only four named CHECK constraints;
- runs in one transaction under an advisory transaction lock;
- never changes business rows or the Alembic head.

After --apply, callers must run scripts/migrate_runtime.py --verify-only and
require RUNTIME_SCHEMA_VERIFIED=PASS before any staging promotion.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

TARGET_DATABASE = "middleware_staging"
TARGET_HEAD = "0067_service_catalog_monitoring_state"
LOCK_NAME = "codestra.middleware.staging-schema-contract-normalize"
LOCK_TIMEOUT = "5s"
STATEMENT_TIMEOUT = "30s"

CONSTRAINTS = (
    (
        "campaign_design_current",
        "ck_campaign_current_lifecycle",
        "lifecycle_state IN ('approval_pending','approved')",
    ),
    (
        "campaign_design_failure",
        "ck_campaign_failure_status",
        "status IN ('retry','dead_letter')",
    ),
    (
        "campaign_design_revision",
        "ck_campaign_design_approval",
        "approval_state IN ('preview','approved')",
    ),
    (
        "campaign_event_inbox",
        "ck_campaign_inbox_state",
        "processing_state IN ('processing','completed')",
    ),
)


class ReconcileError(RuntimeError):
    pass


def resolve_database_url() -> str:
    filename = os.environ.get("DATABASE_URL_FILE", "").strip()
    if filename:
        path = Path(filename)
        if not path.is_absolute() or not path.is_file():
            raise ReconcileError("DATABASE_URL_FILE must be an existing absolute file")
        value = path.read_text(encoding="utf-8").strip()
    else:
        value = os.environ.get("DATABASE_URL", "").strip()
    if value.startswith("postgresql+asyncpg://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if not value.startswith("postgresql+psycopg://"):
        raise ReconcileError("PostgreSQL DSN is required")
    parsed = urlsplit(value.replace("postgresql+psycopg://", "postgresql://", 1))
    if parsed.path.strip("/") != TARGET_DATABASE:
        raise ReconcileError("target database must be middleware_staging")
    return value


def validate_target(conn: Connection) -> None:
    database = conn.execute(text("select current_database()")).scalar_one()
    if database != TARGET_DATABASE:
        raise ReconcileError(f"wrong database: {database}")
    head = conn.execute(text("select version_num from alembic_version")).scalar_one()
    if head != TARGET_HEAD:
        raise ReconcileError(f"unexpected Alembic head: {head}")
    for table, constraint, _ in CONSTRAINTS:
        exists = conn.execute(
            text(
                """
                select count(*)
                from pg_constraint c
                join pg_class t on t.oid=c.conrelid
                join pg_namespace n on n.oid=t.relnamespace
                where n.nspname='public' and t.relname=:table
                  and c.conname=:constraint and c.contype='c'
                """
            ),
            {"table": table, "constraint": constraint},
        ).scalar_one()
        if exists != 1:
            raise ReconcileError(f"missing or ambiguous constraint: {table}.{constraint}")


def reconcile(conn: Connection) -> None:
    conn.execute(
        text("select set_config('lock_timeout', :timeout, true)"),
        {"timeout": LOCK_TIMEOUT},
    )
    conn.execute(
        text("select set_config('statement_timeout', :timeout, true)"),
        {"timeout": STATEMENT_TIMEOUT},
    )
    conn.execute(text("select pg_advisory_xact_lock(hashtext(:name))"), {"name": LOCK_NAME})
    validate_target(conn)
    for table, constraint, expression in CONSTRAINTS:
        conn.execute(
            text(
                f'ALTER TABLE public."{table}" DROP CONSTRAINT "{constraint}"'
            )
        )
        conn.execute(
            text(
                f'ALTER TABLE public."{table}" ADD CONSTRAINT "{constraint}" CHECK ({expression})'
            )
        )
    validate_target(conn)


def main(*, apply: bool) -> None:
    url = resolve_database_url()
    engine = create_engine(url, future=True)
    try:
        if not apply:
            with engine.connect() as conn:
                validate_target(conn)
            print("STAGING_SCHEMA_CONTRACT_TARGET=PASS")
            print("STAGING_SCHEMA_CONTRACT_APPLY=NO")
            return
        with engine.begin() as conn:
            reconcile(conn)
        print("STAGING_SCHEMA_CONTRACT_RECONCILE=PASS")
        print("STAGING_SCHEMA_CONTRACT_APPLY=YES")
        print("ALEMBIC_HEAD_UNCHANGED=" + TARGET_HEAD)
        print("NEXT_REQUIRED=migrate_runtime.py --verify-only")
    finally:
        engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        main(apply=args.apply)
    except Exception as exc:
        print("STAGING_SCHEMA_CONTRACT_RECONCILE=FAIL ERROR_TYPE=" + type(exc).__name__)
        raise SystemExit(1) from None
