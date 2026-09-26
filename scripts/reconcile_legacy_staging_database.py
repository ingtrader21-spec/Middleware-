#!/usr/bin/env python3
"""Reconcile the legacy staging Alembic branch onto canonical Middleware 0067.

This is a one-time staging-only bridge for databases that are exactly at
0058_odoo_delivery_sources from Codestra-SRL/codestra-middleware commit
b29db772ed82c0d2f1adfdb8e6da58d4baa77524.

The legacy and canonical graphs share 0056_klyrow_delivery_events. The bridge:
1. validates the exact legacy lineage/schema signature;
2. archives the legacy provider-route registry metadata as evidence;
3. in one transaction, moves the Alembic marker to shared 0056, removes only
   the obsolete provider-route registry identities, applies canonical migrations
   through 0067, and validates data-preservation postconditions.

No business rows are deleted. Any failed precondition or postcondition rolls the
transaction back.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

LEGACY_SOURCE_SHA = "b29db772ed82c0d2f1adfdb8e6da58d4baa77524"
LEGACY_HEAD = "0058_odoo_delivery_sources"
SHARED_HEAD = "0056_klyrow_delivery_events"
TARGET_HEAD = "0069_agent_provisioning_rls"
LEGACY_ENDPOINT_ID = "55000000-0000-4000-8000-000000000021"
CANONICAL_ENDPOINT_ID = "66000000-0000-4000-8000-000000000012"
PROVIDER_ENDPOINT_KEY = "odoo.provider_activities.create"
LOCK_NAME = "codestra.middleware.legacy-staging-reconcile"
CANONICAL_TABLES = (
    "platform_services",
    "monitoring_resources",
    "monitoring_operations",
    "monitoring_events",
    "agent_provisioning_request",
    "agent_provisioning_step",
    "agent_provisioning_audit",
    "telnexa_delivery_event_inbox",
    "telnexa_delivery_analytics",
    "odoo_campaign_saga",
    "platform_service_monitoring_audit",
)
PRESERVED_ROW_COUNTS = (
    "odoo_result_delivery",
    "integration_event",
    "outbox_event",
)


class ReconcileError(RuntimeError):
    """Fail-closed reconciliation error."""


def _git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _resolve_head_without_git(root: Path) -> str:
    git_path = root / ".git"
    if git_path.is_file():
        value = git_path.read_text(encoding="utf-8").strip()
        if not value.startswith("gitdir: "):
            raise ReconcileError("unsupported .git pointer")
        git_path = (root / value.removeprefix("gitdir: ").strip()).resolve()
    head_text = (git_path / "HEAD").read_text(encoding="utf-8").strip()
    if not head_text.startswith("ref: "):
        return head_text
    ref = head_text.removeprefix("ref: ").strip()
    ref_path = git_path / ref
    if ref_path.is_file():
        return ref_path.read_text(encoding="utf-8").strip()
    packed = git_path / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            sha, name = line.split(" ", 1)
            if name == ref:
                return sha
    raise ReconcileError(f"cannot resolve git ref: {ref}")


def verify_source(
    root: Path, expected_base_sha: str, expected_source_sha: str
) -> str:
    if shutil.which("git"):
        head = _git_output(root, "rev-parse", "HEAD")
    else:
        head = _resolve_head_without_git(root)
    if head != expected_source_sha:
        raise ReconcileError(
            f"source SHA mismatch: expected={expected_source_sha} actual={head}"
        )
    if shutil.which("git"):
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", expected_base_sha, head],
            check=True,
            capture_output=True,
            text=True,
        )
    return head


def resolve_database_url() -> str:
    filename = os.environ.get("DATABASE_URL_FILE", "").strip()
    if filename:
        path = Path(filename)
        if not path.is_absolute() or not path.is_file():
            raise ReconcileError("DATABASE_URL_FILE must be an existing absolute file")
        value = path.read_text(encoding="utf-8").strip()
    else:
        value = os.environ.get("DATABASE_URL", "").strip()
    if not value:
        raise ReconcileError("DATABASE_URL_FILE or DATABASE_URL is required")
    if value.startswith("postgresql+asyncpg://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if not value.startswith("postgresql+psycopg://"):
        raise ReconcileError("PostgreSQL DSN is required")
    return value


def _scalar(conn: Connection, sql: str, **params: Any) -> Any:
    return conn.execute(text(sql), params).scalar_one()


def capture_legacy_evidence(conn: Connection) -> dict[str, Any]:
    endpoint_rows = conn.execute(
        text(
            """
            select row_to_json(e)::text
            from integration_endpoint e
            where endpoint_key=:key
            order by endpoint_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    schema_rows = conn.execute(
        text(
            """
            select row_to_json(s)::text
            from integration_schema_version s
            where endpoint_key=:key
            order by schema_version_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    version_rows = conn.execute(
        text(
            """
            select row_to_json(v)::text
            from integration_endpoint_version v
            join integration_endpoint e on e.endpoint_id=v.endpoint_id
            where e.endpoint_key=:key
            order by v.endpoint_version_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    binding_rows = conn.execute(
        text(
            """
            select row_to_json(b)::text
            from integration_route_binding b
            join integration_endpoint_version v
              on v.endpoint_version_id=b.endpoint_version_id
            join integration_endpoint e on e.endpoint_id=v.endpoint_id
            where e.endpoint_key=:key
            order by b.binding_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    return {
        "legacy_source_sha": LEGACY_SOURCE_SHA,
        "legacy_head": _scalar(conn, "select version_num from alembic_version"),
        "provider_endpoint": [json.loads(row) for row in endpoint_rows],
        "provider_schema": [json.loads(row) for row in schema_rows],
        "provider_versions": [json.loads(row) for row in version_rows],
        "provider_bindings": [json.loads(row) for row in binding_rows],
    }


def validate_legacy_state(conn: Connection) -> dict[str, int]:
    database = _scalar(conn, "select current_database()")
    if database != "middleware_staging":
        raise ReconcileError(f"wrong database: {database}")

    head = _scalar(conn, "select version_num from alembic_version")
    if head != LEGACY_HEAD:
        raise ReconcileError(f"unexpected legacy head: {head}")

    provider_ids = conn.execute(
        text(
            """
            select endpoint_id::text from integration_endpoint
            where endpoint_key=:key order by endpoint_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    if provider_ids != [LEGACY_ENDPOINT_ID]:
        raise ReconcileError(f"unexpected legacy provider endpoint ids: {provider_ids}")

    constraint = _scalar(
        conn,
        """
        select pg_get_constraintdef(oid)
        from pg_constraint
        where conname='ck_odoo_result_delivery_one_source'
        """,
    )
    if "num_nonnulls(acknowledgement_id, runtime_result_id, integration_event_id) = 1" not in constraint:
        raise ReconcileError("legacy Odoo delivery constraint signature mismatch")

    counts: dict[str, int] = {}
    for table in PRESERVED_ROW_COUNTS:
        counts[table] = int(_scalar(conn, f"select count(*) from {table}"))
    return counts


def bridge_and_upgrade(conn: Connection, root: Path) -> None:
    conn.execute(text("select pg_advisory_xact_lock(hashtext(:name))"), {"name": LOCK_NAME})
    conn.execute(
        text(
            """
            update alembic_version
               set version_num=:shared
             where version_num=:legacy
            """
        ),
        {"shared": SHARED_HEAD, "legacy": LEGACY_HEAD},
    )
    if _scalar(conn, "select version_num from alembic_version") != SHARED_HEAD:
        raise ReconcileError("failed to move marker to shared head")

    conn.execute(
        text(
            """
            delete from integration_route_binding
             where endpoint_version_id in (
               select v.endpoint_version_id
               from integration_endpoint_version v
               join integration_endpoint e on e.endpoint_id=v.endpoint_id
               where e.endpoint_key=:key
             )
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    )
    conn.execute(
        text(
            """
            delete from integration_endpoint_version
             where endpoint_id in (
               select endpoint_id from integration_endpoint
               where endpoint_key=:key
             )
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    )
    conn.execute(
        text("delete from integration_schema_version where endpoint_key=:key"),
        {"key": PROVIDER_ENDPOINT_KEY},
    )
    conn.execute(
        text("delete from integration_endpoint where endpoint_key=:key"),
        {"key": PROVIDER_ENDPOINT_KEY},
    )

    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.attributes["connection"] = conn
    command.upgrade(cfg, TARGET_HEAD)


def validate_canonical_state(conn: Connection, counts_before: dict[str, int]) -> dict[str, Any]:
    head = _scalar(conn, "select version_num from alembic_version")
    if head != TARGET_HEAD:
        raise ReconcileError(f"target head mismatch: {head}")

    provider_ids = conn.execute(
        text(
            """
            select endpoint_id::text from integration_endpoint
            where endpoint_key=:key order by endpoint_id
            """
        ),
        {"key": PROVIDER_ENDPOINT_KEY},
    ).scalars().all()
    if provider_ids != [CANONICAL_ENDPOINT_ID]:
        raise ReconcileError(f"canonical provider endpoint mismatch: {provider_ids}")

    missing = [
        name
        for name in CANONICAL_TABLES
        if _scalar(conn, "select to_regclass(:name)", name=f"public.{name}") is None
    ]
    if missing:
        raise ReconcileError(f"missing canonical tables: {missing}")

    counts_after: dict[str, int] = {}
    for table in PRESERVED_ROW_COUNTS:
        counts_after[table] = int(_scalar(conn, f"select count(*) from {table}"))
    if counts_after != counts_before:
        raise ReconcileError(
            f"preserved business row counts changed: before={counts_before} after={counts_after}"
        )

    width = _scalar(
        conn,
        """
        select character_maximum_length
        from information_schema.columns
        where table_schema='public'
          and table_name='alembic_version'
          and column_name='version_num'
        """,
    )
    if width != 64:
        raise ReconcileError(f"alembic version width mismatch: {width}")

    version_count = int(
        _scalar(
            conn,
            """
            select count(*)
            from integration_endpoint_version v
            join integration_endpoint e on e.endpoint_id=v.endpoint_id
            where e.endpoint_key=:key
            """,
            key=PROVIDER_ENDPOINT_KEY,
        )
    )
    binding_count = int(
        _scalar(
            conn,
            """
            select count(*)
            from integration_route_binding b
            join integration_endpoint_version v
              on v.endpoint_version_id=b.endpoint_version_id
            join integration_endpoint e on e.endpoint_id=v.endpoint_id
            where e.endpoint_key=:key
            """,
            key=PROVIDER_ENDPOINT_KEY,
        )
    )
    if (version_count, binding_count) != (2, 2):
        raise ReconcileError(
            f"canonical provider route cardinality mismatch: versions={version_count} bindings={binding_count}"
        )
    return {
        "target_head": head,
        "provider_endpoint_id": provider_ids[0],
        "provider_version_count": version_count,
        "provider_binding_count": binding_count,
        "preserved_row_counts": counts_after,
        "canonical_table_count": len(CANONICAL_TABLES),
        "alembic_version_width": width,
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.execute:
        raise ReconcileError("--execute is required")

    root = Path(__file__).resolve().parents[1]
    source_sha = verify_source(
        root, args.expected_base_sha, args.expected_source_sha
    )
    dsn = resolve_database_url()
    engine = create_engine(dsn, pool_pre_ping=True)

    archive: dict[str, Any]
    summary: dict[str, Any]
    with engine.connect() as conn:
        tx = conn.begin()
        try:
            archive = capture_legacy_evidence(conn)
            counts_before = validate_legacy_state(conn)
            write_json(
                args.evidence_dir / "legacy-provider-route-before.json",
                {**archive, "source_sha": source_sha, "counts_before": counts_before},
            )
            bridge_and_upgrade(conn, root)
            summary = validate_canonical_state(conn, counts_before)
            tx.commit()
        except Exception:
            tx.rollback()
            raise

    engine.dispose()
    write_json(
        args.evidence_dir / "reconciliation-result.json",
        {
            "status": "PASS",
            "source_sha": source_sha,
            "expected_base_sha": args.expected_base_sha,
            "legacy_source_sha": LEGACY_SOURCE_SHA,
            "from_head": LEGACY_HEAD,
            **summary,
        },
    )
    print("RECONCILIATION_STATUS=PASS")
    print(f"SOURCE_SHA={source_sha}")
    print(f"FROM_HEAD={LEGACY_HEAD}")
    print(f"TO_HEAD={TARGET_HEAD}")
    print("BUSINESS_ROW_COUNTS_PRESERVED=YES")
    print("PRODUCTION_MUTATIONS=0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReconcileError, subprocess.CalledProcessError) as exc:
        print(f"RECONCILIATION_STATUS=FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
