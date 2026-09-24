"""Read-only structural attestation of the SQL-managed production schema.

The checked-in baseline comes from a disposable, fully migrated database. It
must never be learned from the database being admitted. Receipts alone are not
proof of tables, columns, constraints, indexes or evidence-immutability triggers.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

CONTRACT_PATH = "config/runtime-sql-schema.v1.json"
ALEMBIC_CATALOG_MIGRATIONS = {
    "campaign": "0058_campaign_design.py",
    "monitoring": "0059_integrated_monitoring.py",
}
SQL_GLOB = "[0-9][0-9][0-9][0-9]_*.sql"
TABLE_RE = re.compile(
    r"\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(middleware_[a-z0-9_]+)\s*\(", re.I
)

# Exclude physical OIDs, owners, row data, statistics and sequence *values*.
# Include logical definitions and validity/enforcement flags. pg_catalog-only
# search_path makes deparsed object names deterministic and avoids shadowing.
CATALOG_SQL = """
SELECT c.relname::text AS table_name,
       pg_catalog.jsonb_build_object(
         'kind', c.relkind, 'persistence', c.relpersistence,
         'row_security', c.relrowsecurity, 'force_row_security', c.relforcerowsecurity,
         'columns', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', a.attname, 'type', pg_catalog.format_type(a.atttypid, a.atttypmod),
             'not_null', a.attnotnull, 'identity', a.attidentity, 'generated', a.attgenerated,
             'collation', CASE WHEN a.attcollation = 0 THEN NULL
                         ELSE cn.nspname || '.' || col.collname END,
             'default', pg_catalog.pg_get_expr(d.adbin, d.adrelid, false)
           ) ORDER BY a.attname COLLATE "C")
           FROM pg_catalog.pg_attribute a
           LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           LEFT JOIN pg_catalog.pg_collation col ON col.oid = a.attcollation
           LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid = col.collnamespace
           WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
         ), '[]'::jsonb),
         'constraints', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', k.conname, 'type', k.contype,
             'definition', pg_catalog.pg_get_constraintdef(k.oid, false),
             'validated', k.convalidated, 'deferrable', k.condeferrable,
             'deferred', k.condeferred
           ) ORDER BY k.conname COLLATE "C")
           FROM pg_catalog.pg_constraint k
           WHERE k.conrelid = c.oid AND k.contype IN ('c','f','p','u','x')
         ), '[]'::jsonb),
         'indexes', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', ic.relname, 'definition', pg_catalog.pg_get_indexdef(i.indexrelid, 0, false),
             'valid', i.indisvalid, 'ready', i.indisready, 'live', i.indislive,
             'unique', i.indisunique, 'primary', i.indisprimary,
             'immediate', i.indimmediate
           ) ORDER BY ic.relname COLLATE "C")
           FROM pg_catalog.pg_index i
           JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid
           WHERE i.indrelid = c.oid
         ), '[]'::jsonb),
         'triggers', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', t.tgname, 'enabled', t.tgenabled,
             'definition', pg_catalog.pg_get_triggerdef(t.oid, false),
             'function', pg_catalog.pg_get_functiondef(t.tgfoid)
           ) ORDER BY t.tgname COLLATE "C")
           FROM pg_catalog.pg_trigger t
           WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
         ), '[]'::jsonb),
         'internal_triggers', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'constraint', k.conname, 'enabled', t.tgenabled,
             'type', t.tgtype, 'function', p.proname
           ) ORDER BY k.conname COLLATE "C", p.proname COLLATE "C", t.tgtype)
           FROM pg_catalog.pg_trigger t
           JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
           LEFT JOIN pg_catalog.pg_constraint k ON k.oid = t.tgconstraint
           WHERE t.tgrelid = c.oid AND t.tgisinternal
         ), '[]'::jsonb),
         'policies', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', p.polname, 'command', p.polcmd, 'permissive', p.polpermissive,
             'roles', ARRAY(SELECT CASE WHEN r.roleid = 0 THEN 'public' ELSE rol.rolname::text END
               FROM pg_catalog.unnest(p.polroles) r(roleid)
               LEFT JOIN pg_catalog.pg_roles rol ON rol.oid = r.roleid ORDER BY 1),
             'using', pg_catalog.pg_get_expr(p.polqual, p.polrelid, false),
             'check', pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false)
           ) ORDER BY p.polname COLLATE "C")
           FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid
         ), '[]'::jsonb),
         'sequences', COALESCE((
           SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
             'name', sn.nspname || '.' || sc.relname, 'column', a.attname,
             'type', pg_catalog.format_type(s.seqtypid, NULL),
             'start', s.seqstart, 'increment', s.seqincrement,
             'min', s.seqmin, 'max', s.seqmax, 'cache', s.seqcache, 'cycle', s.seqcycle
           ) ORDER BY sc.relname COLLATE "C")
           FROM pg_catalog.pg_depend dep
           JOIN pg_catalog.pg_sequence s ON s.seqrelid = dep.objid
           JOIN pg_catalog.pg_class sc ON sc.oid = s.seqrelid
           JOIN pg_catalog.pg_namespace sn ON sn.oid = sc.relnamespace
           JOIN pg_catalog.pg_attribute a ON a.attrelid = dep.refobjid AND a.attnum = dep.refobjsubid
           WHERE dep.refobjid = c.oid AND dep.deptype IN ('a','i')
             AND dep.classid = 'pg_catalog.pg_class'::regclass
             AND dep.refclassid = 'pg_catalog.pg_class'::regclass
         ), '[]'::jsonb)
       )::text AS structure
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relname::text = ANY($1::text[])
ORDER BY c.relname COLLATE "C"
"""


class SchemaDriftError(RuntimeError):
    """A sanitized mismatch; no credentials or business records are included."""


def alembic_tables(root: Path, namespace: str) -> tuple[str, ...]:
    """Derive each table from its declared, source-locked Alembic namespace."""
    names: set[str] = set()
    filename = ALEMBIC_CATALOG_MIGRATIONS[namespace]
    path = root / "migrations" / "versions" / filename
    if not path.is_file() or path.is_symlink():
        raise SchemaDriftError(f"{namespace} schema source migration is missing")
    for call in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "op"
            and call.func.attr == "create_table"
        ):
            continue
        if not call.args or not isinstance(call.args[0], ast.Constant):
            raise SchemaDriftError(f"{namespace} schema table name must be literal")
        name = call.args[0].value
        if not isinstance(name, str) or not re.fullmatch(
            re.escape(namespace) + r"_[a-z0-9_]+", name
        ):
            raise SchemaDriftError(f"{namespace} schema table name is invalid")
        if name in names:
            raise SchemaDriftError(f"{namespace} schema table is declared twice")
        names.add(name)
    if not names:
        raise SchemaDriftError(f"{namespace} schema has no managed tables")
    return tuple(sorted(names))


def campaign_tables(root: Path) -> tuple[str, ...]:
    """Return only the six campaign tables, preserving existing callers."""
    return alembic_tables(root, "campaign")


def monitoring_tables(root: Path) -> tuple[str, ...]:
    """Return the durable monitoring tables required for runtime admission."""
    return alembic_tables(root, "monitoring")


def managed_tables(root: Path) -> tuple[str, ...]:
    """Discover names from numbered SQL and the declared Alembic catalog surface."""
    names: set[str] = set()
    for relative in ("migrations", "migrations/automation"):
        paths = sorted((root / relative).glob(SQL_GLOB))
        if not paths:
            raise SchemaDriftError("SQL schema source bundle is missing")
        for path in paths:
            text = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
            names.update(name.lower() for name in TABLE_RE.findall(text))
    if not names:
        raise SchemaDriftError("SQL schema has no managed tables")
    names.update(campaign_tables(root))
    names.update(monitoring_tables(root))
    return tuple(sorted(names))


def structure_digest(structure: dict[str, Any]) -> str:
    payload = json.dumps(structure, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_contract(root: Path, history_digest: str) -> dict[str, str]:
    document = json.loads((root / CONTRACT_PATH).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise SchemaDriftError("SQL schema contract version is invalid")
    if document.get("migration_history_sha256") != history_digest:
        raise SchemaDriftError(
            "SQL schema contract is not bound to the accepted migration history"
        )
    tables = document.get("tables")
    if not isinstance(tables, dict) or set(tables) != set(managed_tables(root)):
        raise SchemaDriftError(
            "SQL schema contract table coverage is incomplete or unexpected"
        )
    if any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        for value in tables.values()
    ):
        raise SchemaDriftError("SQL schema contract contains an invalid signature")
    return tables


async def inspect_schema(
    conn: Any, names: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    """Catalog reads only, in one read-only repeatable-read transaction."""
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        await conn.execute("SET LOCAL search_path = pg_catalog")
        rows = await conn.fetch(CATALOG_SQL, list(names))
    structures: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = json.loads(row["structure"])
        if not isinstance(value, dict) or row["table_name"] in structures:
            raise SchemaDriftError("invalid SQL schema catalog response")
        structures[row["table_name"]] = value
    if set(structures) != set(names):
        raise SchemaDriftError("SQL-managed table is missing from public schema")
    return structures


async def verify_sql_schema(conn: Any, root: Path) -> None:
    from scripts.production_migration_authority import validate_authority

    # Revalidate the protected source even for direct library callers. Never
    # persist a new reference signature learned from the admission target.
    _, _, history_digest = validate_authority(root)
    required = load_contract(root, history_digest)
    actual = await inspect_schema(conn, tuple(sorted(required)))
    for name, expected in required.items():
        if structure_digest(actual[name]) != expected:
            raise SchemaDriftError(
                "SQL-managed schema structure mismatch: public." + name
            )
