"""Private read-only PostgreSQL operational evidence API.

No handler accepts SQL and no route applies migrations, backups, restores, or
business/provider mutations. The surface is mounted only on the integration
profile and must remain unreachable at the public edge.
"""

from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import APIRouter, HTTPException, Request

from app.api_inputs import authorization_header
from app.control_plane_auth import caller_for_authorization
from app.security import SecurityError

router = APIRouter(prefix="/internal/v1/database", tags=["internal-database"])

READ_SCOPE = "platform.database.read"
VERIFY_SCOPE = "platform.database.verify"
ADMIN_SCOPE = "platform.database.admin"

_REQUIRED_TABLES = (
    "alembic_version",
    "platform_services",
    "platform_service_monitoring_audit",
)
_SAFE_EVIDENCE_FIELDS = (
    "evidence_id",
    "kind",
    "created_at",
    "completed_at",
    "source_database",
    "target_database",
    "source_schema_head",
    "target_schema_head",
    "sha256",
    "size_bytes",
    "verified",
    "status",
)


def _runtime(request: Request):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None or getattr(runtime, "pool", None) is None:
        raise HTTPException(503, "database runtime unavailable")
    return runtime


async def _authorize(request: Request, required_scope: str) -> str:
    runtime = _runtime(request)
    authorization = authorization_header(request)
    try:
        caller = caller_for_authorization(authorization)
        await runtime.tokens.verify(
            authorization,
            expected_client_id=caller.client_id,
            required_scope=required_scope,
        )
    except SecurityError:
        raise
    return caller.client_id


def _dsn_policy(database_url: str) -> dict[str, Any]:
    parsed = urlsplit(database_url)
    query = parse_qs(parsed.query)
    sslmode = (query.get("sslmode") or [""])[0]
    return {
        "expected_database": parsed.path.lstrip("/") or None,
        "expected_role": parsed.username or None,
        "sslmode": sslmode or "unspecified",
        "tls_required": sslmode in {"require", "verify-ca", "verify-full"},
        "hostname_verification": sslmode == "verify-full",
        "ca_verification": sslmode in {"verify-ca", "verify-full"},
        "client_certificate_configured": bool(
            (query.get("sslcert") or [""])[0] and (query.get("sslkey") or [""])[0]
        ),
    }


async def _snapshot(request: Request) -> dict[str, Any]:
    runtime = _runtime(request)
    policy = _dsn_policy(runtime.settings.database_url)
    started = perf_counter()
    async with runtime.pool.acquire() as conn:
        identity = await conn.fetchrow(
            "SELECT current_database() AS database_name, current_user AS role_name, "
            "current_setting('server_version') AS server_version, "
            "pg_is_in_recovery() AS in_recovery"
        )
        present = await conn.fetchval(
            "SELECT to_regclass('public.alembic_version') IS NOT NULL"
        )
        head_rows = (
            await conn.fetch(
                "SELECT version_num FROM public.alembic_version ORDER BY version_num"
            )
            if present
            else []
        )
        tables = await conn.fetch(
            "SELECT tablename FROM pg_catalog.pg_tables "
            "WHERE schemaname='public' AND tablename = ANY($1::text[]) "
            "ORDER BY tablename",
            list(_REQUIRED_TABLES),
        )
        ssl = await conn.fetchrow(
            "SELECT ssl, version, cipher, bits FROM pg_stat_ssl "
            "WHERE pid=pg_backend_pid()"
        )
    latency_ms = round((perf_counter() - started) * 1000, 3)
    heads = [str(row["version_num"]) for row in head_rows]
    found = {str(row["tablename"]) for row in tables}
    current_head = heads[0] if len(heads) == 1 else None
    tls_active = bool(ssl and ssl["ssl"])
    expected_head = runtime.settings.schema_head
    return {
        "reachable": True,
        "latency_ms": latency_ms,
        "database_name": str(identity["database_name"]),
        "role_name": str(identity["role_name"]),
        "server_version": str(identity["server_version"]),
        "in_recovery": bool(identity["in_recovery"]),
        "alembic_heads": heads,
        "head_count": len(heads),
        "alembic_head": current_head,
        "expected_alembic_head": expected_head,
        "schema_matches": len(heads) == 1 and current_head == expected_head,
        "required_tables": list(_REQUIRED_TABLES),
        "missing_required_tables": sorted(set(_REQUIRED_TABLES) - found),
        "tls_active": tls_active,
        "tls_version": str(ssl["version"]) if ssl and ssl["version"] else None,
        "tls_cipher": str(ssl["cipher"]) if ssl and ssl["cipher"] else None,
        "tls_bits": int(ssl["bits"]) if ssl and ssl["bits"] is not None else None,
        "dsn_policy": policy,
    }


def _safe_evidence(request: Request, filename: str, kind: str) -> dict[str, Any]:
    root = str(
        getattr(
            _runtime(request).settings,
            "database_certification_evidence_dir",
            "",
        )
        or ""
    ).strip()
    if not root:
        return {"kind": kind, "available": False, "status": "evidence_unavailable"}
    path = Path(root) / filename
    if not path.is_file():
        return {"kind": kind, "available": False, "status": "evidence_unavailable"}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"kind": kind, "available": False, "status": "evidence_invalid"}
    data = {key: raw.get(key) for key in _SAFE_EVIDENCE_FIELDS if key in raw}
    data["kind"] = kind
    data["available"] = True
    return data


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    return {
        "status": "ok",
        "reachable": snap["reachable"],
        "latency_ms": snap["latency_ms"],
        "tls_active": snap["tls_active"],
    }


@router.get("/readiness")
async def readiness(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    policy = snap["dsn_policy"]
    expected_db = policy["expected_database"]
    expected_role = policy["expected_role"]
    ready = (
        snap["schema_matches"]
        and not snap["missing_required_tables"]
        and (not expected_db or snap["database_name"] == expected_db)
        and (not expected_role or snap["role_name"] == expected_role)
        and (not policy["tls_required"] or snap["tls_active"])
    )
    return {
        "status": "ready" if ready else "not_ready",
        "ready": ready,
        "database_matches": not expected_db or snap["database_name"] == expected_db,
        "role_matches": not expected_role or snap["role_name"] == expected_role,
        "schema_matches": snap["schema_matches"],
        "missing_required_tables": snap["missing_required_tables"],
        "tls_required": policy["tls_required"],
        "tls_active": snap["tls_active"],
        "expected_alembic_head": snap["expected_alembic_head"],
        "alembic_head": snap["alembic_head"],
    }


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    return {
        key: snap[key]
        for key in (
            "database_name",
            "role_name",
            "server_version",
            "in_recovery",
            "alembic_head",
            "expected_alembic_head",
            "head_count",
            "tls_active",
        )
    }


@router.get("/schema")
async def schema(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    return {
        "authority": "middleware",
        "alembic_head": snap["alembic_head"],
        "expected_alembic_head": snap["expected_alembic_head"],
        "head_count": snap["head_count"],
        "runtime_schema_verified": (
            snap["schema_matches"] and not snap["missing_required_tables"]
        ),
        "drift_detected": (
            not snap["schema_matches"] or bool(snap["missing_required_tables"])
        ),
        "required_tables": snap["required_tables"],
        "missing_required_tables": snap["missing_required_tables"],
    }


@router.get("/migrations")
async def migrations(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    return {
        "alembic_heads": snap["alembic_heads"],
        "head_count": snap["head_count"],
        "expected_alembic_head": snap["expected_alembic_head"],
        "verified": snap["schema_matches"],
        "apply_supported": False,
    }


@router.post("/migrations/verify")
async def verify_migrations(request: Request) -> dict[str, Any]:
    await _authorize(request, VERIFY_SCOPE)
    snap = await _snapshot(request)
    verified = snap["schema_matches"] and not snap["missing_required_tables"]
    return {
        "verified": verified,
        "read_only": True,
        "alembic_head": snap["alembic_head"],
        "expected_alembic_head": snap["expected_alembic_head"],
        "missing_required_tables": snap["missing_required_tables"],
    }


@router.get("/pool")
async def pool(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    pool = _runtime(request).pool
    size = int(pool.get_size())
    idle = int(pool.get_idle_size())
    return {
        "size": size,
        "idle": idle,
        "in_use": max(size - idle, 0),
        "min_size": int(pool.get_min_size()),
        "max_size": int(pool.get_max_size()),
    }


@router.get("/security/tls")
async def tls(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    policy = snap["dsn_policy"]
    return {
        "required": policy["tls_required"],
        "active": snap["tls_active"],
        "verification_mode": policy["sslmode"],
        "ca_verification": policy["ca_verification"],
        "hostname_verification": policy["hostname_verification"],
        "protocol": snap["tls_version"],
        "cipher": snap["tls_cipher"],
        "bits": snap["tls_bits"],
    }


@router.get("/security/certificates")
async def certificates(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    snap = await _snapshot(request)
    policy = snap["dsn_policy"]
    return {
        "tls_active": snap["tls_active"],
        "ca_verification": policy["ca_verification"],
        "hostname_verification": policy["hostname_verification"],
        "client_certificate_configured": policy["client_certificate_configured"],
        "private_key_exposed": False,
        "dsn_exposed": False,
    }


@router.get("/security/rls")
async def rls(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    runtime = _runtime(request)
    async with runtime.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT count(*) FILTER (WHERE c.relrowsecurity) AS rls_tables, "
            "count(*) AS total_tables "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relkind='r'"
        )
        policy_count = await conn.fetchval(
            "SELECT count(*) FROM pg_policies WHERE schemaname='public'"
        )
    return {
        "rls_enabled_tables": int(row["rls_tables"]),
        "public_tables": int(row["total_tables"]),
        "policy_count": int(policy_count),
        "evidence_only": True,
    }


_ROLE_ISOLATION_QUERY = """
WITH me AS (SELECT * FROM pg_catalog.pg_roles WHERE rolname = current_user),
public_tables AS (
  SELECT c.relowner, c.relrowsecurity, c.relforcerowsecurity
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
)
SELECT me.rolname AS role_name,
  session_user AS session_role_name,
  current_user = session_user AS session_user_matches,
  me.rolsuper AS superuser,
  me.rolbypassrls AS bypassrls,
  me.rolcreaterole AS createrole,
  me.rolcreatedb AS createdb,
  me.rolreplication AS replication,
  (SELECT count(*) FROM pg_catalog.pg_roles r
    WHERE r.oid <> me.oid AND (r.rolsuper OR r.rolbypassrls)
      AND pg_catalog.pg_has_role(me.oid, r.oid, 'MEMBER')) AS elevated_role_memberships,
  (SELECT count(*) FROM public_tables t
    WHERE pg_catalog.pg_has_role(me.oid, t.relowner, 'USAGE')) AS owned_public_tables,
  (SELECT count(DISTINCT t.relowner) FROM public_tables t
    WHERE t.relowner <> me.oid
      AND pg_catalog.pg_has_role(me.oid, t.relowner, 'SET')) AS settable_public_owner_roles,
  (SELECT count(*) FROM public_tables t
    WHERE t.relrowsecurity AND NOT t.relforcerowsecurity
      AND pg_catalog.pg_has_role(me.oid, t.relowner, 'USAGE')) AS owned_rls_tables_without_force,
  (SELECT count(DISTINCT t.relowner) FROM public_tables t
    WHERE t.relowner <> me.oid
      AND t.relrowsecurity AND NOT t.relforcerowsecurity
      AND pg_catalog.pg_has_role(me.oid, t.relowner, 'SET')) AS settable_rls_owner_roles_without_force,
  (SELECT count(*) FROM public_tables t
    WHERE t.relrowsecurity AND t.relforcerowsecurity) AS forced_rls_tables,
  pg_catalog.has_schema_privilege(me.oid, 'public', 'CREATE') AS public_schema_create
FROM me
"""


@router.get("/security/roles")
async def roles(request: Request) -> dict[str, Any]:
    """Runtime-role isolation evidence (DB-19/DB-20 ROLE_ISOLATION precheck).

    A superuser or BYPASSRLS role, a member of one, or the owner of a table
    without FORCE ROW LEVEL SECURITY is not bound by tenant RLS policies; a
    role that owns tables or may CREATE in ``public`` can run DDL. Any of these
    means the runtime shares migration authority and is not isolated.
    """
    await _authorize(request, READ_SCOPE)
    async with _runtime(request).pool.acquire() as conn:
        row = await conn.fetchrow(_ROLE_ISOLATION_QUERY)
    if row is None:
        raise HTTPException(503, "database role unavailable")
    flags = {
        key: bool(row[key])
        for key in (
            "superuser",
            "bypassrls",
            "createrole",
            "createdb",
            "replication",
            "public_schema_create",
        )
    }
    counts = {
        key: int(row[key] or 0)
        for key in (
            "elevated_role_memberships",
            "owned_public_tables",
            "settable_public_owner_roles",
            "owned_rls_tables_without_force",
            "settable_rls_owner_roles_without_force",
            "forced_rls_tables",
        )
    }
    session_user_matches = bool(row["session_user_matches"])
    isolated = session_user_matches and not any(flags.values()) and not (
        counts["elevated_role_memberships"]
        or counts["owned_public_tables"]
        or counts["settable_public_owner_roles"]
    )
    return {
        "role_name": str(row["role_name"]),
        "session_role_name": str(row["session_role_name"]),
        "session_user_matches": session_user_matches,
        **flags,
        **counts,
        "rls_bypass_possible": bool(
            not session_user_matches
            or flags["superuser"]
            or flags["bypassrls"]
            or counts["elevated_role_memberships"]
            or counts["owned_rls_tables_without_force"]
            or counts["settable_rls_owner_roles_without_force"]
        ),
        "runtime_role_isolated": isolated,
        "evidence_only": True,
    }


@router.get("/performance")
async def performance(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    runtime = _runtime(request)
    async with runtime.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT numbackends, xact_commit, xact_rollback, blks_read, blks_hit, "
            "tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted, "
            "deadlocks, temp_files FROM pg_stat_database "
            "WHERE datname=current_database()"
        )
    return {key: int(value or 0) for key, value in dict(row).items()}


@router.get("/locks")
async def locks(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    runtime = _runtime(request)
    async with runtime.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT count(*) FILTER (WHERE granted) AS granted, "
            "count(*) FILTER (WHERE NOT granted) AS waiting FROM pg_locks"
        )
    return {"granted": int(row["granted"]), "waiting": int(row["waiting"])}


@router.get("/capacity")
async def capacity(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    runtime = _runtime(request)
    async with runtime.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT pg_database_size(current_database()) AS database_bytes, "
            "current_setting('max_connections')::int AS max_connections, "
            "(SELECT count(*) FROM pg_stat_activity "
            "WHERE datname=current_database()) AS connections"
        )
    return {
        "database_bytes": int(row["database_bytes"]),
        "max_connections": int(row["max_connections"]),
        "connections": int(row["connections"]),
    }


@router.get("/backups")
async def backups(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    return {"items": [_safe_evidence(request, "backup.json", "backup")]}


@router.get("/backups/latest")
async def latest_backup(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    return _safe_evidence(request, "backup.json", "backup")


@router.get("/restores/latest")
async def latest_restore(request: Request) -> dict[str, Any]:
    await _authorize(request, READ_SCOPE)
    return _safe_evidence(request, "restore.json", "restore")
