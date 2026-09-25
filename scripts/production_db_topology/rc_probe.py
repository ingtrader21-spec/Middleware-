"""PAS-95 in-image probe: exercise the exact release-candidate code against the
disposable production-shaped PostgreSQL topology.

Runs only inside the locally built RC image (``/app`` is the RC source tree),
started by ``scripts/certify_production_db_topology.py`` on an internal Docker
network that has no route to any other host. Every write this probe issues is
inside a transaction that is rolled back. Output is one JSON document on
stdout; passwords, DSNs and key material are never printed.

Commands: profile-gate, connect-matrix, roles, rls, pool, api, schema, scrape.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

sys.path.insert(0, "/app")

PARAMS = json.loads(Path("/probe/params.json").read_text(encoding="utf-8"))
MATRIX = Path("/run/secrets/matrix")
UNIT_PREFIX = PARAMS["secret_path_prefix"]
UNIT_DSN_FILE = Path(UNIT_PREFIX + "database-url")
CONNECT_TIMEOUT = 10

# The PAS-96/PAS-97 runtime role-isolation query, verbatim from
# app/api/internal/database.py at d7ab51e (PR #327, not yet on main).
ROLE_ISOLATION_QUERY = """
WITH me AS (SELECT * FROM pg_catalog.pg_roles WHERE rolname = current_user),
public_tables AS (
  SELECT c.relowner, c.relrowsecurity, c.relforcerowsecurity
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
)
SELECT me.rolname AS role_name,
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
  (SELECT count(*) FROM public_tables t
    WHERE t.relrowsecurity AND NOT t.relforcerowsecurity
      AND pg_catalog.pg_has_role(me.oid, t.relowner, 'USAGE')) AS owned_rls_tables_without_force,
  (SELECT count(*) FROM public_tables t
    WHERE t.relrowsecurity AND t.relforcerowsecurity) AS forced_rls_tables,
  pg_catalog.has_schema_privilege(me.oid, 'public', 'CREATE') AS public_schema_create
FROM me
"""


def _secret(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _dsn(
    role: str,
    *,
    host: str | None = None,
    password: str | None = None,
    sslmode: str | None = "verify-full",
    cert_dir: Path | None = None,
    ca: bool = True,
    database: str | None = None,
) -> str:
    """Build a libpq-style DSN from matrix material without logging it."""
    password = password if password is not None else _secret(MATRIX / role / "password")
    base = (
        f"postgresql://{quote(role, safe='')}:{quote(password, safe='')}@"
        f"{host or PARAMS['database_host']}:{PARAMS['database_port']}/"
        f"{database or PARAMS['database_name']}"
    )
    query: list[str] = []
    if sslmode:
        query.append(f"sslmode={sslmode}")
        if ca:
            query.append(f"sslrootcert={MATRIX / 'ca.crt'}")
        if cert_dir is not None:
            query.append(f"sslcert={cert_dir / 'client.crt'}")
            query.append(f"sslkey={cert_dir / 'client.key'}")
    return base + ("?" + "&".join(query) if query else "")


def _error(exc: BaseException) -> dict[str, str | None]:
    """Credential-free error classification."""
    return {
        "error_type": type(exc).__name__,
        "sqlstate": getattr(exc, "sqlstate", None),
    }


async def _connect(dsn: str):
    import asyncpg

    return await asyncio.wait_for(
        asyncpg.connect(dsn, timeout=CONNECT_TIMEOUT), CONNECT_TIMEOUT + 2
    )


async def _session_identity(conn) -> dict[str, object]:
    row = await conn.fetchrow(
        "SELECT current_user AS role_name, current_database() AS database_name, "
        "current_setting('server_version') AS server_version, s.ssl, s.version, "
        "s.cipher, s.bits, s.client_dn "
        "FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()"
    )
    return {
        "role_name": row["role_name"],
        "database_name": row["database_name"],
        "server_version": row["server_version"],
        "ssl": bool(row["ssl"]),
        "tls_version": row["version"],
        "cipher": row["cipher"],
        "bits": row["bits"],
        "client_dn": row["client_dn"],
    }


async def _attempt(dsn: str) -> dict[str, object]:
    try:
        conn = await _connect(dsn)
    except BaseException as exc:  # noqa: BLE001 - every rejection is evidence
        return {"accepted": False, **_error(exc)}
    try:
        return {"accepted": True, **(await _session_identity(conn))}
    finally:
        await conn.close()


# --------------------------------------------------------------------- commands


def profile_gate() -> dict[str, object]:
    """Replay the RC's own locked-profile validation for candidate DSNs."""
    from app.core import config as config_module
    from app.core.config import ConfigurationError, Settings

    profiles = {
        item["profile_id"]: item
        for item in json.loads(
            Path("/app/config/runtime-profiles.v1.json").read_text(encoding="utf-8")
        )["profiles"]
    }
    production = profiles[PARAMS["runtime_profile_id"]]["database"]
    compose = profiles[PARAMS["compose_profile_id"]]["database"]
    prod_base = (
        f"postgresql://{production['username']}:placeholder@{production['host']}:"
        f"{production['port']}/{production['name']}"
    )
    compose_base = (
        f"postgresql://{compose['username']}:placeholder@{compose['host']}:"
        f"{compose['port']}/{compose['name']}"
    )
    client_material = (
        f"&sslrootcert={UNIT_PREFIX}db-ca.crt&sslcert={UNIT_PREFIX}db-client.crt"
        f"&sslkey={UNIT_PREFIX}db-client.key"
    )
    cases = {
        "production_verify_full_sslmode_only": (production, prod_base + "?sslmode=verify-full"),
        "production_verify_full_with_ca_and_client_certificate": (
            production,
            prod_base + "?sslmode=verify-full" + client_material,
        ),
        "production_process_rewritten_asyncpg_scheme": (
            production,
            prod_base.replace("postgresql://", "postgresql+asyncpg://", 1)
            + "?sslmode=verify-full",
        ),
        "production_plaintext": (production, prod_base),
        "compose_as_shipped_no_sslmode": (compose, compose_base),
        "compose_with_verify_full": (compose, compose_base + "?sslmode=verify-full"),
    }
    results: dict[str, object] = {}
    for name, (profile, dsn) in cases.items():
        candidate = Settings.model_construct(database_url=dsn)
        try:
            candidate._validate_database_profile(profile)
        except ConfigurationError as exc:
            results[name] = {"accepted": False, "reason": str(exc)}
        else:
            results[name] = {"accepted": True}
    # F-01: the process-wide settings object rewrites a profile-conformant DSN.
    process_dsn = config_module.settings.database_url
    return {
        "cases": results,
        "process_settings_scheme": process_dsn.split("://", 1)[0],
        "database_url_file_bound_to_profile_prefix": _database_url_file_bound(),
    }


def _database_url_file_bound() -> bool:
    """True if the RC validator binds DATABASE_URL_FILE to the profile prefix."""
    source = Path("/app/app/core/config.py").read_text(encoding="utf-8")
    start = source.find("secret_prefix = profile[\"secret_path_prefix\"]")
    window = source[start : start + 1400] if start >= 0 else ""
    return "database_url_file" in window


async def connect_matrix() -> dict[str, object]:
    positives = {}
    for role in PARAMS["login_roles"]:
        positives[role] = await _attempt(_dsn(role, cert_dir=MATRIX / role))
    api = PARAMS["api_role"]
    other = PARAMS["cross_cn_role"]
    negatives = {
        "plaintext_sslmode_disable": _dsn(api, sslmode="disable"),
        "tls_without_client_certificate": _dsn(api),
        "tls_require_without_verification_or_certificate": _dsn(api, sslmode="require", ca=False),
        "client_certificate_cn_of_another_role": _dsn(api, cert_dir=MATRIX / other),
        "client_certificate_from_untrusted_ca": _dsn(api, cert_dir=MATRIX / "negative" / "rogue"),
        "expired_client_certificate": _dsn(api, cert_dir=MATRIX / "negative" / "expired"),
        "server_hostname_not_in_certificate": _dsn(
            api, host=PARAMS["mismatch_host"], cert_dir=MATRIX / api
        ),
        "wrong_password_with_valid_certificate": _dsn(
            api, password="not-the-password", cert_dir=MATRIX / api
        ),
        "superuser_over_network": _dsn(
            "postgres", password="not-a-network-credential", cert_dir=MATRIX / api
        ),
        "compose_profile_as_shipped_dsn": (
            f"postgresql://{PARAMS['compose_username']}:placeholder@"
            f"{PARAMS['compose_host']}:{PARAMS['database_port']}/{PARAMS['compose_database']}"
        ),
    }
    rejected = {}
    for name, dsn in negatives.items():
        rejected[name] = await _attempt(dsn)
    return {"positive": positives, "negative": rejected}


async def _expect_denied(conn, statement: str) -> dict[str, object]:
    tx = conn.transaction()
    await tx.start()
    try:
        await conn.execute(statement)
    except BaseException as exc:  # noqa: BLE001
        outcome = {"denied": True, **_error(exc)}
    else:
        outcome = {"denied": False}
    finally:
        await tx.rollback()
    return outcome


async def roles() -> dict[str, object]:
    isolation = {}
    for role in PARAMS["login_roles"]:
        conn = await _connect(_dsn(role, cert_dir=MATRIX / role))
        try:
            row = dict(await conn.fetchrow(ROLE_ISOLATION_QUERY))
        finally:
            await conn.close()
        flags = ("superuser", "bypassrls", "createrole", "createdb", "replication", "public_schema_create")
        row = {k: (bool(v) if k in flags else (int(v) if isinstance(v, int) else v)) for k, v in row.items()}
        row["runtime_role_isolated"] = not any(row[k] for k in flags) and not (
            row["elevated_role_memberships"] or row["owned_public_tables"]
        )
        row["rls_bypass_possible"] = bool(
            row["superuser"] or row["bypassrls"] or row["elevated_role_memberships"]
            or row["owned_rls_tables_without_force"]
        )
        isolation[role] = row

    api = PARAMS["api_role"]
    conn = await _connect(_dsn(api, cert_dir=MATRIX / api))
    try:
        runtime_denials = {
            "create_table": await _expect_denied(conn, "CREATE TABLE public.pas95_probe (x int)"),
            "disable_ledger_triggers": await _expect_denied(
                conn, "ALTER TABLE public.middleware_event_ledger DISABLE TRIGGER ALL"
            ),
            "drop_forced_rls": await _expect_denied(
                conn, "ALTER TABLE public.callback_record NO FORCE ROW LEVEL SECURITY"
            ),
            "session_replication_role_replica": await _expect_denied(
                conn, "SET LOCAL session_replication_role = replica"
            ),
            "set_role_migration_owner": await _expect_denied(conn, "SET LOCAL ROLE middleware_migration"),
            "delete_append_only_ledger": await _expect_denied(
                conn, "DELETE FROM public.middleware_event_ledger"
            ),
            "truncate_append_only_ledger": await _expect_denied(
                conn, "TRUNCATE public.middleware_event_ledger"
            ),
            "drop_schema_receipts": await _expect_denied(
                conn, "DROP TABLE public.middleware_schema_migrations"
            ),
        }
    finally:
        await conn.close()
    backup = PARAMS["backup_role"]
    conn = await _connect(_dsn(backup, cert_dir=MATRIX / backup))
    try:
        backup_denials = {
            "insert": await _expect_denied(
                conn,
                "INSERT INTO public.middleware_schema_migrations (version, name) VALUES (9999, 'pas95')",
            ),
        }
    finally:
        await conn.close()
    exporter = PARAMS["exporter_role"]
    conn = await _connect(_dsn(exporter, cert_dir=MATRIX / exporter))
    try:
        exporter_denials = {
            "read_application_table": await _expect_denied(
                conn, "SELECT count(*) FROM public.callback_record"
            ),
        }
    finally:
        await conn.close()
    return {
        "isolation": isolation,
        "runtime_denials": runtime_denials,
        "backup_denials": backup_denials,
        "exporter_denials": exporter_denials,
    }


_FILLERS = {
    "uuid": "gen_random_uuid()",
    "character varying": "'pas95'",
    "text": "'pas95'",
    "character": "'p'",
    "timestamp with time zone": "now()",
    "timestamp without time zone": "now()",
    "date": "current_date",
    "integer": "1",
    "bigint": "1",
    "smallint": "1",
    "numeric": "1",
    "boolean": "false",
    "jsonb": "'{}'::jsonb",
    "json": "'{}'::json",
}


async def _synthetic_callback_insert(conn, tenant: str) -> str:
    columns = await conn.fetch(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name='callback_record' "
        "AND is_nullable='NO' AND column_default IS NULL ORDER BY ordinal_position"
    )
    overrides = {
        "tenant_id": f"'{tenant}'",
        "campaign_id": f"'{PARAMS['rls_campaign']}'",
        "assigned_agent_id": "'pas95-agent'",
        "idempotency_key": "gen_random_uuid()::text",
    }
    names = [row["column_name"] for row in columns]
    values = [overrides.get(row["column_name"], _FILLERS[row["data_type"]]) for row in columns]
    for name, value in overrides.items():
        if name not in names:
            names.append(name)
            values.append(value)
    return f"INSERT INTO public.callback_record ({', '.join(names)}) VALUES ({', '.join(values)})"


async def rls() -> dict[str, object]:
    api = PARAMS["api_role"]
    tenant_a, tenant_b = PARAMS["rls_tenants"]
    campaign = PARAMS["rls_campaign"]
    conn = await _connect(_dsn(api, cert_dir=MATRIX / api))
    result: dict[str, object] = {}
    try:
        catalog = await conn.fetch(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
            "(SELECT count(*) FROM pg_policies p WHERE p.schemaname='public' "
            "AND p.tablename=c.relname) AS policies "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity ORDER BY 1"
        )
        result["rls_tables"] = [
            {
                "table": row["relname"],
                "enabled": row["relrowsecurity"],
                "forced": row["relforcerowsecurity"],
                "policies": int(row["policies"]),
            }
            for row in catalog
        ]
        tx = conn.transaction()
        await tx.start()
        try:
            async def scope(tenant: str, role: str = "service") -> None:
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true), "
                    "set_config('app.campaign_ids', $2, true), set_config('app.role', $3, true)",
                    tenant,
                    campaign,
                    role,
                )

            async def visible() -> int:
                return int(await conn.fetchval(
                    "SELECT count(*) FROM public.callback_record WHERE campaign_id=$1", campaign
                ))

            await scope(tenant_a)
            await conn.execute(await _synthetic_callback_insert(conn, tenant_a))
            result["tenant_a_sees_own_row"] = await visible()
            await scope(tenant_b)
            result["tenant_b_sees_tenant_a_rows"] = await visible()
            await scope("")
            result["unscoped_session_sees_rows"] = await visible()
            await scope(tenant_a, role="agent")
            result["tenant_a_agent_without_assignment_sees_rows"] = await visible()
            await scope(tenant_a)
            sp = conn.transaction()
            await sp.start()
            try:
                await conn.execute(await _synthetic_callback_insert(conn, tenant_b))
            except BaseException as exc:  # noqa: BLE001
                result["cross_tenant_insert"] = {"denied": True, **_error(exc)}
                await sp.rollback()
            else:
                result["cross_tenant_insert"] = {"denied": False}
                await sp.rollback()
        finally:
            await tx.rollback()
    finally:
        await conn.close()
    # The schema owner is subject to FORCE ROW LEVEL SECURITY as well.
    owner = PARAMS["migration_role"]
    conn = await _connect(_dsn(owner, cert_dir=MATRIX / owner))
    try:
        result["owner_unscoped_rows"] = int(
            await conn.fetchval("SELECT count(*) FROM public.callback_record")
        )
        result["owner_row_security_setting"] = await conn.fetchval("SHOW row_security")
    finally:
        await conn.close()
    return result


async def pool() -> dict[str, object]:
    from app.core import runtime as runtime_module
    from app.core.config import settings
    from app.db.session import _build_engine
    from sqlalchemy import text

    dsn = _secret(UNIT_DSN_FILE)
    started = time.monotonic()
    p = await runtime_module._open_pool(dsn)
    asyncpg_result: dict[str, object] = {
        "min_size": p.get_min_size(),
        "max_size": p.get_max_size(),
        "command_timeout_seconds": runtime_module.SHARED_POOL_COMMAND_TIMEOUT_SECONDS,
        "open_seconds": round(time.monotonic() - started, 3),
    }
    held = []
    try:
        for _ in range(p.get_max_size()):
            held.append(await p.acquire(timeout=10))
        try:
            extra = await p.acquire(timeout=1)
        except asyncio.TimeoutError:
            asyncpg_result["acquire_beyond_max_times_out"] = True
        else:
            held.append(extra)
            asyncpg_result["acquire_beyond_max_times_out"] = False
        conn = held[0]
        row = await conn.fetchrow(
            "SELECT count(*) FILTER (WHERE a.usename = current_user) AS role_sessions, "
            "count(*) FILTER (WHERE a.usename = current_user AND s.ssl) AS role_tls_sessions, "
            "array_agg(DISTINCT a.application_name) FILTER (WHERE a.usename = current_user) AS application_names, "
            "current_setting('statement_timeout') AS statement_timeout, "
            "current_setting('lock_timeout') AS lock_timeout, "
            "current_setting('idle_in_transaction_session_timeout') AS idle_in_tx_timeout, "
            "current_setting('max_connections')::int AS max_connections, "
            "current_setting('superuser_reserved_connections')::int AS superuser_reserved "
            "FROM pg_stat_activity a JOIN pg_stat_ssl s ON s.pid = a.pid"
        )
        asyncpg_result.update({k: (list(v) if isinstance(v, list) else v) for k, v in dict(row).items()})
    finally:
        for conn in held:
            await p.release(conn)
        await p.close()

    engine = _build_engine(settings, dsn)
    engine_result: dict[str, object] = {
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_timeout_seconds": settings.database_pool_timeout_seconds,
        "pool_recycle_seconds": settings.database_pool_recycle_seconds,
        "command_timeout_seconds": settings.database_command_timeout_seconds,
    }
    connections = []
    try:
        capacity = settings.database_pool_size + settings.database_max_overflow
        for _ in range(capacity):
            connection = await engine.connect()
            await connection.execute(text("SELECT 1"))
            connections.append(connection)
        started = time.monotonic()
        try:
            extra = await engine.connect()
        except Exception as exc:  # noqa: BLE001 - sqlalchemy TimeoutError
            engine_result["connect_beyond_capacity"] = {
                "refused": True,
                "error_type": type(exc).__name__,
                "waited_seconds": round(time.monotonic() - started, 1),
            }
        else:
            connections.append(extra)
            engine_result["connect_beyond_capacity"] = {"refused": False}
        ssl = await connections[0].execute(
            text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        )
        engine_result["tls_active"] = bool(ssl.scalar())
    finally:
        for connection in connections:
            await connection.close()
        await engine.dispose()
    return {"asyncpg_pool": asyncpg_result, "sqlalchemy_engine": engine_result}


async def api() -> dict[str, object]:
    from fastapi.exception_handlers import http_exception_handler
    from fastapi.testclient import TestClient
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from starlette.middleware.exceptions import ExceptionMiddleware

    from app.api.internal import database as database_api
    from app.core import runtime as runtime_module
    from app.core.config import CANONICAL_SCHEMA_HEAD

    dsn = _secret(UNIT_DSN_FILE)
    scopes: list[str] = []

    class RecordingTokens:
        async def verify(self, _authorization, *, expected_client_id, required_scope):
            scopes.append(required_scope)
            return SimpleNamespace(client_id=expected_client_id)

    database_api.caller_for_authorization = lambda _authorization: SimpleNamespace(
        client_id="pas95-certification"
    )
    class RouterHost:
        """Serve the canonical router alone (no app-level middleware).

        Supplies what the handlers read from ``request.app`` and runs the
        pool on the TestClient's event loop via ASGI lifespan.
        """

        def __init__(self, router) -> None:
            # The exception layer a FastAPI application installs, so 404/405/503 keep their codes.
            self.router = ExceptionMiddleware(
                router, handlers={StarletteHTTPException: http_exception_handler}
            )
            self.state = SimpleNamespace()

        async def __call__(self, scope, receive, send):  # pragma: no cover - runs in image
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        pool = await runtime_module._open_pool(dsn)
                        self.state.runtime = SimpleNamespace(
                            pool=pool,
                            tokens=RecordingTokens(),
                            settings=SimpleNamespace(
                                database_url=dsn,
                                schema_head=CANONICAL_SCHEMA_HEAD,
                                database_certification_evidence_dir=PARAMS.get("api_evidence_dir", ""),
                            ),
                        )
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        await self.state.runtime.pool.close()
                        await send({"type": "lifespan.shutdown.complete"})
                        return
            scope["app"] = self
            # FastAPI's app middleware normally provides this per-request stack.
            async with contextlib.AsyncExitStack() as stack:
                scope["fastapi_middleware_astack"] = stack
                await self.router(scope, receive, send)

    app = RouterHost(database_api.router)
    headers = {"Authorization": "Bearer pas95-certification"}
    routes = sorted(
        (sorted(route.methods)[0], route.path)
        for route in database_api.router.routes
        if getattr(route, "methods", None)
    )
    responses: dict[str, object] = {}
    leaked = False
    password = dsn.split("://", 1)[1].split("@", 1)[0].split(":", 1)[1]
    with TestClient(app) as client:
        for method, path in routes:
            response = client.request(method, path, headers=headers)
            body_text = response.text
            leaked = leaked or password in body_text or "PRIVATE KEY" in body_text
            responses[f"{method} {path}"] = {"status": response.status_code, "body": response.json()}
        negatives = {}
        prefix = "/internal/v1/database"
        for method, path in (
            ("POST", f"{prefix}/migrations/apply"),
            ("POST", f"{prefix}/sql"),
            ("POST", f"{prefix}/query"),
            ("DELETE", f"{prefix}/backups"),
            ("POST", f"{prefix}/restores"),
        ):
            negatives[f"{method} {path}"] = client.request(method, path, headers=headers).status_code
    return {
        "routes": [f"{m} {p}" for m, p in routes],
        "responses": responses,
        "mutation_routes": negatives,
        "scopes_requested": sorted(set(scopes)),
        "secret_material_in_responses": leaked,
        "role_isolation_route_present": any(p.endswith("/security/roles") for _, p in routes),
    }


async def schema() -> dict[str, object]:
    """The RC's own SQL-managed schema admission, per table (catalog reads only)."""
    import asyncpg

    from scripts.production_migration_authority import validate_authority
    from scripts.runtime_sql_schema import inspect_schema, load_contract, structure_digest

    root = Path("/app")
    _, _, history_digest = validate_authority(root)
    required = load_contract(root, history_digest)
    conn = await asyncpg.connect(
        _secret(UNIT_DSN_FILE), timeout=CONNECT_TIMEOUT, server_settings={"search_path": "public"}
    )
    try:
        actual = await inspect_schema(conn, tuple(sorted(required)))
    finally:
        await conn.close()
    return {
        name: {"matches_contract": structure_digest(actual[name]) == digest, "structure": actual[name]}
        for name, digest in required.items()
    }


def scrape() -> dict[str, object]:
    import urllib.request

    results = {}
    for name, url in PARAMS["exporters"].items():
        deadline = time.monotonic() + 30
        text_body = ""
        while time.monotonic() < deadline:
            try:
                text_body = urllib.request.urlopen(url, timeout=5).read().decode("utf-8")
                if "\npg_up " in "\n" + text_body:
                    break
            except Exception:  # noqa: BLE001 - exporter still starting
                pass
            time.sleep(1)
        metrics: dict[str, float] = {}
        for line in text_body.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            key, _, value = line.rpartition(" ")
            base = key.split("{", 1)[0]
            if base in {"pg_up", "pg_settings_max_connections"} or (
                base == "pg_stat_database_numbackends"
                and f'datname="{PARAMS["database_name"]}"' in key
            ):
                metrics[base] = float(value)
        up = metrics.get("pg_up")
        backends = metrics.get("pg_stat_database_numbackends")
        max_conn = metrics.get("pg_settings_max_connections")
        results[name] = {
            "scraped": bool(text_body),
            "metric_families": len({l.split(" ", 2)[2] for l in text_body.splitlines() if l.startswith("# TYPE ")}),
            "pg_up": up,
            "pg_stat_database_numbackends": backends,
            "pg_settings_max_connections": max_conn,
            "alert_CodestraPostgresDown_condition": up == 0 if up is not None else None,
            "alert_CodestraPostgresConnectionSaturation_condition": (
                backends / max_conn > 0.8 if backends is not None and max_conn else None
            ),
        }
    return results


COMMANDS = {
    "profile-gate": profile_gate,
    "connect-matrix": connect_matrix,
    "roles": roles,
    "rls": rls,
    "pool": pool,
    "api": api,
    "schema": schema,
    "scrape": scrape,
}


def main() -> None:
    command = COMMANDS[sys.argv[1]]
    try:
        result = command()
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        payload = {"command": sys.argv[1], "ok": True, "result": result}
    except BaseException as exc:  # noqa: BLE001 - reported, never raw
        payload = {"command": sys.argv[1], "ok": False, **_error(exc)}
    sys.stdout.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    main()
