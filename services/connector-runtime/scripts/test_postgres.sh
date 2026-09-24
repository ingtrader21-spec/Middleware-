#!/usr/bin/env bash
set -Eeuo pipefail

: "${ADMIN_DATABASE_URL:?ADMIN_DATABASE_URL is required}"
: "${APP_DATABASE_URL:?APP_DATABASE_URL is required}"
: "${POSTGRES_TOOL_IMAGE:?POSTGRES_TOOL_IMAGE is required}"

# This script performs destructive schema and database operations and is only
# safe against the disposable loopback PostgreSQL service created by CI.
python3 - "$ADMIN_DATABASE_URL" "$APP_DATABASE_URL" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

for name, value in zip(("ADMIN_DATABASE_URL", "APP_DATABASE_URL"), sys.argv[1:], strict=True):
    parsed = urlsplit(value)
    if parsed.scheme not in {
        "postgres",
        "postgresql",
        "postgresql+psycopg",
        "postgresql+psycopg_async",
    }:
        raise SystemExit(f"{name} must use PostgreSQL")
    hostname = parsed.hostname
    try:
        loopback = hostname == "localhost" or (
            hostname is not None and ipaddress.ip_address(hostname).is_loopback
        )
    except ValueError:
        loopback = False
    if not loopback:
        raise SystemExit(f"{name} must target a disposable loopback database")
PY

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ADMIN_PGURL="${ADMIN_DATABASE_URL/postgresql+psycopg:/postgresql:}"
ADMIN_PGURL="${ADMIN_PGURL/postgresql+psycopg_async:/postgresql:}"

export DATABASE_URL="$ADMIN_DATABASE_URL"
alembic upgrade head

# Use a non-owner, non-superuser role for RLS and concurrency tests. PostgreSQL
# superusers bypass RLS even when FORCE ROW LEVEL SECURITY is enabled.
psql "$ADMIN_PGURL" -v ON_ERROR_STOP=1 <<'SQL'
DO $codestra$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'connector_app_test') THEN
        CREATE ROLE connector_app_test
            LOGIN PASSWORD 'connector_app_test'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
END
$codestra$;
GRANT USAGE ON SCHEMA connector_sdk TO connector_app_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA connector_sdk TO connector_app_test;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA connector_sdk TO connector_app_test;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA connector_sdk TO connector_app_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA connector_sdk
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO connector_app_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA connector_sdk
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO connector_app_test;
SQL

export ADMIN_DATABASE_URL APP_DATABASE_URL
pytest -q -m postgres

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
BASE_URL="${ADMIN_PGURL%/*}"
RESTORE_URL="$BASE_URL/connector_restore"

# Run pg_dump and pg_restore from the same pinned PostgreSQL major version as
# the disposable server. The hosted runner's client may be older than it.
docker run --rm --network host \
    -e PGPASSWORD=connector \
    -v "$TMP_DIR:/backup" \
    "$POSTGRES_TOOL_IMAGE" \
    pg_dump -h 127.0.0.1 -U connector -d connector \
        --format=custom --no-owner --no-acl --file=/backup/connector.dump

psql "$BASE_URL/postgres" -v ON_ERROR_STOP=1 \
    -c 'DROP DATABASE IF EXISTS connector_restore' \
    -c 'CREATE DATABASE connector_restore'

docker run --rm --network host \
    -e PGPASSWORD=connector \
    -v "$TMP_DIR:/backup:ro" \
    "$POSTGRES_TOOL_IMAGE" \
    pg_restore -h 127.0.0.1 -U connector -d connector_restore \
        --no-owner --no-acl /backup/connector.dump

psql "$RESTORE_URL" -v ON_ERROR_STOP=1 \
    -c 'SELECT count(*) FROM connector_sdk.connector_installations'
psql "$BASE_URL/postgres" -v ON_ERROR_STOP=1 \
    -c 'DROP DATABASE connector_restore'

export DATABASE_URL="$ADMIN_DATABASE_URL"
alembic downgrade base
alembic upgrade head
alembic current
