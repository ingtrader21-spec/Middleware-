#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

: "${RUNTIME_INTEGRATION_TESTS:?RUNTIME_INTEGRATION_TESTS must be set to 1}"
: "${RUNTIME_INTEGRATION_ALLOW_DISPOSABLE:?RUNTIME_INTEGRATION_ALLOW_DISPOSABLE must be YES}"
: "${DATABASE_URL:?DATABASE_URL is required}"
: "${REDIS_URL:?REDIS_URL is required}"

if [[ "$RUNTIME_INTEGRATION_TESTS" != "1" ]]; then
  echo "ERROR=RUNTIME_INTEGRATION_TESTS_MUST_EQUAL_1" >&2
  exit 1
fi
if [[ "$RUNTIME_INTEGRATION_ALLOW_DISPOSABLE" != "YES" ]]; then
  echo "ERROR=DISPOSABLE_TEST_ACK_REQUIRED" >&2
  exit 1
fi

python3 - <<'PY'
import os
import re
from urllib.parse import unquote, urlparse

safe_db_name = re.compile(r"^middleware_test_[A-Za-z0-9_]+$")
pg = urlparse(os.environ["DATABASE_URL"])
redis = urlparse(os.environ["REDIS_URL"])

if pg.scheme not in {"postgres", "postgresql"}:
    raise SystemExit("DATABASE_URL must use postgres/postgresql")
if pg.params or pg.query or pg.fragment:
    raise SystemExit("DATABASE_URL must not contain params, query overrides, or fragments")
if pg.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit("DATABASE_URL must target localhost disposable PostgreSQL")
database_name = unquote(pg.path.lstrip("/"))
if not safe_db_name.fullmatch(database_name):
    raise SystemExit("database name must match middleware_test_[A-Za-z0-9_]+")

if redis.scheme not in {"redis", "rediss"}:
    raise SystemExit("REDIS_URL must use redis/rediss")
if redis.params or redis.query or redis.fragment:
    raise SystemExit("REDIS_URL must not contain params, query overrides, or fragments")
if redis.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit("REDIS_URL must target localhost disposable Redis")
try:
    redis_db = int(unquote(redis.path.lstrip("/") or "0"))
except ValueError as exc:
    raise SystemExit("REDIS_URL must select an explicit numeric disposable DB") from exc
if redis_db <= 0:
    raise SystemExit("REDIS_URL must not target Redis DB 0")

print("DISPOSABLE_INTEGRATION_TARGETS=PASS")
PY

python3 -m venv .venv-integration
trap 'rm -rf .venv-integration' EXIT
. .venv-integration/bin/activate
python -m pip install --disable-pip-version-check --no-input --quiet --upgrade pip
python -m pip install --disable-pip-version-check --no-input --quiet \
  --require-hashes -r requirements-test.txt

pytest -q tests/integration

echo "POSTGRES_INTEGRATION=PASS"
echo "REDIS_INTEGRATION=PASS"
echo "INBOX_CONCURRENCY=PASS"
echo "IMMUTABLE_EVENT_LEDGER=PASS"
echo "EVENT_LEDGER_CONCURRENT_CHAIN=PASS"
echo "OUTBOX_LEASE_DLQ=PASS"
echo "OUTBOX_PRE_DISPATCH_LEASE_REFRESH=PASS"
echo "RUNTIME_INTEGRATION_CI=PASS"
