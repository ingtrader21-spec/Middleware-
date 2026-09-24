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

database = urlparse(os.environ["DATABASE_URL"])
redis = urlparse(os.environ["REDIS_URL"])
if database.scheme not in {"postgres", "postgresql"}:
    raise SystemExit("DATABASE_URL must use postgres/postgresql")
if database.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit("DATABASE_URL must target disposable localhost PostgreSQL")
if database.params or database.query or database.fragment:
    raise SystemExit("DATABASE_URL must not contain overrides")
if re.fullmatch(r"middleware_test_[A-Za-z0-9_]+", unquote(database.path[1:])) is None:
    raise SystemExit("DATABASE_URL must select a middleware_test_* database")
if redis.scheme not in {"redis", "rediss"}:
    raise SystemExit("REDIS_URL must use redis/rediss")
if redis.hostname not in {"127.0.0.1", "localhost"}:
    raise SystemExit("REDIS_URL must target disposable localhost Redis")
if redis.params or redis.query or redis.fragment:
    raise SystemExit("REDIS_URL must not contain overrides")
if int(unquote(redis.path[1:] or "0")) <= 0:
    raise SystemExit("REDIS_URL must select a nonzero disposable database")
print("SYNTHETIC_ACCEPTANCE_TARGETS=PASS")
PY

NATS_CONTAINER="codestra-synthetic-acceptance"
NATS_IMAGE="nats@sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3"

cleanup() {
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  rm -rf .venv-synthetic-acceptance
}
trap cleanup EXIT

docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
docker run --detach \
  --name "$NATS_CONTAINER" \
  --publish 127.0.0.1:4222:4222 \
  "$NATS_IMAGE" \
  --jetstream \
  --store_dir /data

python3 -m venv .venv-synthetic-acceptance
. .venv-synthetic-acceptance/bin/activate
python -m pip install --disable-pip-version-check --no-input --quiet \
  --require-hashes -r requirements-test.txt

python - <<'PY'
import asyncio
import nats


async def wait_until_ready() -> None:
    for _ in range(100):
        try:
            client = await nats.connect(
                "nats://127.0.0.1:4222",
                connect_timeout=0.2,
                max_reconnect_attempts=0,
            )
        except Exception:
            await asyncio.sleep(0.1)
            continue
        await client.close()
        return
    raise SystemExit("disposable NATS server did not become ready")


asyncio.run(wait_until_ready())
PY

export NATS_INTEGRATION_TESTS=1
export NATS_TEST_URL=nats://127.0.0.1:4222
export TEMPORAL_INTEGRATION_TESTS=1
pytest -q tests/integration/test_synthetic_acceptance.py

echo "SYNTHETIC_API_AUTH_REPLAY=PASS"
echo "SYNTHETIC_POSTGRES_LEDGER_OUTBOX=PASS"
echo "SYNTHETIC_JETSTREAM_DELIVERY=PASS"
echo "SYNTHETIC_TEMPORAL_ORCHESTRATION=PASS"
echo "SYNTHETIC_NO_PROVIDER_COMMAND=PASS"
echo "SYNTHETIC_ACCEPTANCE_E2E=PASS"
