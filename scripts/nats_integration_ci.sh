#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NATS_CONTAINER="codestra-nats-integration"
NATS_IMAGE="nats@sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3"

cleanup() {
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  rm -rf .venv-nats-integration
}
trap cleanup EXIT

docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
docker run --detach \
  --name "$NATS_CONTAINER" \
  --publish 127.0.0.1:4222:4222 \
  "$NATS_IMAGE" \
  --jetstream \
  --store_dir /data

python3 -m venv .venv-nats-integration
. .venv-nats-integration/bin/activate
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
        try:
            assert client.connected_url is not None
            return
        finally:
            await client.close()
    raise SystemExit("disposable NATS server did not become ready")


asyncio.run(wait_until_ready())
PY

export NATS_INTEGRATION_TESTS=1
export NATS_TEST_URL=nats://127.0.0.1:4222
export NATS_TEST_CONTAINER="$NATS_CONTAINER"
pytest -q tests/integration/test_nats_jetstream.py

echo "NATS_ACK_DEDUP_REPLAY=PASS"
echo "NATS_RECONNECT=PASS"
echo "NATS_ISOLATED_STAGING_PATH=PASS"
