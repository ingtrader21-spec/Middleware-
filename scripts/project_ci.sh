#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf '==> Validating the canonical calling-contract pin\n'
python3 scripts/validate_calling_contract_pin.py
python3 scripts/validate_calling_contract_pin.py --self-test

python3 -m venv .venv-ci
trap 'rm -rf .venv-ci' EXIT

. .venv-ci/bin/activate
python -m pip install --disable-pip-version-check --no-input --quiet --upgrade pip
python -m pip install --disable-pip-version-check --no-input --quiet \
  --require-hashes -r requirements-test.txt

printf '==> Validating all Codestra service contracts in the locked environment\n'
python scripts/validate_codestra_manifest.py

python -m compileall -q app workers tests scripts/validate_platform_control_plane.py scripts/validate_calling_contract_pin.py
python scripts/validate_platform_control_plane.py
python scripts/validate_calling_contract_pin.py
python scripts/validate_calling_contract_pin.py --self-test
pytest -q tests

python - <<'PY'
from app.contracts import WEBHOOK_ROUTES

expected = {
    "/api/v1/odoo/events",
    "/api/v1/n8n/results",
    "/api/v1/vicidial/events",
    "/api/v1/telnexa/events",
    "/api/v1/klyrow/events",
    "/api/v1/kyqra/results",
    "/api/v1/kyqra/progress",
    "/api/v1/postly/events",
}
actual = {route.path for route in WEBHOOK_ROUTES}
assert actual == expected, (actual, expected)
print("RUNTIME_CONTRACT_ROUTES=PASS")
PY

echo "PROJECT_SPECIFIC_CI=PASS"
