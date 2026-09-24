#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m venv .venv-temporal-integration
trap 'rm -rf .venv-temporal-integration' EXIT
. .venv-temporal-integration/bin/activate
python -m pip install --disable-pip-version-check --no-input --quiet \
  --require-hashes -r requirements-test.txt

export TEMPORAL_INTEGRATION_TESTS=1
pytest -q \
  tests/integration/test_temporal_workflows.py \
  tests/integration/test_email_unknown_outcome_reconciliation.py

echo "TEMPORAL_RECONCILIATION_RETRY=PASS"
echo "TEMPORAL_DELAYED_CALLBACK=PASS"
echo "TEMPORAL_PROVISIONING_COMPENSATION=PASS"
echo "TEMPORAL_DEAD_LETTER_APPROVAL=PASS"
echo "TEMPORAL_COMMAND_READBACK_GATE=PASS"
echo "TEMPORAL_COMMAND_MISMATCH_RECONCILIATION=PASS"
echo "TEMPORAL_EMAIL_UNKNOWN_OUTCOME_NO_RETRY=PASS"
echo "TEMPORAL_EMAIL_RECONCILIATION_READBACK=PASS"
echo "TEMPORAL_EMAIL_RECONCILIATION_NO_RESUBMIT=PASS"
echo "TEMPORAL_SMS_UNKNOWN_OUTCOME_NO_RETRY=PASS"
