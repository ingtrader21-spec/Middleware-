#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf '==> Checking Git whitespace errors\n'
git diff --check

printf '==> Checking shell syntax\n'
while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find scripts -type f -name '*.sh' -print0 | sort -z)

printf '==> Compiling Python source\n'
python_dirs=(scripts architecture)
for candidate in app src middleware tests workers migrations; do
  if [[ -d "$candidate" ]]; then
    python_dirs+=("$candidate")
  fi
done
python3 -m compileall -q "${python_dirs[@]}"

printf '==> Validating encoded GitHub repository governance\n'
python3 scripts/validate_repository_governance.py

printf '==> Validating live-governance applier source plan\n'
python3 scripts/apply_repository_governance.py

# The mandatory bundle validator runs in project_ci.sh after hash-locked
# dependencies are installed, before pytest; clean source jobs have no PyYAML.

printf '==> Validating strict automation v2 route conformance\n'
python3 scripts/validate_automation_contract_conformance.py

printf '==> Validating automation v2 authorization invariants\n'
python3 scripts/validate_automation_operation_policy.py

printf '==> Validating repository safety controls\n'
python3 scripts/validate_repository.py

printf '==> Validating Middleware authority convergence controls\n'
python3 scripts/validate_middleware_authority_convergence.py
python3 scripts/validate_middleware_authority_assets.py

printf '==> Validating integration workstream manifest\n'
python3 scripts/validate_workstream_manifest.py

printf '==> Validating canonical connectivity contracts\n'
python3 scripts/validate_connectivity_contracts.py

printf '==> Validating Keycloak identity, API audience, and webhook contracts\n'
python3 scripts/validate_identity_webhook_contracts.py

printf '==> Validating MoneyBee account event boundaries\n'
python3 scripts/validate_moneybee_account_events.py

printf '==> Validating n8n command and result token directions\n'
python3 scripts/validate_n8n_flow.py

printf '==> Validating canonical provider-operation authority\n'
python3 scripts/validate_provider_operation_policy.py
python3 -m unittest discover -s tests -p 'test_provider_operation_policy.py'

printf '==> Validating supplemental site/provider workstreams\n'
python3 scripts/validate_site_workstreams.py

printf '==> Validating server routes and Odoo lead intake\n'
python3 scripts/validate_site_routes_and_leads.py

printf '==> Validating unified-intake observability and pending activation gates\n'
python3 scripts/validate_intake_observability.py

printf '==> Validating fixed-recipient observability alert delivery\n'
python3 scripts/validate_observability_alert_contract.py

if [[ -x scripts/project_ci.sh ]]; then
  printf '==> Running project-specific locked dependency and test pipeline\n'
  scripts/project_ci.sh
else
  printf '%s\n' \
    'PROJECT_SPECIFIC_CI=NOT_YET_IMPORTED' \
    'Add an executable scripts/project_ci.sh in the same pull request that imports the authoritative middleware source.'
fi
