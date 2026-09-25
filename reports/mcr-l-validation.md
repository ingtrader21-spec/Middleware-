# MCR-L implementation validation — 2026-09-24

Workspace: `/home/codestra/Worktrees/MCR-next8/mcr-l`.
Branch: `mission/mcr-l-observability-20260924`.
Base HEAD: `d007a6a8fadcc965a1fbc328916df1da5599e5d5`.
Existing changes were preserved. No production mutation, deployment, rollback,
provider activation, collector registration, commit or push was performed.

## Implementation and contracts

Private bounded decision/suppression/health/cap counters, sanitized generated
local span logs, tenant-checked readback, JSON Schema/OpenAPI and pending service
catalog are retained. Completion lag now excludes partial projections. Completed
normalized delivery-health event counters exclude duplicate, partial and failed
attempts; scoped readback counters distinguish blocked/unavailable/denied results.
Connector catalog covers Klyrow, Telnexa, Evolution, VICIdial, Odoo and Middleware.
Alert coverage includes missing dead-letter evidence, lag, incomplete projections,
replay spikes, unavailable readback and negative delivery signals. The runbook
specifies completion SLI limitations, reconciliation, staging checks and rollback
observability preserving durable evidence.

The delivery ledger has no durable dead-letter authority: `dead_letter: null`
blocks readiness. No readback polling worker or certified OTLP export exists.
`reports/mcr-l-staging-evidence.json` explicitly records staging as not executed;
local checks do not substitute for staging certification. Catalog registration,
public routes and provider effects remain disabled.

## Fresh checks

Interpreter: `/tmp/codestra-mcr-a-venv/bin/python` (Python 3.14).

- Focused suite: `python -m pytest -q tests/test_mcr_observability.py tests/test_mcr_observability_contracts.py tests/test_campaign_recycling_engine.py tests/test_campaign_recycling_contracts.py`.
- `python scripts/validate_mcr_observability.py`: PASS.
- `python scripts/validate_campaign_recycling_contracts.py`: PASS.
- Ruff lint for all six changed/new Python files: PASS.
- Ruff format for the four new Python files: PASS.
- `python -m mypy --follow-imports=silent app/mcr_observability.py`: PASS.
- `git diff --check` and `make security`: PASS.

Regression tests first reproduced partials contaminating completion lag and
missing delivery-health/readback observations. They passed after implementation.
Contract mutation tests reject activated connectors and omitted reconciliation,
health, staging and rollback contracts. Existing tests cover private scrape auth,
secret exclusion, tenant denial, missing/stale/future evidence, numeric evidence,
commit failure, duplicate and partial replay. Database failure coverage verifies
unavailable readback telemetry without logging exception contents.

## Commit/push blockers

`make verify PYTHON=/tmp/codestra-mcr-a-venv/bin/python` exits 2 because its first
gate requires Python 3.12; only Python 3.14 is available. No gate was weakened.

The full suite was attempted with `timeout 50s python -m pytest -x -q tests -o
faulthandler_timeout=30` and exited 124. It stalled in
`tests/recording/test_api_contract.py::test_exporter_mtls_is_required_and_middleware_assigns_uid`.
The thread dump shows Starlette TestClient waiting on AnyIO's asyncio portal.
The temporary diagnostic log is `/tmp/mcr-l-full-tests.log`.

Repository-wide Ruff still reports pre-existing F842 at
`app/api/v1/activity.py:189` and F401 at `app/observability_projection.py:15`.
Format checks also flag the existing modified `app/core/campaign_recycling.py`
and `app/observability.py`; broad reformatting was not applied to preserved work.
Full-suite, repository-format and repository-typecheck success is not claimed.

`git ls-remote --heads origin mission/mcr-l-observability-20260924` failed with
`Could not resolve host: github.com`. Local equals remote is unverified. The local
branch currently tracks a different branch (`origin/mission/mcr-authority-contracts-20260924`);
that upstream was not changed or used as a push destination. No commit/push is
permitted while required gates are not green.
