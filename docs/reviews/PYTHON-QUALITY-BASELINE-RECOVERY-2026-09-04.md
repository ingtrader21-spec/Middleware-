# Python quality baseline recovery

## Decision

Recover only the current-main-safe quality toolchain from closed draft PR #39.
Do not transplant its stale 36-file formatting and typing rewrite.

## Recovered authority

- `requirements-quality.in` pins Ruff, mypy, pytest, and JSON Schema types.
- `requirements-quality.txt` is hash locked for deterministic installation.
- root `mypy.ini` checks core, workers, scripts, architecture, SDK, and tests while
  excluding Connector Runtime, which has an intentionally independent dependency
  environment.
- `services/connector-runtime/mypy.ini` checks Connector Runtime source and tests
  against that environment.
- `.github/workflows/python-quality-baseline.yml` measures Ruff, core mypy, and
  Connector Runtime mypy on the exact pull-request head or protected-main SHA.

## Enforcement boundary

The three quality jobs are deliberately **report only** while current-main debt
is measured and remediated. Tool installation, lock integrity, checkout identity,
configuration, and invocation failures still fail the job. Ordinary Ruff or mypy
findings produce warnings and job summaries but do not become protected required
checks yet.

Ruff and mypy may become required only after all of the following are true:

1. current-main baselines reach zero;
2. fixes are split into small domain-focused pull requests;
3. generated contracts, migrations, idempotency, outbox, reconciliation, and
   fail-closed runtime behavior remain unchanged;
4. both Python 3.12 and 3.13 support remain intact where applicable;
5. the existing image, security, SBOM, integration, and synthetic no-effect gates
   remain green;
6. the protected ruleset is changed through a separately reviewed governance
   update.

## Safety

This recovery adds development-only tooling and CI reporting. It does not modify
runtime/test images, production dependencies, application source, migrations,
provider bindings, secrets, deployment manifests, server state, traffic, or any
external-effect capability.
