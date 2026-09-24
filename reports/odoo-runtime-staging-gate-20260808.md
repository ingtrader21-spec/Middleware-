# Odoo runtime staging gate — 2026-08-08

## Snapshot

- Execution server: `middleware`, public `65.109.65.169`, private `10.40.0.1`.
- Middleware base: `Codestra-SRL/codestra-middleware` `main` at `289047c`.
- Odoo source: `Codestra-SRL/codestra-odoo-addons` `main` at `2d20436`.
- Odoo container: `codestra-odoo19-staging-odoo19-staging-1`.
- Odoo database: `odoo19_staging`; Odoo runtime: `19.0-20260630`.
- Reviewed addon archive SHA-256: `f8f40cdd8b2187236e82232bd62c85c81c00a42eb40dc65ac948e90c2c437727`.
- Installed modules: `call_center_campaign 19.0.5.1.0`, `codestra_integration_hub 19.0.1.0.0`.

## Safe remediation completed

Staging Odoo now mounts the reviewed repository at `/mnt/extra-addons` instead of `/root/odoo19-upgrade`. The container was recreated, reached healthy state, loaded the controller-bearing addon, and returned HTTP 200 from `/health/live`. Production was not touched.

Middleware runtime Compose now declares the isolated Odoo and identity networks for the sync worker, secret-file mounts, and independent disabled-by-default read/sync/result/staging-write/production-write gates. Production and live-write gates remain false.

## External integration blocker

Authenticated `/health/ready` and `/api/v1/integration/capabilities` correctly returned HTTP 401. The available staging `SERVICE_TOKEN` is an opaque 64-character value rather than a three-segment signed JWT. The result-worker client-secret file referenced by runtime Compose is absent. No authentication bypass, replacement credential, or weakened verifier was introduced.

Because no valid approved staging client-credentials identity is available, claim/lease, authenticated reads, middleware intake, result delivery, write canary, recovery, latency, and round-trip certification were not attempted. Every staging and production write flag remains false and no Odoo business record was created, updated, or deleted by this mission.

## Validation

- Ruff: pass.
- Mypy: pass, 147 source files.
- Middleware suite: 846 passed, 20 skipped.
- New staging-gate tests: 4 passed.
- Secret scan: pass.
- Odoo controller compilation: pass.

## Rollback evidence

Restore `/root/odoo19-upgrade:/mnt/extra-addons:ro` in `/opt/codestra/odoo19-staging/compose.yaml` and recreate only `odoo19-staging`. Preserve all outbox/inbox rows. Do not delete integration evidence.
