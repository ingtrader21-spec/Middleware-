# Cross-repository integration certification gate — 2026-09-16

Mission: one-Codex alignment of Caddy, Kong, Keycloak, Middleware, Odoo and N8N so Middleware is the single cross-system command authority. Production activation was not authorized and was not performed. `TEST_SYN` is the only campaign referenced by any runtime probe.

## Verdicts

| Verdict | Value | Basis |
|---|---|---|
| `SOURCE_GO` | **YES** | Every mission-relevant source check below exits 0 at the exact source SHAs; identical contract bytes and digest in all six repositories; no secret findings; no canonical 8080 reference; no uncommitted certification code. |
| `LOCAL_INTEGRATION_GO` | **NO** | The Docker Linux engine on the certifying host cannot start (WSL is not installed; Docker Desktop backend answers HTTP 500). No isolated Compose stack, disposable PostgreSQL/Redis, or Odoo 19 runtime could be started. Reproduction below. |
| `STAGING_GO` | **NO** | No staging DNS, secret-file references, seeded data, logs or restart authority were available to this session. The staging runner (`scripts/certify_edge_integration.py`) is committed and tested but was not executed against staging. |
| `PRODUCTION_GO` | **NO** | Never issued by this mission. Requires separately reviewed signed digests, an updated production lock, staging evidence, independent GitHub approvals and a separate read-only-canary authorization. |

## Repositories, branches and SHAs

All work was done on the isolated branch `codex/cross-repo-authority-20260916` in a dedicated worktree per repository. Dirty main checkouts were left untouched. "Certified SHA" is the commit on which every check in this document was executed from a clean worktree (`git status --porcelain` empty). The Middleware pull request additionally carries this evidence commit on top of its certified SHA; that commit changes only `docs/evidence/`.

| Repository | Base (merge-base with `origin/main`) | Certified SHA | Pull request |
|---|---|---|---|
| Middleware- | `03bd558e181fe4b337de99611d044e22224878c5` | `8e3a0f1c18b013adca0fe1ce9ba91f9ecb2bf0b2` | https://github.com/appolon1908-hue/Middleware-/pull/278 |
| Kong | `bc166fddba62b79b67bc960ca875b27f50782b97` | `4348e5171f7f4d03986843f4129c2b282791bbc9` | https://github.com/appolon1908-hue/Kong/pull/105 |
| Caddy | `dc6f7e4447d76d611d9b8ce9068b34e87b90d948` | `54edf07bdb0d2feb6a53e373ea448bff87d48a74` | https://github.com/appolon1908-hue/Caddy/pull/174 |
| Keycloak | `7f8a7dfafe708dac01f67589d2ba4058f34f5a4a` | `bd4ca21601bc1079a2f3d1f0814420c7ef264dd8` | https://github.com/appolon1908-hue/Keycloak/pull/118 |
| Odoo | `11c47bc15eb41b581f682217b87581fb0ab8e335`; `origin/main` advanced to `1bad581` (PRs #135, #139) and was merged in `7c9b038` | `5319035c` (merge + strict overrides re-bound to the merged subtrees; every Odoo static validator, the cross-repository campaign-authority tests and the 720-file compile were re-run at this SHA with exit 0) | https://github.com/appolon1908-hue/Odoo/pull/142 |
| N8N | `dd100d8ebd17f7eb90871522e74863dedbccd2e9` | `cf6e0ecdc364d2c1720c2d2d7d9296a39a2e13d6` | https://github.com/appolon1908-hue/N8N/pull/66 |

## Canonical contract

- Authority: `Middleware-/deploy/public-api-route-contract.json`, schema `codestra.middleware.public-api-route-contract.v2`, service `middleware-integration-api`, listener port `8095`, 92 operations (`shared_edge`=80, `private_only`=2, `denied`=10).
- Canonical digest (sha256 over `json.dumps(contract, sort_keys=True, separators=(",", ":"))`): `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5`.
- Vendored copies with identical bytes and identical digest, each pinned by a `.sha256` file and checked by that repository's own validator:
  - Caddy `config/middleware-public-api-route-contract.v1.json`
  - Kong `config/middleware-public-api-route-contract.v1.json`
  - Keycloak `config/desired-state/edge-integration-certification/middleware-public-api-route-contract.v2.json`
  - Odoo `contracts/middleware-public-api-route-contract.v2.json`
  - N8N `contracts/middleware-public-api-route-contract.v2.json`
- Prohibited surfaces are `denied` in the contract, refused by Kong (404, no upstream), listed in the Caddy Kong-prefix rule so they never reach the legacy upstream, and never mounted by the deployed Middleware entrypoint (`scripts/audit_release_endpoints.py` fails closed): `/api/v1/integration/campaign-actions`, `/api/v1/integrations/odoo/campaign-actions`, `/api/v1/integrations/odoo/campaign-commands[/{command_id}]`, `/api/v1/odoo/campaign-actions`, and every `/v1/integrations/n8n/*` command alias. No canonical route references port 8080.

## Route / client / audience / scope / upstream matrix

Generated from the canonical contract. Every `shared_edge` upstream is `middleware-integration-api:8095`; every `denied` row has no upstream.

| Class | Calling client | Audience | Auth | Routes |
|---|---|---|---|---|
| shared_edge | authorized-provisioning-client | middleware-api | service-or-user-jwt | 34 |
| shared_edge | platform-operator | middleware-api | service-or-user-jwt | 13 |
| shared_edge | production-operator | middleware-api | service-or-user-jwt | 8 |
| shared_edge | job_family_client_only | middleware-api | automation-service-jwt | 6 |
| shared_edge | odoo-integration | middleware-api | odoo-service-jwt | 3 (`GET /api/v1/integrations/odoo/campaigns/{campaign_id}` `odoo.campaigns.read`; `GET …/desired-state` `odoo.campaigns.read`; `POST /api/v1/odoo/events` `odoo.events.publish`) |
| shared_edge | n8n-automation | middleware-api | n8n-service-jwt | 3 (`POST /api/v1/integrations/n8n/results` `n8n.results.submit`; `GET /api/v1/integrations/n8n/results/{event_id}` `n8n.results.read`; `POST /api/v1/automation/policy-check` `n8n.policy.check`) |
| shared_edge | n8n-operations-automation | middleware-api | automation-service-jwt | 2 |
| shared_edge | all_declared_clients | middleware-api | automation-service-jwt | 2 |
| shared_edge | observability-collector | middleware-api | service-or-user-jwt | 2 |
| shared_edge | callback-ui | codestra-callback-api | callback-jwt | 2 |
| shared_edge | github-app | middleware-api | service-or-user-jwt | 1 |
| private_only | middleware-worker | codestra-odoo | middleware-service-jwt | `POST /api/v1/integration/automation-results` (`odoo.integration.automation_results.write`), `POST /api/v1/integration/campaigns/actual-state` (`odoo.campaign.actual_state.write`) → `odoo:8069` |
| denied | none | — | deny | 10 retired aliases (above) |

Keycloak desired state (`config/desired-state/edge-integration-certification/`) grants `middleware-api`, `middleware-worker`, `n8n-automation` and `odoo-integration` exactly the audiences and scopes above; Middleware never holds `odoo.campaign.control.write`; `telephony:command` is not used anywhere (Odoo now requests `telephony.commands.write`); no integration scope is a realm-wide default; TEST_SYN staging test clients carry exactly one scope each.

## Static certification — commands and exit codes

Run from clean worktrees at the certified SHAs on the certifying host (Windows 10, Python 3.12.10, pytest 9.1.1, decK v1.55.0, Caddy v2.10.0 release binary with a verified SHA-512 checksum, Middleware tests under a venv built from the hash-locked `requirements-test.txt` — FastAPI 0.139.2 / Starlette 1.3.1). Exit code 0 is a pass. Non-zero rows are explained under "Environment-only failures".

| Repo | Check | Exit | Result |
|---|---|---|---|
| Middleware- | `python -m pytest -q tests` | 1 | 84 failed, 3065 passed, 252 skipped — **0 failures that do not also fail on `origin/main`** (baseline on this host: 99 failed); every remaining failure is Windows-only (below) |
| Middleware- | `python -m pytest -q tests -k "public_api_route_contract or integration_api_entrypoint_routes or integration_runtime_wiring or certify_edge_integration or runtime_compose or campaign_control_grants or odoo_campaign_adapter_routes or release_endpoint_audit or runtime_migration or runtime_sql_schema"` | 0 | 234 passed, 34 skipped, 0 xfail |
| Middleware- | `python -m pytest -q tests/test_generated_api_parity.py` | 0 | 11 passed |
| Middleware- | `python -m scripts.audit_release_endpoints` | 0 | `ROUTE_CONTRACT_SHA256=7580123d…`; 80 shared-edge routes PASS; no denied route mounted |
| Middleware- | `python scripts/validate_staging_intake_observability_contract.py` | 0 | `MIDDLEWARE_STAGING_INTAKE_OBSERVABILITY_CONTRACT=PASS` (registry resolved statically) |
| Middleware- | `python scripts/validate_automation_contract_conformance.py` | 0 | `AUTOMATION_CONFORMANCE=PASS expected=13 strict_xfail=0` |
| Middleware- | `python scripts/validate_automation_operation_policy.py` | 0 | `AUTOMATION_OPERATION_POLICY=PASS` |
| Middleware- | `python scripts/validate_n8n_flow.py` | 0 | `N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED` |
| Middleware- | `python scripts/validate_identity_webhook_contracts.py` | 0 | `MIDDLEWARE_INTEGRATION_CONTRACTS=PASS` |
| Middleware- | `python scripts/validate_repository_governance.py` | 0 | `REPOSITORY_GOVERNANCE=PASS skip_files=38` |
| Middleware- | secret grep (`make security` pattern, tracked + untracked, all six repos) | 0 | 0 findings |
| Middleware- | `python -m ruff check app migrations tests` | 1 | 2 findings, both pre-existing on `origin/main` (`app/api/v1/activity.py:189` F842, `app/observability_projection.py:15` F401); 0 in changed files |
| Middleware- | `python -m ruff format --check app migrations tests` | 1 | pre-existing unformatted files on `origin/main`; every file this branch touched that was formatted on `main` is still formatted |
| Middleware- | `python -m mypy app` | 1 | 10 Windows-stub errors (`os.geteuid`, `O_NOFOLLOW`, …) vs 19 on `origin/main` on this host; Linux CI runs `make typecheck` |
| Kong | `python -m pytest -q tests` | 1 | 22 failed, 576 passed, 4 errors — all Windows-only (below); `origin/main` cannot even collect `test_kong_change_authority.py` on Windows (`fcntl`) |
| Kong | `deck file validate config/kong-middleware-routes.production.yml` | 0 | valid |
| Kong | `deck file validate config/staging/kong-middleware-routes.staging.yml` | 0 | valid |
| Kong | `python scripts/validate_community_n8n_egress.py` | 0 | `CURRENT_N8N_RUNTIME_AUTHORITY=RETIRED_DENY_ONLY`, `CANONICAL_MIDDLEWARE_UPSTREAM=middleware-integration-api:8095`, `COMMUNITY_HTTPS_PROMOTION=NOT_AUTHORIZED` |
| Kong | `python scripts/validate_middleware_edge_contract.py` | 0 | every contract route/scope reported |
| Kong | `python tools/generate_migration_manifests.py --check` | 0 | `MIGRATION_MANIFEST_CHECK=PASS FILES=219` |
| Kong | `! grep -n 8080 <canonical route files and both manifests>` | 0 | no 8080 reference |
| Caddy | `python -m pytest -q tests` (with `CADDY_BIN`) | 0 | 9 passed (24 passed including `scripts/test_caddy_kong_contract.py`) |
| Caddy | `python scripts/test_caddy_kong_contract.py` | 0 | 15 tests OK |
| Caddy | `python scripts/validate_repository.py` | 0 | `HSTS_SCOPE=EVERY_PUBLIC_SITE` |
| Caddy | `python scripts/validate_community_n8n.py` | 0 | `COMMUNITY_N8N_SECURITY=PASS` |
| Caddy | `python scripts/test_observability_exposure.py` / `validate_observability_exposure.py --check` | 0 | 18 tests OK; `CADDY_LIVE_RELOAD_AUTHORIZED=NO` |
| Caddy | `caddy validate`, `caddy adapt --validate`, `caddy fmt` (both sites), `scripts/caddy_adapted_routes.py <adapted.json>` | 0 | `Valid configuration`; `CADDY_ADAPTED_ROUTE_MATRIX=PASS CANONICAL=11 FAIL_CLOSED=28 LEGACY_PROBES=1`; format clean |
| Caddy | `git diff --check` | 0 | clean |
| Keycloak | `python scripts/edge_certification_desired_state.py --check --require-cross-check --middleware-repo <Middleware branch>` | 0 | `KEYCLOAK_EDGE_CONTRACT_SHA256=7580123d…`, `EDGE_CONTRACT_CROSS_CHECK=PASS`, `KEYCLOAK_LIVE_APPLY=PROHIBITED` |
| Keycloak | `python -m pytest -q tests` | 1 | 5 failed, 186 passed — all Windows-only (symlink privilege, POSIX 0600/0700 modes, git in temp) |
| Keycloak | `validate-service-integrations.py`, `validate-kong-oidc-contract.py`, `validate-n8n-flow.py`, `validate-governance.sh`, `unittest scripts/release` | 0 | all PASS |
| Odoo | `python -I scripts/validate_odoo_shared_contract.py` | 0 | `ODOO_SHARED_CONTRACT_PARITY=PASS` (28 operations) |
| Odoo | `python -I scripts/generate_odoo_endpoint_catalog.py --check` | 0 | `ODOO_ENDPOINT_CATALOG=PASS` |
| Odoo | campaign authority matrix, integration boundary, API contracts, manifests, migration contracts, calling-contract pin, asset integrity, control-plane validators | 0 | all PASS; `CANONICAL_ADDON_BASELINE=PASS`; overrides re-bound to the exact committed subtrees |
| Odoo | `python -m pytest -q tests/test_cross_repository_campaign_authority.py` | 0 | 4 passed |
| Odoo | compile every `.py` under `custom-addons`, `scripts`, `tests/security` | 0 | 716 files, 0 syntax errors |
| N8N | `validate_repository.py`, `validate_workflows.py workflows`, `validate_workflow_completeness.py`, `scan_secrets.py .`, `validate_platform_control_plane.py`, `validate_v2_client_cells.py`, `validate_ruleset_contract.py`, `validate_catalog_reconciliation.py` | 0 | all PASS; `N8N_V2_RUNTIME_APPLY_AUTHORIZED=NO`; `SECRET_SCAN=PASS` |
| N8N | `python -m pytest -q tests/test_cross_repository_contract.py tests/test_middleware_surface.py tests/test_shared_templates.py tests/test_v2_client_cells.py tests/test_integration_contracts.py tests/test_workflow_completeness.py` | 0 | 48 passed, 65 xfailed (the pre-existing `test_workflow_completeness` design-catalog markers, unchanged from `main`) |

### Environment-only failures (all reproduce identically or worse on `origin/main` on this host)

- Windows cannot create symlinks without elevation (`WinError 1314`), has no POSIX file modes/`umask`, no `fcntl`, no `os.getuid/geteuid`, no `O_NOFOLLOW`, cannot execute `#!/bin/bash` scripts directly (`WinError 193`), and limits environment values to 32 767 characters. Every remaining Middleware (81), Kong (26) and Keycloak (5) failure is one of these; the Middleware failure set is a strict subset of the `origin/main` failure set on the same host (99).
- Line endings: the host checks out with `core.autocrlf=true`. Byte-hash pins computed on such a checkout are wrong for CI; two such pins created before this session were corrected (Middleware migration history digest, Odoo shared-contract `file_sha256`) and every committed blob was verified CR-free.

## Local integration runtime (Phase 10)

Not run. Blocker and exact reproduction:

```text
$ docker info
request returned 500 Internal Server Error for API route and version
http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/v1.55/info
$ wsl -l -v
(prints installer usage: no WSL distribution is installed)
```

Docker Desktop's Linux engine needs WSL 2 (or Hyper-V) and elevation to install; neither was performed. Consequences: no isolated Compose stack, no disposable PostgreSQL/Redis for `tests/integration` (`RUNTIME_INTEGRATION_TESTS=1 RUNTIME_INTEGRATION_ALLOW_DISPOSABLE=YES DATABASE_URL=… REDIS_URL=… pytest tests/integration` → 111 skipped here), no Odoo 19 install/upgrade/ORM run, and the Caddy pinned validator image (`docker.io/library/caddy@sha256:ae4458…`) could not be pulled — the identical Caddy v2.10.0 release binary was used instead and CI still runs the image.

## Staging certification (Phase 11)

Not run: no staging DNS, secret-file references, seeded data, logs or restart authority were available. `scripts/certify_edge_integration.py` (fail-closed, TEST_SYN-only) and the Keycloak `certify_edge_identity_staging.py` / `reconcile_edge_certification_staging.py` are committed with their tests; every precondition failure is reported as a failed certification, never inferred as a pass. No Caddy, Kong or Middleware process was reloaded or restarted; no production traffic was sent.

## Correlation, restart and legacy-fallback evidence

Static only. The Caddy adapted-config matrix proves every canonical probe reaches Kong through an exact method+path rule and every wrong-method/retired probe never resolves to the legacy upstream; Kong denied routes terminate 404 with no upstream; the Middleware audit proves no denied route is mounted on the deployed entrypoint. Live correlation-ID propagation across Caddy/Kong/Middleware/Odoo logs, restart evidence and zero-legacy-traffic counters require the staging run above.

## Production and provider effects

Unchanged and disabled: `runtime_apply_authorized=false` / `runtimeApplyAuthorized=false` in every Kong authority and manifest; `KEYCLOAK_LIVE_APPLY=PROHIBITED`; `CADDY_LIVE_RELOAD_AUTHORIZED=NO`; `N8N_V2_RUNTIME_APPLY_AUTHORIZED=NO`; every n8n workflow inactive and credential-free; Odoo design-outbox cron unloaded and inactive; Middleware `provider_effects_enabled=false` and all live-write switches false. No email, SMS, dial, workflow activation, provider write or Odoo production write was performed.

## Decisions recorded (R6)

- **R6-2026-09-16-canonical-middleware-upstream (Kong).** Kong PR #30 bound the `/v1/integrations/n8n/*` route authority to the runtime observed at the time (`appolon-middleware-integration-api:8080`) and denied the generic alias. The canonical contract names `middleware-integration-api:8095` as the only shared-edge upstream and the aliases as `denied`. The contract wins: the route authority is `RETIRED_DENY_ONLY`, the HTTPS egress proposal is `SUPERSEDED_NOT_APPLIED`, the legacy host is recorded as `retired_legacy_runtime`, and the topology collector must re-prove the canonical alias before any runtime reconciliation, which remains unauthorized.
- **Deprecated Middleware aliases.** The `/v1/integrations/n8n/*` command aliases carry a published sunset (`Wed, 30 Jun 2027`). They are edge-denied and never mounted on the deployed entrypoint, and remain only on the in-process monolith factory, marked deprecated, until that sunset. Removing them early would have silently broken the deprecation contract.
- **Routing-rule work excluded.** The Odoo main checkout holds unrelated, incomplete routing-rule work (model file not present in the branch); its references were kept out of this branch so the addon installs, and the main checkout was left untouched.

## Remaining blockers

| Blocker | Reproduction | Needed |
|---|---|---|
| GitHub Actions cannot start any job for the repository owner (re-checked after the Odoo merge push at 2026-09-16T18:11Z: still locked; completed runs cannot be retried) | `gh run list -R appolon1908-hue/<repo> --branch codex/cross-repo-authority-20260916` shows `startup_failure`; the check-run annotation reads "The job was not started because your account is locked due to a billing issue." (runs on other branches succeeded until 2026-09-16T02:00Z) | Resolve the account billing lock, then re-run the workflows on all six pull requests (`gh run rerun <id>` or close/reopen) so the exact-head and merge-result validations produce the Linux CI evidence this gate cannot substitute for |
| Local integration runtime | `docker info` → HTTP 500; `wsl -l -v` → no distribution | Install WSL 2 / enable the Docker Linux engine with elevation, then `docker compose -f deploy/compose.runtime.yaml …` with namespaced volumes and non-production ports |
| Middleware disposable-DB integration suite | `RUNTIME_INTEGRATION_TESTS=1 RUNTIME_INTEGRATION_ALLOW_DISPOSABLE=YES DATABASE_URL=postgresql://… REDIS_URL=redis://… python -m pytest -q tests/integration` | the runtime above |
| Odoo install/upgrade/ORM tests | Odoo 19 + PostgreSQL container: `odoo -i call_center_campaign,codestra_campaign_control_plane --test-enable --stop-after-init` | the runtime above |
| Caddy pinned-image validation | `bash scripts/validate-ci.sh` (needs Docker) | CI (`validate-source` / `validate-merge-result`) runs it on every push |
| Staging certification | `CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN … python scripts/certify_edge_integration.py`; Keycloak `make certify-edge-identity` / `reconcile-edge-certification` | staging DNS, secret-file references, seeded TEST_SYN data, log access, restart authority |
