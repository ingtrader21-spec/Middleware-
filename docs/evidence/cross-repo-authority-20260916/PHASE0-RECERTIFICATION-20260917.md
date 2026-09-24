# Phase 0 — core platform integration gate re-certification (2026-09-17)

Re-verification of the six-repository core integration before any further monitoring-stack work, at the branch heads current on 2026-09-17T11:30Z. Canonical command path unchanged: Caddy → Kong → `middleware-integration-api:8095` → approved Odoo/N8N internal APIs; Middleware remains the only cross-system command authority.

## Exact branches and SHAs (branch `codex/cross-repo-authority-20260916`, all worktrees clean)

| Repository | PR | Certified SHA (2026-09-16 gate) | Head now | Drift since certification | Merge-base with `origin/main` |
| --- | --- | --- | --- | --- | --- |
| Middleware- | #278 | `8e3a0f1c18b013adca0fe1ce9ba91f9ecb2bf0b2` | `bd6adaf0bab4191e112676be274abbf910078221` | three commits touching only `docs/evidence/cross-repo-authority-20260916/GATE.md` | `03bd558e` (unchanged) |
| Caddy | #174 | `54edf07bdb0d2feb6a53e373ea448bff87d48a74` | same | none | `dc6f7e44` |
| Kong | #105 | `4348e5171f7f4d03986843f4129c2b282791bbc9` | `bd8ec3cea4714b78ab2b27b5fa3e0e239e9a491b` | **this phase**: `fix(routes): pin the OIDC cache_tokens_salt vault reference on canonical Middleware routes` (see finding K1) | `bc166fdd` |
| Keycloak | #118 | `bd4ca21601bc1079a2f3d1f0814420c7ef264dd8` | `96bdda74dbaa7d7ac6c68ec6baabc5ad42dd234d` | one commit (`fix(identity): reconcile edge certification metadata with Middleware v2`, 2026-09-17 09:51Z): contract metadata only — declares schema v2, records the superseded v1 digest `af984cba…`, adds the `/api/v1/integrations/odoo/campaign-commands/{command_id}` denied route, re-renders the desired-state plan; digest unchanged; plan `.sha256` verified equal to the index blob (`2dc6518d…`) | `7f8a7dfa` |
| Odoo | #142 | `53190351ec745d88e3c051aa0d3915a431cc95d2` (the 2026-09-16 gate printed it as `5319035c`, a truncation typo) | same | none | `1bad5819` |
| N8N | #66 | `cf6e0ecdc364d2c1720c2d2d7d9296a39a2e13d6` | same | none | `dd100d8e` |

All six PRs are OPEN and MERGEABLE. GitHub Actions is still account-locked (`startup_failure` on Kong `bd8ec3ce` at 11:26Z; annotation "The job was not started because your account is locked due to a billing issue."). Nothing merged; no bypass.

## Canonical contract — identical in every consumer

`schema = codestra.middleware.public-api-route-contract.v2`, `service = middleware-integration-api`, `listener_port = 8095`, `environment = TEST_SYN`, `live_apply_authorized = false`, `provider_effects_enabled = false`; 92 routes: 80 `shared_edge` (all upstream `middleware-integration-api:8095`), 2 `private_only` (`odoo:8069`), 10 `denied` (no upstream); audiences: `middleware-api` ×88, `codestra-odoo` ×2 (private worker), `codestra-callback-api` ×2; the string `8080` does not occur.

| Repository | Vendored path | Blob sha256 (raw bytes) | Canonical digest | Pin file |
| --- | --- | --- | --- | --- |
| Middleware- | `deploy/public-api-route-contract.json` | `3567567f0d57…` | `7580123dead9…` | `deploy/public-api-route-contract.sha256` = digest |
| Caddy | `config/middleware-public-api-route-contract.v1.json` | identical | identical | `config/middleware-public-api-route-contract.sha256` = digest |
| Kong | `config/middleware-public-api-route-contract.v1.json` | identical | identical | `config/middleware-public-api-route-contract.sha256` = digest; also pinned in `kong-canonical-middleware-routes.json`, `kong-middleware-authority.v2.json` |
| Keycloak | `config/desired-state/edge-integration-certification/middleware-public-api-route-contract.v2.json` | identical | identical | `….sha256` = digest; `contract.json`, `canonical-service-authority.v2.json`, rendered plan |
| Odoo | `contracts/middleware-public-api-route-contract.v2.json` | identical | identical | `contracts/middleware-public-api-route-contract.sha256` = digest |
| N8N | `contracts/middleware-public-api-route-contract.v2.json` | identical | identical | `contracts/middleware-public-api-route-contract.sha256` = digest |

`BYTE_IDENTICAL_ALL_SIX = True`; canonical digest `7580123dead97ea342c704a57a3c8eed9f5dce69aab247d4b693db96bc7334d5` in all six (computed from `HEAD:` blobs, not working-tree bytes).

## Component checks (exit 0 unless noted)

### 1. Caddy `54edf07b`
- canonical routes go to Kong / wrong methods never reach fallback / retired routes never hit legacy: `caddy v2.10.0 validate` → `Valid configuration`; `caddy adapt --validate` + `scripts/caddy_adapted_routes.py --kong-upstream 127.0.0.1:8000 --legacy-upstream 127.0.0.1:18101` → `CADDY_ADAPTED_ROUTE_MATRIX=PASS CANONICAL=11 FAIL_CLOSED=28 LEGACY_PROBES=1`; `scripts/test_caddy_kong_contract.py` 15 OK; `pytest tests` 9 passed.
- correlation ID preserved: the adapted config deletes request headers only on `graf/supe/bao.codestra.media` (auth-proxy headers) and `n8n-editor` (`Authorization` + oauth2-proxy headers); `X-Correlation-ID` is never deleted or rewritten on any host, so `api.codestra.co` passes it to Kong unchanged.
- TLS config valid: one `:443` server hosting `api.codestra.co`, `automation.codestra.co`, `bao/graf/supe.codestra.media`, `n8n-editor`; Caddy-managed ACME certificates with HTTP→HTTPS redirect; `HSTS_SCOPE=EVERY_PUBLIC_SITE`; `caddy fmt` clean on all four sites; `git diff --check` clean; `COMMUNITY_N8N_SECURITY=PASS`; `CADDY_LIVE_RELOAD_AUTHORIZED=NO`.

### 2. Kong `bd8ec3ce` (after finding K1)
- canonical route/method mapping: `scripts/generate_middleware_routes.py` regenerates 80 shared + 10 denied routes from the pinned contract (`generated 80 shared routes and 10 denied routes (7580123d…)`); `validate_middleware_edge_contract.py` → `MIDDLEWARE_EDGE_CONTRACT=PASS ROUTES=4 STAGING_IDENTITIES=5`.
- `middleware-api` audience, required azp/scope validation: every route carries `openid-connect` with `audience=[middleware-api]` (or the contract's audience), `scopes_required=[<scope>]`, `consumer_claim=[azp]`, plus the post-function azp/tenant check (`tests/test_kong_middleware_contract_v2.py`, `tests/test_kong_route_authority_hardening.py`, `tests/test_kong_canonical_route_contract.py`, `tests/test_kong_campaign_edge_certification.py` → 71 passed).
- upstream `middleware-integration-api:8095`: `CANONICAL_MIDDLEWARE_UPSTREAM=middleware-integration-api:8095`, `CURRENT_N8N_RUNTIME_AUTHORITY=RETIRED_DENY_ONLY`, `COMMUNITY_HTTPS_PROMOTION=NOT_AUTHORIZED`.
- zero canonical route references 8080: `grep -c 8080` = 0 in both route files and both JSON authorities.
- `deck file validate` (decK **1.66.0**, the CI-pinned version) → valid for `config/kong-middleware-routes.production.yml` and `config/staging/kong-middleware-routes.staging.yml`; `MIGRATION_MANIFEST_CHECK=PASS FILES=219`; full suite 22 failed / 576 passed / 4 errors — the identical Windows-only set as the 2026-09-16 gate.

**Finding K1 (fixed in `bd8ec3ce`).** The 2026-09-16 gate validated the generated route files with decK v1.55.0. CI pins decK 1.66.0, which refuses to build state for an `openid-connect` plugin without an explicit `cache_tokens_salt` (`Error: building state: openid-connect plugin requires explicit non-empty config values for cache_tokens_salt …`), and CI never ran `deck file validate` on these two files. The generator now emits `cache_tokens_salt: "{vault://env/kong-oidc-cache-tokens-salt}"` — the same vault reference the CI-validated calling and moneybee renderers already use, never a literal — both files are added to the `kong-config` workflow's decK step, and the migration manifests are re-pinned over LF bytes (verified: manifest sha256 of `.github/workflows/kong-config.yml` = sha256 of its LF content). Route mapping, audience, azp/scope, upstream and contract digest are unchanged.

### 3. Keycloak `96bdda74`
- `middleware-api` audience: `contract.json` `audience = canonicalMiddlewareAudience = middleware-api`; `validate-kong-oidc-contract.py` → `MIDDLEWARE_AUDIENCE=middleware-api`.
- canonical service clients / exact scopes (`canonical-service-authority.v2.json`, `fullScopeAllowed=false`, `defaultClientScopes=[]`, `optionalClientScopes=[]` on the managed client JSON): `middleware-api` → aud `middleware-api`, `telephony.commands.write`; `middleware-worker` → aud `codestra-odoo`, `odoo.campaign.actual_state.write`, `odoo.integration.automation_results.write`; `n8n-automation` → aud `middleware-api`, the `automation.*` v2 scopes + `n8n.results.submit/read`, `n8n.policy.check`; `odoo-integration` → aud `middleware-api`, `odoo.campaigns.read`, `odoo.events.publish`. TEST_SYN certification identities carry exactly one scope each (`test-syn-wrong-audience` has a foreign audience by design).
- `EDGE_CONTRACT_CROSS_CHECK=PASS` (`edge_certification_desired_state.py --check --require-cross-check --middleware-repo <Middleware #278 worktree>`; `KEYCLOAK_EDGE_CONTRACT_SHA256=7580123d…`, `KEYCLOAK_LIVE_APPLY=PROHIBITED`).
- no realm-wide integration scopes: `config/realms/codestra.json` `defaultDefaultClientScopes=[]`, `defaultOptionalClientScopes=[]`; `monitoring-readonly` optional scopes exactly `health.read`, `metrics.read`.
- `validate-service-integrations.py` (`SERVICE_INTEGRATION_VALIDATION=PASS`, `ADMINISTRATIVE_BOUNDARIES=PASS`), `validate-n8n-flow.py` (`N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED`); `pytest tests` 5 failed / 186 passed — the same Windows-only five (symlink privilege, 0600 modes, file-mode change).

### 4. Middleware `bd6adaf0`
- integration_api exposes the canonical registry: `python -m scripts.audit_release_endpoints` → `ROUTE_CONTRACT_SHA256=7580123d…`, 80 shared-edge routes `PASS`, no denied route mounted, the only non-PASS rows are the two enumerated `EDGE_EXPOSURE_UNDECIDED` private routes (`/api/v1/campaign-designs/approvals|preview`, not in the contract, not edge-routed).
- command / idempotency / reconciliation authority and 401/403/404/409 semantics: contract, entrypoint, wiring, certification, grants, adapter, audit and schema test set → 237 passed, 34 skipped; `tests/test_generated_api_parity.py` + `tests/test_staging_acceptance.py` 22 passed; semantics selection (`idempoten*|409|unauthorized|forbidden|not_found`) 78 passed, 2 Windows-only failures (`/`-rooted controller workspace, openssl VICIdial); `AUTOMATION_CONFORMANCE=PASS expected=13`, `AUTOMATION_OPERATION_POLICY=PASS`, `MIDDLEWARE_INTEGRATION_CONTRACTS=PASS`, `REPOSITORY_GOVERNANCE=PASS`, `MIDDLEWARE_STAGING_INTAKE_OBSERVABILITY_CONTRACT=PASS`, `N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED`.
- provider kill switches remain closed: `enable_external_delivery=False`, `live_writes_enabled=False`, `odoo_write=False`, `external_dial_enabled=False` (settings defaults); the runtime-safety read-back schema and `test_staging_acceptance` require every effect and umbrella control false, `production_dialing=DISABLED`, `production_activation_configured=false`.
- TEST_SYN only for certification: `app/core/policy.py::enforce_test_campaign` (`only TEST_SYN is permitted`); `automation_allowed_campaigns="TEST_SYN"`, `webphone_staging_campaign="TEST_SYN"`, `test_syn_odoo_tenant_id="TEST_SYN_TENANT"`.

### 5. Odoo `53190351`
- business/campaign authority: `validate_campaign_authority_matrix.py` PASS (10 roles); `tests/test_cross_repository_campaign_authority.py` 4 passed; `CANONICAL_ADDON_BASELINE=PASS`; `PLATFORM_CONTROL_PLANE=PASS`; `OBSERVABILITY_CONTROL_PLANE=PASS`.
- commands enter Middleware first / no direct provider bypass: `validate_integration_boundary.py` → "only Codestra Middleware may write through approved service APIs or the ORM bridge"; no `smtplib`/`twilio`/`telnyx`/raw `requests.post` client in `call_center_campaign` or `codestra_campaign_control_plane`.
- result/read-back paths: `ODOO_SHARED_CONTRACT_PARITY=PASS` (28 operations), `ODOO_ENDPOINT_CATALOG=PASS`, `CANONICAL_API_SOURCE_INVENTORY=PASS` (21 endpoints), `CALLING_CONTRACT_PIN=PASS`, manifests 81 modules PASS, `MISSION_MIGRATION_SOURCE_GATE=PASS` (0 destructive operations), asset integrity PASS; all `.py` under `custom-addons`, `scripts`, `tests/security` compile. `CANONICAL_API_RUNTIME_CERTIFICATION=BLOCKED` and `RESTORE_REHEARSAL_GATE=BLOCKED_RUNTIME_EVIDENCE` are runtime-evidence gates (unchanged; need the Odoo 19 runtime).

### 6. N8N `cf6e0ecd`
- communicates only through Middleware / v2 automation-result APIs: every HTTP node URL in `workflows/` targets `https://middleware.invalid/v2/automation/{commands,approvals,jobs/claim,jobs/reconcile,jobs/{id}/complete|fail}` or `/api/v1/integrations/n8n/results[/{event_id}]`; no `8080`; `PLATFORM_CONTROL_PLANE=PASS`; cross-repository/middleware-surface/v2-cells/integration-contract tests 48 passed, 65 xfailed (pre-existing design-catalog markers).
- no direct Odoo/provider delivery: zero e-mail/SMS/Twilio/Telnyx/SMTP/Odoo nodes; `N8N_DIRECT_PROVIDER_GRANTS=DISALLOWED` (Keycloak + Middleware).
- workflows inactive except approved TEST_SYN certification: 10 workflows, `active: 0`, credential-bound nodes 0; TEST_SYN appears only as `TEST_SYN_TENANT` in the v2 templates; `N8N_V2_RUNTIME_APPLY_AUTHORIZED=NO`; `LIVE_SERVER_MUTATION_CAPABILITY=ABSENT`; `SECRET_SCAN=PASS`; `WORKFLOW_VALIDATION=PASS`.

## Verdict

`PHASE0_CORE_INTEGRATION=ALIGNED` at the heads above: one real gap (K1) found and closed in Kong; one metadata-only upstream commit (Keycloak) verified; Middleware, Caddy, Odoo and N8N unchanged since certification. Exact-SHA CI remains **BLOCKED_PENDING_EXACT_SHA_CI** for all six until the Actions lock lifts; the Kong PR #105 head is now `bd8ec3ce` and must be the SHA CI tests.
