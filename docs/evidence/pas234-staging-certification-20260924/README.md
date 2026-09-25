# PAS-234 — Middleware V3 staging certification packet (2026-09-24)

Linear: https://linear.app/passion-fruit/issue/PAS-234
Parent: PAS-233. Reuses PAS-27, PAS-180, PAS-151 and PAS-102 evidence; it does not repeat them.
Machine-readable form: [`staging-certification-packet.v1.json`](staging-certification-packet.v1.json),
bound to repository truth by `tests/test_pas234_staging_certification.py`.

```text
GATE_A=COMPLETE              # inventory, authority map, contracts, test/rollback/evidence freeze
GATE_B=NO_GO                 # blockers B-01..B-08 below
STAGING_CERTIFIED=NO
ROLLBACK_PROVEN=NO           # R1/R2 plan frozen in PAS-180; not executed
TARGET_IMAGE_DIGEST=PENDING_PAS27
RUNTIME_MUTATION=0
PROVIDER_EFFECTS=0
PRODUCTION_GO=NO
```

No deployment, server command, registry push, migration or provider call was made to produce this packet.
Source reviewed: protected main `0606b0db9ff59802f8da3824d209d2effc13f87d`.

## 1. Certification matrix

| Area | State | Evidence (this lane unless tagged) |
|---|---|---|
| Source authority | **OK** | Single router registry `app/router_registry.py`; one image target `runtime` in `release.yml`; all units run `${MIDDLEWARE_IMAGE}` (one digest, no mixed images). |
| Runtime authority (profile) | **BLOCKED — B-03, B-04** | Profile lock is fail-closed (`app/core/config.py:1449-1558`), but it cannot boot the Server 1 topology (§2). |
| API routes / contracts | **OK** | `generate_api_contracts.py --check` → `OPENAPI_ROUTES=331`; `generate_postman.py --check` → digest `17816985…eba11`; `generate_route_authority_report.py --check` → `MATCH operations=320 DIRECT_EFFECT_BYPASSES=0`; route contract sha256 `9c32daec…512b` matches. Certification routes present; DB `apply`/`sql`/`query` absent. |
| Staging compose / profile | **GAP — B-06** | `deploy/compose.runtime.yaml` is the only runtime compose. It reads the shared `/opt/codestra/env/middleware.env` and sets neither `APP_ENV`, `RUNTIME_PROFILE_ID` nor `DATABASE_URL_FILE`. Those live on the host only, so the staging identity can't be checked from source. |
| DB / TLS | **BLOCKED — B-04, B-05, B-07** | Server side ready: verify-full, `clientname=CN`, schema 0067 (`PAS-180`). App side: `database_alternates` and cert paths exist only in PR #304; the schema-digest repair is PR #309. |
| Effects-off | **OK (frozen)** | Every compose `*_ENABLED` is `false` except the recorded exceptions (§3); the env template has dispatch/NATS/Temporal disabled and `PRODUCTION_DIALING=DISABLED`; `validate_domain` rejects effect enablement in staging (`config.py:1229-1259`). |
| Image identity | **BLOCKED — B-01, B-02** | OCI `revision`/`source` labels, `APP_SOURCE_SHA`, and `USER 65532:65532` exist (`Dockerfile.runtime:24-49`); `GET /version` reports `source_sha`/`image_digest`/`schema_head`; staging config requires a 40-char SHA and a `sha256:` digest (`config.py:1272-1282`). No signed digest exists. |
| Rollback / readback | **PLAN FROZEN, NOT PROVEN** | R1 (stop new units; DB stays 0067+TLS) and R2 (owner-approved restore of the 0058 snapshot) per PAS-180 §4. Read-only readback: `scripts/migrate_runtime.py --verify-only`, `scripts/verify_container_image.sh`, `scripts/collect_staging_migration_evidence.sh`, PAS-102 Postman DB collection. The deploy controller is production-only (§4). |
| Observability | **OK (source)** | `validate_staging_intake_observability_contract.py` → `PASS`; `/healthz`, `/readyz`, `/metrics` and `/v1/runtime/safety` exist; compose healthcheck probes `/healthz` and `/readyz` on 8095. Live Alloy → Prometheus/Loki/Tempo readback is Gate B. |

## 2. New finding in this lane — B-03 locked-profile boot defect

`app/core/config.py:2280-2286` builds the module-level `settings` and then rewrites
`DATABASE_URL` from `postgresql://` to `postgresql+asyncpg://`. `run_api` and `run_worker`
call `validate_runtime` (`app/entrypoints/runtime.py:84-107,231-233`), which validates
**that module object**. `_validate_database_profile` then requires `scheme == "postgresql"`
exactly. Result: with `APP_ENV=staging` (or any locked profile) every API/worker process
fails closed with `DATABASE_URL does not match the locked runtime profile`, even for a
profile-exact DSN.

Reproduced locally (no network):

| Probe | Result |
|---|---|
| staging profile-exact DSN, module `settings` (rewritten scheme) | `ConfigurationError: DATABASE_URL does not match the locked runtime profile` |
| same DSN with `postgresql://` restored | `PASS` |
| PR #304 head `4e524fc`, Server 1 alternate DSN (`middleware_api@postgres/middleware_staging`, verify-full + cert paths) | same rejection; `PASS` with `postgresql://` restored |

Existing tests miss it because they construct `Settings.from_env()`/`.replace()` rather
than the module object. `tests/test_pas234_staging_certification.py::test_module_settings_accept_a_profile_exact_staging_dsn`
pins it as `xfail(strict=True)`: the suite turns red when the defect is fixed, which forces
the marker to be removed. The fix belongs with the DB/TLS authority (PR #304 lane), for
example by comparing the driver-normalised scheme in `_validate_database_profile`. It is
not changed here.

PAS-151's 2026-09-21 local smoke of a `0606b0d` image reached `/health` 200. That run did
not record `APP_ENV`; under `APP_ENV=staging` the defect above prevents startup.

## 3. Effects-off exceptions (frozen by test)

Across the 21 compose services, the only truthy values besides the safety-positive
`HEALTH_REQUIRE_DATABASE` and `VICIDIAL_ODOO_SYNTHETIC_ONLY` are:

| Service | Value | Assessment |
|---|---|---|
| `middleware-integration-api` | `N8N_RUNTIME_ENABLED=true` | Allowed in the PAS-13 units. It only lets `POST /api/v1/n8n-runtime/dispatch` store PENDING rows (`app/api/v1/n8n_runtime.py`). Outbound n8n delivery is gated by the four broad-event flags, which are all `false` (`app/adapters/n8n/transport.py:131`). |
| `middleware-n8n-runtime-worker` | `N8N_RUNTIME_ENABLED=true` | **Must stay stopped in staging certification.** It POSTs signed envelopes to `http://webhook:5678` for PENDING rows whose workflow-registry entry is enabled and in tenant scope. The only other gates are `n8n_runtime_enabled` and a staging host allowlist; `SEND_EVENTS`/`N8N_DELIVERY_ENABLED` are not consulted (`app/workers/n8n_runtime.py:127-199`). |
| `middleware-social-n8n-delivery-worker` | `N8N_RUNTIME_ENABLED=true` | Out of scope. `SOCIAL_N8N_DELIVERY_WORKER_ENABLED=false` makes it exit at start, so it would crash-loop, but it produces no effect. |
| `middleware-odoo-result-worker`, `middleware-odoo-campaign-saga-worker` | `ENVIRONMENT=production` | Out of scope. Production label inside the shared compose. |

Any new truthy flag, or a removal from this list, fails `test_compose_effect_exceptions_are_frozen`
until this packet is updated.

## 4. Blockers (exact)

| ID | Blocker | Owner | Evidence |
|---|---|---|---|
| B-01 | Hosted Actions not executing (billing lock). Release runs `35602170321`/`35613442378` and PR checks on #304/#309/#326 fail in seconds with 0 steps. At 2026-09-25T00:35Z the newest main-push runs (`d166bcb8`) were queued with no conclusion. | PAS-190 | `gh run list`, PAS-180 F-12 |
| B-02 | No signed RC digest for `ghcr.io/ingtrader21-spec/codestra-middleware`. The last successful `release.yml` run was `34536988755` (2026-09-10). | PAS-27 | PAS-27 `00-summary.md`, `05`, `06` |
| B-03 | Locked-profile boot defect (§2), present on main and on the #304 head. | PAS-79/80 (#304 lane) | this packet, xfail ratchet |
| B-04 | Staging profile on main admits only `middleware_staging@postgresql.middleware-staging.svc.cluster.local/codestra_staging` with no cert paths. Server 1 is `postgres/middleware_staging` with per-role users and cert paths, and `database_alternates` exists only in unmerged #304. #304's head also stacks four unrelated lanes. | PAS-79/80 | PAS-180 F-02/F-15/F-16 |
| B-05 | PR #309 (0067 CHECK-constraint reconciler) is not accepted. It is BLOCKED and CI never ran. | PAS-151 | PR #309 body |
| B-06 | No staging compose overlay or staging env in Git; the staging identity is host-only. | PAS-13 | PAS-180 F-08, §1 |
| B-07 | Per-role CN-bound client certs are not issued or mounted per unit, and there is no in-app certificate expiry/identity check. | PAS-79 / operator | PAS-180 F-03/F-13 |
| B-08 | The Caddy → Kong → Middleware chain can't be certified: the Kong `openid-connect` plugin is unlicensed and the JWT/JWKS fallback (Kong #116) is unaccepted. | PAS-151 | Linear PAS-151 |

Non-blocking gaps, recorded so they aren't rediscovered:

* **Deploy controller is production-only.** `deploy/production/server/codestra-middleware-deploy` hard-codes `APP_ENV=production` and the production-compose profile. It also still pins receipts `1..10` while main ships `0011` (`:510`, PAS-27 F-07). The staging deploy therefore follows the manual PAS-180 P0–P5 plan.
* **Postman DB staging env port.** It targets `http://127.0.0.1:31883`, not the canonical 8095 (PAS-180 F-17). No tracked source explains 31883.
* **Stale docstring.** `app/api/internal/database.py:4-5` says the router is integration-only, but it is in `CANONICAL_ROUTERS`. Isolation actually comes from the edge allowlist plus scoped tokens.
* **Unread identity vars.** `DEPLOYED_SOURCE_SHA` and `RUNTIME_ARTIFACT_CHECKSUM` are set in compose but read by no code; `/version` is the identity readback.
* **Runtime uid.** Compose runs uid `10001` over image uid `65532`. Per-unit key files must be owned by `10001` (PAS-180 §7).

## 5. Gate B entry criteria

All of the following, in order. Each one is a readback, not an assumption.

1. B-01 cleared: a hosted exact-head run executes with real steps.
2. Accepted DB/TLS authority on main (#304 successor, DB/TLS-only diff) that fixes B-03 and B-04. When B-03 is fixed, drop the xfail marker.
3. #309 accepted; staging reconciler run and `migrate_runtime.py --verify-only` → `RUNTIME_SCHEMA_VERIFIED=PASS`.
4. Signed RC from that main (B-02). Verify cosign identity, SBOM, SLSA subject, OCI revision and a single Alembic head, then record the digest in the JSON packet.
5. Staging overlay and env reviewed (B-06); per-role certs mounted (B-07).
6. Execute PAS-180 P0–P5 with the four units in `staging_units` only; `middleware-n8n-runtime-worker` stays stopped.
7. Readback: `/readyz` 200, `/version` (`source_sha`, `image_digest`), `/v1/runtime/safety` all false, `/internal/v1/database/{readiness,security/tls}`, PAS-102 Postman DB collection against 8095, TEST_SYN.
8. Prove R1 rollback (stop units → prior state) and restart/reconnect, then set `ROLLBACK_PROVEN=YES`.
9. PAS-151 chain run (B-08).

## 6. Local verification (this lane, 2026-09-24, Python 3.14.4, `requirements-test.txt`)

| Command | Result |
|---|---|
| `pytest tests/test_staging_acceptance.py tests/test_runtime.py tests/test_security.py tests/test_certify_test_syn.py` | 73 passed |
| `pytest tests/test_staging_intake_observability_contract_validation.py tests/test_internal_database_api.py tests/test_runtime_compose.py tests/test_public_api_route_contract.py tests/test_generated_api_parity.py tests/test_release_authority.py` | 172 passed (on unmodified main) |
| `pytest tests/test_pas234_staging_certification.py` | 8 passed, 1 xfailed (B-03) |
| `scripts/validate_staging_intake_observability_contract.py` | `MIDDLEWARE_STAGING_INTAKE_OBSERVABILITY_CONTRACT=PASS` |
| `scripts/validate_runtime_profiles.py` | `RUNTIME_ENVIRONMENT_PROFILES=PASS` |
| `scripts/validate_repository_governance.py` | `REPOSITORY_GOVERNANCE=PASS` |
| `alembic heads` | single head `0067_service_catalog_monitoring_state` |
| `scripts/derive_trust_pins.py --check` (main) | `ACTIVE_STALE_BEFORE=0`, `LAUNCHER_PARITY=YES` |

The PAS-27 note that `EXPECTED_PROFILE` drifts no longer reproduces on `0606b0d`: the validator passes.

Trust closure: this change adds tracked files, so the `ingtrader21-spec/Middleware-`
source-closure entry is re-derived with `scripts/derive_trust_pins.py --apply-candidate`
in the same commit (PAS-27 `07`). `APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256` is
already a documented structural exception and does not match on main either (actual
`6c704b97…`, pinned `4bc320b1…`), so the new test file does not change its status.

## 7. Reused evidence

* PAS-27: `docs/evidence/pas27-schema-0067-rc-20260921/` (release lane, GHCR access, known gaps).
* PAS-180: `origin/pas-180/staging-preflight-refresh2-20260924` @ `8d0edd8`, `docs/evidence/staging-preflight-20260924/` (current state, TLS classification, P0–P5 plan, R1/R2 rollback, readback commands). Not merged: PR #326 carries the older `29d3996` head, and the refresh-2 head has no PR.
* PAS-151: PR #309 @ `16afd468` (schema reconciler and rehearsal); Linear PAS-151 (Kong chain, candidate image `sha256:deb0c4fc…`, local only).
* PAS-102: `postman/collections/Middleware-V3-Database-Certification.postman_collection.json`, `postman/environments/Middleware-V3-DB-Staging.postman_environment.json`.
