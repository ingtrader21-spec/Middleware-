# PAS-180 — Middleware staging preflight packet, refresh 2026-09-24 (V3-M1A)

Linear: https://linear.app/passion-fruit/issue/PAS-180
Parent gate: PAS-13 (V3-M1 deploy Middleware V3 to staging). Release gate: PAS-27.
Packet date: 2026-09-24. Supersedes `../staging-preflight-20260921/` for current
state, target, TLS and rollback; that packet stays as the historical 0058/PLAINTEXT
baseline and the source of the legacy image inventory.

This refresh re-baselines the packet after the canonical staging database was
reconciled to 0067 and moved to verify-full TLS. It records the current state,
classifies what is left, and gives a fail-closed execution and rollback plan for
the only remaining forward step: deploying the exact signed image. It authorizes
nothing. Nothing on the server was mutated to produce it.

```text
STAGING_PREFLIGHT_PACKET=PASS
CURRENT_STATE_RECORDED=YES
BACKUP_ROLLBACK_READY=YES          # rollback points fixed; backup timestamp/digest + restore of the 0067 backup re-read at gate P1
TLS_PREREQUISITES_CLASSIFIED=YES
RUNTIME_MUTATION=0
PROVIDER_EFFECTS=0
TARGET_IMAGE_DIGEST=PENDING_PAS27  # no successful signed release run; deploy (P3) is blocked, not this packet
LIVE_READBACK=PENDING_OPERATOR     # values tagged LIVE_READBACK_PENDING, see readback-commands.md
```

## Provenance and limits

| Tag | Meaning |
|---|---|
| `ISSUE@2026-09-24` | authoritative PAS-180 issue packet supplied to this session on 2026-09-24 (operator-recorded Server 1 state) |
| `REPO@8ecf6e9` | this branch's base, protected main `8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692` |
| `MAIN@0606b0d` | current protected main `0606b0db9ff59802f8da3824d209d2effc13f87d` (PR #307, PAS-27 evidence only; no runtime/schema change vs `8ecf6e9`) |
| `PR#304@4e524fc` | open PR #304 head `4e524fc84c10bdf40efbc5b9b37a3e6f1c9b4381` (not merged) |
| `GH@2026-09-24` | read-only `gh` readback taken by this session on 2026-09-24 |
| `PKT@20260921` | carried over from the 2026-09-21 packet (still valid, not re-read) |
| `LIVE_READBACK_PENDING` | must be read on Server 1 before execution; exact command in `readback-commands.md` |

This session did not connect to Server 1. Current-state values come from the
issue packet; the plan re-reads every one at gate P0 and stops on drift.

## 1. Current state (recorded)

### 1.1 Source / release authority

| Key | Value | Provenance |
|---|---|---|
| PROTECTED_MAIN | `0606b0db9ff59802f8da3824d209d2effc13f87d` | `GH@2026-09-24` |
| CANONICAL_ALEMBIC_HEAD | `0067_service_catalog_monitoring_state` (single head; down `0066_reconcile_odoo_campaign_scope`) | `MAIN@0606b0d` |
| CORE_SQL_RECEIPTS / AUTOMATION | `1..11` / `1` | `MAIN@0606b0d` |
| FORWARD_IMAGE_REPOSITORY | `ghcr.io/ingtrader21-spec/codestra-middleware` | `MAIN@0606b0d` |
| SIGNED_RC_STATUS | **NOT PUBLISHED.** Run `35602170321` (`8ecf6e9`) failed at push `permission_denied: read_package`; run `35613442378` (`0606b0d`) never started: *"The job was not started because your account is locked due to a billing issue."* No later release run. | `GH@2026-09-24` |
| TARGET_IMAGE_DIGEST | `PENDING_PAS27` | — |

### 1.2 Canonical staging runtime (Server 1, Compose project `codestra-middleware-staging`)

| Key | Value | Provenance |
|---|---|---|
| CURRENT_STAGING_DB_SCHEMA | `0067_service_catalog_monitoring_state` (0058 → 0067 reconciliation done) | `ISSUE@2026-09-24` |
| CURRENT_STAGING_DB_NAME / CONTAINER | `middleware_staging` / `codestra-middleware-staging-postgres-1` | `PKT@20260921` |
| CURRENT_STAGING_DB_HEALTH | healthy | `ISSUE@2026-09-24` |
| CURRENT_STAGING_DB_TLS | **on**; `hostssl` + `scram-sha-256` + `clientcert=verify-full` + `clientname=CN` for all service roles (§3); non-SSL network connections **rejected** | `ISSUE@2026-09-24` |
| CURRENT_STAGING_REDIS | `codestra-middleware-staging-redis-1`, healthy | `ISSUE@2026-09-24` |
| CURRENT_STAGING_APP_PLANE | **intentionally stopped**: legacy API, scheduler, odoo-result, notification and social workers | `ISSUE@2026-09-24` |
| legacy `callback` / `scraper-odoo-delivery-worker` | not named in the issue; last seen exited (137) on 2026-09-21 → `LIVE_READBACK_PENDING` | `PKT@20260921` |
| CURRENT_STAGING_MIDDLEWARE_IMAGE (last API image) | `codestra/middleware:staging-b29db772`, image ID `sha256:b81c125296effc17a33258212d9a71a3c427a972fa9783ec2c060109d167408f`, source Codestra-SRL `b29db772`, no registry digest | `ISSUE@2026-09-24` + `PKT@20260921` |
| READINESS_ENDPOINT | `http://127.0.0.1:8095/readyz` | `ISSUE@2026-09-24` |
| POSTGRES_IMAGE / VERSION, pg_hba line set, cert fingerprints/expiry | `LIVE_READBACK_PENDING` (§3–§4 of readback sheet) | — |

The full legacy image inventory (five families, full IDs) is unchanged and lives
in `../staging-preflight-20260921/staging-preflight-packet.v1.json`
`current_state.legacy_workloads`.

## 2. Target state

| Key | Value | Provenance |
|---|---|---|
| TARGET_SCHEMA | `0067_service_catalog_monitoring_state` — **equals current**; the deploy applies no Alembic revision. SQL receipts `1..11` / automation `1` are verified, not applied (`--verify-only`), unless readback shows them missing | `MAIN@0606b0d` |
| TARGET_IMAGE_DIGEST | `PENDING_PAS27` (`ghcr.io/ingtrader21-spec/codestra-middleware@sha256:<64 hex>`; OCI `revision == SOURCE_SHA`, user `65532`, `amd64`, cosign identity `release.yml@refs/heads/main`) | `MAIN@0606b0d` |
| TARGET_SOURCE_SHA | protected main at RC build time; must contain an accepted #304 successor (§5) | — |
| TARGET_RUNTIME_PROFILE | `codestra-middleware-staging-v1`, `APP_ENV=staging` | `MAIN@0606b0d` |
| TARGET_DB_DSN (per unit) | `postgresql://<role>:<secret>@postgres:5432/middleware_staging?sslmode=verify-full&sslrootcert=/run/secrets/middleware-staging-db-ca.crt&sslcert=/run/secrets/middleware-staging-db-client.crt&sslkey=/run/secrets/middleware-staging-db-client.key` | `PR#304@4e524fc` |
| TARGET_EFFECT_FLAGS | all `false`; `NATS_DISPATCH_MODE=disabled`; `TEMPORAL_WORKER_MODE=disabled`; `OUTBOX_DISPATCH_ENABLED=false`; `PRODUCTION_DIALING=DISABLED` | `MAIN@0606b0d` (`deploy/compose.runtime.yaml`) |

## 3. TLS prerequisites (classified)

Current class: **verify-full + client certificate, CN-bound** (`clientname=CN`:
the client certificate CN must equal the PostgreSQL role name). Non-SSL network
connections are rejected.

| Item | Requirement | Classification | Provenance |
|---|---|---|---|
| Server TLS | `ssl=on`, server cert/key/CA configured | **READY** | `ISSUE@2026-09-24` |
| Server cert SAN | must contain `DNS:postgres` (DSN host; `verify-full` checks hostname) | `LIVE_READBACK_PENDING` (P0.6) | plan |
| POSTGRES_CA | mounted read-only at `/run/secrets/middleware-staging-db-ca.crt` in every unit, readable by uid `10001` | CA exists (TLS on); per-unit mount **not yet created** (new units) | plan |
| Client certs | **one certificate per role, CN = role**. Because of `clientname=CN`, a shared client cert works for exactly one role; each unit mounts its own cert/key at the single #304 path `/run/secrets/middleware-staging-db-client.{crt,key}`; key `0600` owned by uid `10001` | issuance/presence per role `LIVE_READBACK_PENDING` (P0.6); **F-13** | `ISSUE@2026-09-24` + `PR#304@4e524fc` |
| pg_hba | `hostssl … scram-sha-256 clientcert=verify-full clientname=CN` for `middleware_api`, `middleware_worker`, `middleware_reconciler`, `middleware_scheduler`, `middleware_migration`, `middleware_backup`, `postgres_exporter`; non-SSL rejected | **READY** (exact lines `LIVE_READBACK_PENDING`) | `ISSUE@2026-09-24` |
| Cert expiry / identity check in app | PAS-79 requires it; #304 still has none | **GAP F-03** — operator `openssl x509 -checkend` + CN/SAN check at P0.6 as interim | `PR#304@4e524fc` |
| App-side verify-full DSN parser | #304 (`app/db/connection.py`); not on main. Main's `migrate_runtime.py` passes DSN params through; main's config has no staging `database_alternates` | **BLOCKED on #304** (F-02) | `MAIN@0606b0d` |
| Legacy image under TLS | `b81c1252…` (b29db772) predates the #304 authority; whether it can present a CN-bound client cert is unproven | **UNPROVEN** → rollback class R2 only (§4, F-14) | plan |

Nothing on the TLS side needs a server mutation for the forward deploy other than
installing per-unit client material (P2), which is file-only.

## 4. Backup / restore / rollback points

| Key | Value | Provenance |
|---|---|---|
| LAST_BACKUPS | encrypted all-DB backup: **last run successful**; off-server Middleware backup: **last run successful** | `ISSUE@2026-09-24` |
| BACKUP_TIMESTAMP / BACKUP_DIGEST | not carried in the issue packet → `LIVE_READBACK_PENDING` (`STATUS.txt` / `SHA256SUMS` / `REMOTE-SHA256SUMS`, readback §5). Must be newer than the 0067/TLS change and show `LOCAL_ENCRYPTED_CHECKSUM=PASS`, `OFFSERVER_COPY=PASS`, `REMOTE_CHECKSUM_READBACK=PASS` | gate P1 |
| ISOLATED_RESTORE_RESULT (pre-reconcile) | **PASS** — PR #297 disposable restore of `20260920T212950Z` snapshot, 0058 → 0067 bridge, rows preserved, `PRODUCTION_MUTATIONS=0` | `PKT@20260921` |
| ISOLATED_RESTORE_RESULT (current 0067 backup) | required at P1: decrypt + `pg_restore` into a `--network none` disposable container; expect `alembic_version = 0067_service_catalog_monitoring_state`, receipts `1..11`/`1`, row counts = live | gate P1 |
| ROLLBACK_SCHEMA_REFERENCE | R1: `0067_service_catalog_monitoring_state` (no schema change in the forward step). R2: `0058_odoo_delivery_sources` only by restoring the pre-reconcile snapshot (`/opt/codestra/backups/middleware-db-reconcile/20260920T212950Z/`); no Alembic downgrade across the lineage bridge | `REPO@8ecf6e9` |
| ROLLBACK_IMAGE_REFERENCE | old staging API `codestra/middleware:staging-b29db772` = `sha256:b81c125296effc17a33258212d9a71a3c427a972fa9783ec2c060109d167408f` (+ the other four legacy families by image ID). Present only in the Server 1 Docker cache (F-06) → `docker save` at P1 | `ISSUE@2026-09-24` + `PKT@20260921` |
| ROLLBACK_CONFIG | `pg_hba.conf`, `postgresql.conf`, `/opt/codestra/middleware-staging/compose*.yaml`, new staging overlay — copied + `sha256sum` at P1 | plan |

Rollback classes:

* **R1 (default, forward-step rollback)** — stop/remove the new units; DB stays
  0067 + TLS; app plane returns to its current *intentionally stopped* state.
  No DB or pg_hba change. This is the only rollback the deploy needs.
* **R2 (disaster, owner decision)** — return to the legacy app on `b81c1252…`:
  restore the pre-reconcile 0058 snapshot **and** either prove the legacy image
  presents a CN-bound client cert (F-14) or temporarily re-admit a non-verify-full
  path — the latter is a security regression and needs explicit owner approval.
  Not executed by PAS-13 without that approval.

## 5. PR #304 (DB/TLS authority) — re-review at `4e524fc`

State (`GH@2026-09-24`): OPEN, `mergeStateStatus=BLOCKED`, `REVIEW_REQUIRED`;
8 commits, 25 files, +2373/−77 vs main `0606b0d`. All 29 reported checks
FAILURE in 1–3 s — consistent with the account-level Actions billing lock (F-12),
so they are not evidence of code defects **or** of correctness.

* Head now **stacks unrelated lanes**: merge commits of
  `pas-179/deploy-readiness-repair-evidence-20260921`,
  `docs/edge-digest-chain-convergence-evidence-20260921` (#308),
  PR #310 and `mission/pas-61-api-postman-authority`, on top of the TLS fix
  `82a1ab5 fix(db): validate TLS paths independent of host OS`. The DB/TLS
  authority must be reviewed as its own diff before PAS-13 consumes it (F-15).
* `database_alternates` for `codestra-middleware-staging-v1` still lists only the
  four runtime roles; `middleware_migration`, `middleware_backup`,
  `postgres_exporter` are not in the profile. Correct for runtime units; the
  migration role path must not go through the locked runtime profile (F-16).
* Single client-cert path per unit — compatible with `clientname=CN` only with
  per-unit mounts (F-13).
* Still no certificate expiry / identity check (F-03).
* `redis_alternates` still `redis://redis:6379/0`, plaintext, no username (F-05).

## 6. Least-privilege roles

| Role | Purpose | Expected attributes | State |
|---|---|---|---|
| `middleware_api` | integration API | LOGIN; no SUPERUSER/CREATEDB/CREATEROLE/BYPASSRLS; DML on app schema only | hostssl+CN READY; grants `LIVE_READBACK_PENDING` |
| `middleware_worker` | notification (and later) workers | same | same |
| `middleware_reconciler` | reconciliation worker | same | same |
| `middleware_scheduler` | scheduler | same | same |
| `middleware_migration` | DDL owner for Alembic/SQL receipts; used only by `migrate_runtime.py --verify-only` in this plan | owns schema; no SUPERUSER; not mounted into runtime units | same |
| `middleware_backup` | backup job | read-only (`pg_read_all_data` or equivalent); no DML/DDL | same |
| `postgres_exporter` | metrics | `pg_monitor` only | same |

Role-provisioning source is still not in the repo (F-04); the readback verifies
attributes (`pg_roles`) and that no runtime role owns tables.

## 7. Secret-reference hygiene

Only paths are recorded; no value, DSN password, token or key appears in this
packet. The committed Postman staging environment has empty `secret`-typed token
values and `allow_database_mutations=false` (checked 2026-09-24).

| Secret | Host path | Mount | Check |
|---|---|---|---|
| per-unit DSN | `/etc/codestra/secrets/middleware-runtime/middleware-{integration-api,notification-worker,scheduler,reconciliation-worker}-database-url` | `/run/secrets/database_url` | `stat` only; owner `10001`, `0400`, not symlink |
| DB CA | `/etc/codestra/secrets/middleware-staging/db/ca.crt` (proposed) | `/run/secrets/middleware-staging-db-ca.crt` | `openssl x509` on public cert only |
| per-role client cert/key | `/etc/codestra/secrets/middleware-staging/db/<role>/client.{crt,key}` (proposed; one dir per role because of `clientname=CN`) | `/run/secrets/middleware-staging-db-client.{crt,key}` | cert: CN/expiry; key: `stat` only, `0600` uid `10001` |
| redis / middleware / webhook | `/etc/codestra/secrets/codestra-compose/{redis_url,middleware_secret,webhook_shared_secret}` | compose `secrets:` | `stat` only |
| DB API tokens (Postman) | operator-local only, never exported | Postman `db_read_token` / `db_verify_token` | never committed |

## 8. API endpoints, OpenAPI and Postman references

All paths below exist in `contracts/platform/middleware-openapi.generated.json`
on `MAIN@0606b0d`; `scripts/generate_postman.py --check` reports no drift.

| Endpoint | Use in plan | Expected |
|---|---|---|
| `GET /healthz` | P3/P4 liveness (compose healthcheck) | 200 |
| `GET /readyz` at `http://127.0.0.1:8095/readyz` | P3/P4 readiness (`HEALTH_REQUIRE_DATABASE=true`) | 200 |
| `GET /metrics` | worker scrape | 200 |
| `GET /v1/runtime/safety` | P0/P4 effect-flag proof | all false |
| `GET /internal/v1/database/readiness` | P4 gate | `ready=true`, head 0067, `head_count=1`, `tls_required=true`, `tls_active=true` |
| `GET /internal/v1/database/security/tls` | P4 | `sslmode=verify-full`, `hostname_verification=true`, `client_certificate_configured=true`, TLS ≥ 1.2 |
| `GET /internal/v1/database/{health,status,schema,migrations,pool,security/certificates,security/rls,performance,locks,capacity}` | P4 evidence | recorded |
| `GET /internal/v1/database/{backups,backups/latest,restores/latest}` | P4 | reflect P1 evidence when `database_certification_evidence_dir` is set; else `evidence_unavailable` (acceptable, recorded) |
| `POST /internal/v1/database/migrations/verify` | P4 (scope `platform.database.verify`) | verify only |
| `POST /internal/v1/database/{migrations/apply,sql,query}` | negative | 404/405 (Postman folders 01 / 06) |
| public `{base_url}/internal/v1/database/*` | negative | denied (Postman folder 05) |

Postman authority: `postman/collections/Middleware-V3-Database-Certification.postman_collection.json`
with `postman/environments/Middleware-V3-DB-Staging.postman_environment.json`
(`expected_alembic_head=0067_service_catalog_monitoring_state`,
`allow_database_mutations=false`). Its `db_private_base_url` is
`http://127.0.0.1:31883`, which is not the canonical integration API port
(8095); the operator must point it at the canonical unit for the P4 run (F-17).

## 9. Expected units (PAS-13 minimum)

| Canonical service (`deploy/compose.runtime.yaml`) | Command | DB role | Replaces legacy |
|---|---|---|---|
| `middleware-integration-api` (port 8095) | `app.entrypoints.integration_api` | `middleware_api` | `…-middleware-staging-1` (`b81c1252…`) |
| `middleware-notification-worker` | `app.entrypoints.notification_worker` | `middleware_worker` | `…-notification-worker-staging-1` |
| `middleware-scheduler` | `app.entrypoints.scheduler` | `middleware_scheduler` | `…-scheduler-staging-1` |
| `middleware-reconciliation-worker` | `app.entrypoints.reconciliation_worker` | `middleware_reconciler` | (new) |

Legacy callback, odoo-result, scraper and social workers stay stopped. The other
17 canonical services stay out of PAS-13 scope.

## 10. Findings

Carried from 2026-09-21 (status updated):

| ID | Status 2026-09-24 | Blocks |
|---|---|---|
| F-01 signed RC not published | **OPEN**, now also F-12 | P0 |
| F-02 #304 not consumable | **OPEN** (see §5, F-15) | P0 |
| F-03 no cert expiry/identity check in #304 | OPEN (operator interim at P0.6) | P0.6 |
| F-04 no role-provisioning authority in repo | OPEN (roles exist per issue; attributes re-read at P0.7) | P0.7 |
| F-05 plaintext redis alternate in #304 | OPEN | P2 decision |
| F-06 rollback images only in Server 1 cache | OPEN (`docker save` at P1) | P1 |
| F-07 deploy controller pins receipts `1..10` vs `0011` | OPEN (`MAIN@0606b0d` line 510 unchanged) | controller-driven deploy |
| F-08 no staging compose overlay in Git | OPEN | P2 |
| F-09 cause of 2026-09-21 exit 137 | superseded: the app plane is now *intentionally* stopped; the two exit-137 units stay stopped and are out of scope | — |
| F-10 #304 body overstated reconciliation | closed: live DB is now 0067 | — |
| F-11 installed backup controller is production-shaped | info | — |

New:

| ID | Finding | Owner | Blocks |
|---|---|---|---|
| F-12 | GitHub Actions for `ingtrader21-spec/Middleware-` is locked by a billing issue: release run `35613442378` never started; every #304 check fails in seconds. No RC and no trustworthy CI until cleared. | account owner / PAS-27 | P0.1, P0.2 |
| F-13 | `clientname=CN` requires one client certificate per role (CN = role). Four runtime certs must be issued/mounted per unit; a shared cert fails closed for three of four units. | staging operator / PAS-79 | P0.6, P2 |
| F-14 | Legacy rollback image `b81c1252…` has no proven way to present a CN-bound client cert; R2 rollback to it cannot connect under the current pg_hba without an owner-approved exception. R1 is the operational rollback. | PAS-13 owner | R2 only |
| F-15 | #304 head `4e524fc` merges four unrelated lanes into the DB/TLS PR; review scope and closure re-derivation must be redone on a clean DB/TLS-only head. | PAS-79/80 | P0.2 |
| F-16 | #304 staging `database_alternates` admits only the 4 runtime roles; `middleware_migration` verification must use a DSN outside the runtime profile lock (or the profile must add a migration alternate). | PAS-79/80 | P1.7 |
| F-17 | Postman staging env `db_private_base_url=http://127.0.0.1:31883` does not target the canonical API (8095). | PAS-102 | P4 |
| F-18 (info) | This branch adds tracked docs, so `scripts/derive_trust_pins.py --check` reports `ACTIVE_STALE_AFTER=1` for the Middleware closure (expected; see PAS-27 07). Merging this evidence to main requires rebase onto `0606b0d` + `--apply-candidate` in the PR — not done here (release/trust file, ownership fence). | merge owner | merge only |

## 11. Ownership fence honoured

* No migration applied, no image replaced, no service reloaded, no deploy, no provider/business effect.
* No Server 1 command executed from this session; no Linear or external plugin call; GitHub reads were read-only `gh` queries.
* No edit to `.codestra/`, release, trust, deploy, workflow or runtime files.

## Files

* `README.md` — this packet
* `execution-plan.md` — fail-closed plan P0→P5 with exact input matrix and R1/R2 rollback
* `readback-commands.md` — read-only commands for every `LIVE_READBACK_PENDING`
* `staging-preflight-packet.v1.json` — machine-readable packet
