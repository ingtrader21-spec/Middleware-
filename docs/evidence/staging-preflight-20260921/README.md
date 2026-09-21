# PAS-180 — Middleware staging preflight packet (V3-M1A)

Linear: https://linear.app/passion-fruit/issue/PAS-180
Parent gate: PAS-13 (V3-M1 deploy Middleware V3 to staging). Release gate: PAS-27.
Packet date: 2026-09-21. Author session: `middleware-96` (inventory/evidence lane only).

This packet records the canonical Middleware staging state, classifies the DB/TLS
prerequisites, fixes the backup/rollback points, and prepares a fail-closed
execution plan for `0058 -> 0067 reconciliation -> verify-full TLS -> exact signed
image deploy -> health/readback`. It authorizes nothing. Nothing on the server was
mutated to produce it.

```text
STAGING_PREFLIGHT_PACKET=PASS
CURRENT_STATE_RECORDED=YES
BACKUP_ROLLBACK_READY=YES          # rollback points fixed + restore rehearsed 2026-09-20; fresh backup is gate P1
TLS_PREREQUISITES_CLASSIFIED=YES
RUNTIME_MUTATION=0
PROVIDER_EFFECTS=0
LIVE_READBACK=PENDING_OPERATOR     # see "Provenance" below and readback-commands.md
```

## Provenance and limits

Every value below carries one of these provenance tags:

| Tag | Meaning |
|---|---|
| `REPO@8ecf6e9` | derived from protected main `8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692` (MAIN_AFTER_301) |
| `REPO@bd406a6` | same, unchanged since `bd406a6508c8095a3f23b35149a2eebcb94c94c6` |
| `PR#304@61c30e1` | from open PR #304 head `61c30e1cd8b51b8450429fbf0e1298878c2a5cf0` (NOT merged) |
| `SENTINELX 2026-09-21` | independent runtime readback of Server 1 recorded on PAS-13 / PAS-102 (08:04 AST) |
| `PR#297 2026-09-20` | rehearsal evidence recorded in merged PR #297 (`8829d92`) |
| `LIVE_READBACK_PENDING` | must be read from Server 1 before execution; exact command in `readback-commands.md` |

This session's SSH access to Server 1 (`65.109.65.169`) was denied by the
workstation permission classifier (shared production host), so no fresh live
readback was taken here. The most recent independent readback (SentinelX, today)
is used as the recorded current state; the execution plan re-reads every value at
gate P0 and stops on any drift.

## 1. Current state (recorded)

### 1.1 Source / release authority

| Key | Value | Provenance |
|---|---|---|
| PROTECTED_MAIN | `8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692` (PR #301 merged 2026-09-21T12:47:11Z) | GitHub |
| CANONICAL_ALEMBIC_HEAD | `0067_service_catalog_monitoring_state` (`migrations/versions/0067_*.py`, down `0066_reconcile_odoo_campaign_scope`) | `REPO@8ecf6e9` |
| CORE_SQL_RECEIPTS | `migrations/0001..0011_*.sql` (11 receipts); automation `migrations/automation/0001_automation_v2.sql` | `REPO@8ecf6e9` |
| FORWARD_IMAGE_REPOSITORY | `ghcr.io/ingtrader21-spec/codestra-middleware` (was `appolon1908-hue` before #301) | `REPO@8ecf6e9` |
| SIGNED_RC_STATUS | **NOT PUBLISHED**. "Signed Middleware Release" run `35602170321` on `8ecf6e9` failed at push: `denied: permission_denied: read_package` (package/installation authority; PAS-27 lane) | GitHub 2026-09-21T12:54Z |
| TARGET_IMAGE_DIGEST | `PENDING_PAS27` | — |

### 1.2 Canonical staging runtime (Server 1 / Application Server A, `65.109.65.169`)

| Key | Value | Provenance |
|---|---|---|
| STAGING_COMPOSE_PROJECT | `codestra-middleware-staging` | `REPO@8ecf6e9` (`config/middleware-authority-convergence.v1.json` workloads) |
| STAGING_CONFIG_AUTHORITY | `/opt/codestra/middleware-staging/compose.yaml` (+ `compose.scraper-canary.yaml`) — server-side, not in Git | `REPO@8ecf6e9` |
| CURRENT_STAGING_MIDDLEWARE_IMAGE | `codestra/middleware:staging-b29db772` — mutable local tag, docker image ID `sha256:b81c125296effc17a33258212d9a71a3c427a972fa9783ec2c060109d167408f`, source Codestra-SRL `b29db772ed82c0d2f1adfdb8e6da58d4baa77524`; **no registry digest** | `REPO@8ecf6e9` + `SENTINELX 2026-09-21` |
| CURRENT_STAGING_APP_PLANE | **DOWN** — 9 `codestra-middleware-staging-*` API/worker containers exited ~2026-09-21T11:20Z (7 exit 0; `callback` and `scraper-odoo-delivery-worker` exit 137). Cause not established. | `SENTINELX 2026-09-21` |
| CURRENT_STAGING_DB_CONTAINER | `codestra-middleware-staging-postgres-1` (healthy) | `SENTINELX 2026-09-21` |
| CURRENT_STAGING_DB_NAME | `middleware_staging` | `REPO@8ecf6e9` (`scripts/reconcile_legacy_staging_database.py` precondition) |
| CURRENT_STAGING_DB_SCHEMA | `0058_odoo_delivery_sources` (legacy lineage `0056_klyrow_delivery_events -> 0057_provider_activities -> 0058_odoo_delivery_sources`, source `b29db772`) | `SENTINELX 2026-09-21` + `REPO@8ecf6e9` |
| CURRENT_STAGING_DB_TLS | **off** (PostgreSQL `ssl=off`) | `SENTINELX 2026-09-21` |
| CURRENT_STAGING_DB_ROLES | `LIVE_READBACK_PENDING` (legacy role names / grants unknown) | — |
| CURRENT_STAGING_REDIS | `codestra-middleware-staging-redis-1` (healthy) | `SENTINELX 2026-09-21` |
| POSTGRES_IMAGE / VERSION | `LIVE_READBACK_PENDING` | — |
| HOST_CAPACITY | 260 containers / 108 running / 1 unhealthy / 0 restarting | `SENTINELX 2026-09-21` |

Legacy staging workloads (all `rollback-only` in the convergence authority):

| Workload | Image tag (mutable) | Docker image ID | Source |
|---|---|---|---|
| `codestra-middleware-staging-middleware-staging-1` (API) | `codestra/middleware:staging-b29db772` | `sha256:b81c1252…67408f` | Codestra-SRL `b29db772` |
| `codestra-middleware-staging-odoo-result-worker-staging-1` | `codestra/middleware:staging-b29db772` | `sha256:b81c1252…67408f` | Codestra-SRL `b29db772` |
| `codestra-middleware-staging-callback-staging-1` | `codestra/middleware:current-hardened-20260723` | `sha256:57a4a3a2…93f4d` | `f1c07e0-reprofix2` (INVALID_REVISION_METADATA) |
| `codestra-middleware-staging-notification-worker-staging-1` | `codestra/middleware:staging-preflight-n8n-auth-20260801` | `sha256:ed7accf6…f2386` | UNESTABLISHED |
| `codestra-middleware-staging-scheduler-staging-1` | `codestra/middleware:staging-preflight-n8n-auth-20260801` | `sha256:ed7accf6…f2386` | UNESTABLISHED |
| `codestra-middleware-staging-scraper-odoo-delivery-worker-1` | `codestra/middleware:scraper-protected-main-4780bd72` | `sha256:dc97c48f…fcda1` | Codestra-SRL `4780bd72` |
| `codestra-middleware-staging-social-dead-letter-worker-staging-1` | `codestra/middleware:social-staging-12cd5fc` | `sha256:8e4a1afa…18fe6` | UNESTABLISHED |
| `codestra-middleware-staging-social-delivery-worker-staging-1` | `codestra/middleware:social-staging-12cd5fc` | `sha256:8e4a1afa…18fe6` | UNESTABLISHED |
| `codestra-middleware-staging-social-reconciliation-worker-staging-1` | `codestra/middleware:social-staging-12cd5fc` | `sha256:8e4a1afa…18fe6` | UNESTABLISHED |

Full image IDs are in `staging-preflight-packet.v1.json`. Their GHCR legacy
mirror (`ghcr.io/appolon1908-hue/codestra-middleware-legacy:*`) is still
`PENDING_SERVER_A_ACCESS` — the rollback images exist **only** in the Server 1
Docker image cache. See finding F-06.

### 1.3 Isolated PAS-102 candidate (NOT canonical, NOT forward authority)

| Key | Value | Provenance |
|---|---|---|
| `middleware-pas102-staging-db` | Alembic `0067_service_catalog_monitoring_state`, PostgreSQL `ssl=on` | `SENTINELX 2026-09-21` |
| `middleware-pas102-candidate-api` | `codestra/middleware:pas102-112bab3` (local unsigned build), healthy | `SENTINELX 2026-09-21` |

This proves 0067 + TLS on the same host. It must not be promoted or confused with
the canonical project. It is also a second `postgres`-named topology on the host;
the execution plan pins the canonical container by exact name.

## 2. Target state

| Key | Value | Provenance |
|---|---|---|
| TARGET_SCHEMA | `0067_service_catalog_monitoring_state` | `REPO@8ecf6e9` |
| TARGET_SQL_RECEIPTS | core `1..11`, automation `1` (`public.middleware_schema_migrations`, `public.middleware_automation_schema_migrations`) | `REPO@8ecf6e9` |
| TARGET_IMAGE_DIGEST | `PENDING_PAS27` (`ghcr.io/ingtrader21-spec/codestra-middleware@sha256:<digest>`; OCI labels `org.opencontainers.image.revision == source SHA`, `version == sha-<SHA>`, user `65532`, arch `amd64`) | `REPO@8ecf6e9` deploy controller checks |
| TARGET_SOURCE_SHA | protected main at RC build time (`>= 8ecf6e9`; must include #304's accepted successor, see §5) | — |
| TARGET_RUNTIME_PROFILE | `codestra-middleware-staging-v1`, `APP_ENV=staging` | `REPO@8ecf6e9` |
| TARGET_DB_DSN (per unit) | `postgresql://<role>:<secret>@postgres:5432/middleware_staging?sslmode=verify-full&sslrootcert=/run/secrets/middleware-staging-db-ca.crt&sslcert=/run/secrets/middleware-staging-db-client.crt&sslkey=/run/secrets/middleware-staging-db-client.key` | `PR#304@61c30e1` (`database_alternates`) |
| TARGET_DB_ROLES | `middleware_api`, `middleware_worker`, `middleware_reconciler`, `middleware_scheduler` | `PR#304@61c30e1` |
| TARGET_REDIS | main profile: `rediss://middleware-staging@redis.middleware-staging.svc.cluster.local:6379/14`; #304 alternate: `redis://redis:6379/0` (plaintext, see F-05) | `REPO@8ecf6e9` / `PR#304@61c30e1` |
| TARGET_EFFECT_FLAGS | every flag in `deploy/compose.runtime.yaml` `x-runtime.environment` = `false`; `NATS_DISPATCH_MODE=disabled`, `TEMPORAL_WORKER_MODE=disabled`, `OUTBOX_DISPATCH_ENABLED=false`, `PRODUCTION_DIALING=DISABLED` | `REPO@8ecf6e9` |

Topology note: the staging profile on main (`config/runtime-profiles.v1.json`)
still describes a Kubernetes-style topology
(`postgresql.middleware-staging.svc.cluster.local` / `codestra_staging` /
`middleware_staging` user). The real staging is Docker Compose
(`postgres` / `middleware_staging` / four roles). A canonical image cannot boot
with a locked staging profile against the real DB until #304's
`database_alternates` (or an equivalent accepted profile change) is on main.
This makes #304 a hard prerequisite, not an optional input (§5).

## 3. TLS / hostssl / verify-full prerequisites (classified)

Current class: **PLAINTEXT** (`ssl=off`, no hostssl). Target class: **verify-full + client certificate (mTLS)** for the four runtime roles and the migration path (PR #304 refuses anything below `verify-full` when `APP_ENV` is staging/production, validates cert/key paths, and requires `sslkey` mode without group/other bits).

| Item | Requirement | Readiness | Provenance |
|---|---|---|---|
| POSTGRES_CA | CA that signs the server certificate; mounted read-only at `/run/secrets/middleware-staging-db-ca.crt` in every unit; file exists, absolute, readable by container uid `10001` | `LIVE_READBACK_PENDING` (not established that a staging DB CA exists) | `PR#304@61c30e1`, `deploy/compose.runtime.yaml` |
| POSTGRES_SERVER_CERT | server cert + key inside `codestra-middleware-staging-postgres-1`; SAN **must contain `DNS:postgres`** (the DSN host; `verify-full` checks hostname); key `0600` owned by the postgres uid; `ssl=on`, `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file` set; reloadable via `pg_reload_conf()` (no restart) | `NOT_ACTIVE` (`ssl=off`); file presence `LIVE_READBACK_PENDING` | `SENTINELX 2026-09-21` |
| POSTGRES_CLIENT_CERT | client cert/key per role (or one per unit) at `/run/secrets/middleware-staging-db-client.{crt,key}`; key `0600`, owned by uid `10001` (compose `user: 10001:10001`, `read_only: true`), else #304 fails closed (`sslkey permissions must deny group/other access` / `file is unavailable`) | `LIVE_READBACK_PENDING` | `PR#304@61c30e1` |
| pg_hba.conf | `hostssl middleware_staging <four roles> <compose subnet> scram-sha-256 clientcert=verify-full`; plaintext `host` lines for those roles removed only after P6 readback passes (P7); `hostnossl … reject` for the four roles at P7 | `LIVE_READBACK_PENDING` (current pg_hba unknown) | plan |
| Certificate validity / identity | PAS-79 requires non-expired certificate + expected identity before connection. #304 does **not** check expiry or identity (docstring defers to DB-04/DB-05). Operator must verify with `openssl x509 -checkend` and SAN match at P4. | GAP (F-03) | `PR#304@61c30e1` |
| Runtime/migration parity | `app/db/session.py`, `scripts/migrate_runtime.py`, and direct asyncpg all consume the same native DSN through `app/db/connection.py` | Source-level PASS in #304 (73 focused tests); not on main | `PR#304@61c30e1` |
| Readback | `/internal/v1/database/security/tls` → `pg_stat_ssl` (`tls_active`, version, cipher); `/security/certificates`; `dsn_policy.hostname_verification=true` | available on main (PAS-102) | `REPO@8ecf6e9` |

Server-side TLS enablement, pg_hba edits and secret installation are **mutations**
and belong to the execution phase (P4), not to this packet.

## 4. Backup / restore / rollback points

| Key | Value | Provenance |
|---|---|---|
| RECORDED_PHYSICAL_SNAPSHOT | `/opt/codestra/backups/middleware-db-reconcile/20260920T212950Z/postgres-data.tar`, `SHA256SUMS=PASS` | `PR#297 2026-09-20` |
| RECORDED_SNAPSHOT_DIGEST | value not recorded in #297 → `LIVE_READBACK_PENDING` (`sha256sum` of the tar / `SHA256SUMS`) | — |
| ISOLATED_RESTORE_RESULT | **PASS** — disposable restore of that snapshot, bridge executed from branch head `ec801b2b1ba5049d5b4753260bdaab5a0fd916b3`: `FROM_HEAD=0058_odoo_delivery_sources`, `TO_HEAD=0067_service_catalog_monitoring_state`, rows preserved (`odoo_result_delivery` 2→2, `integration_event` 4→4, `outbox_event` 3→3), `PRODUCTION_MUTATIONS=0` | `PR#297 2026-09-20` |
| ROLLBACK_SCHEMA_REFERENCE | `0058_odoo_delivery_sources` via **restore of the pre-reconcile snapshot only**. There is no Alembic downgrade path across the lineage bridge (the bridge rewrites `alembic_version` and deletes legacy provider-route registry rows). | `REPO@8ecf6e9` |
| ROLLBACK_IMAGE_REFERENCE | the five legacy image families in §1.2 by **image ID**; rollback compose = `/opt/codestra/middleware-staging/compose.yaml` as backed up at P1 | `REPO@8ecf6e9` |
| ROLLBACK_PG_HBA | backup of `pg_hba.conf` + `postgresql.conf` taken at P1, restored on any P4–P6 failure | plan |
| FRESH_BACKUP_AT_EXECUTION | mandatory (gate P1): physical tar of the data volume with the app plane stopped + `pg_dump --format=custom` of `middleware_staging` + `sha256sum` + isolated `pg_restore` readback (`alembic_version = 0058_odoo_delivery_sources`, row counts) | plan |
| INSTALLED_BACKUP_TOOL | `deploy/production/server/codestra-middleware-backup` is production-shaped: config pins `codestra_middleware_appolon` / `codestra-postgres-1` / `/var/backups/codestra-middleware`, and its restore rehearsal requires `public.middleware_schema_migrations`, which the legacy 0058 database has no reason to contain. **Not usable unmodified for staging**; the plan uses explicit `pg_dump`/`pg_restore` (F-07). | `REPO@8ecf6e9` |

## 5. PR #304 (DB/TLS authority) review — consumed as a staging prerequisite

Head `61c30e1c` (PR body still cites `fbca878` — stale). Base `bd406a65`; **now
one commit behind main** (`8ecf6e9`). Files: `app/db/connection.py` (new),
`app/core/config.py`, `app/db/session.py`, `scripts/migrate_runtime.py`,
`config/runtime-profiles.v1.json`, `config/test-skip-register.v1.json`,
`.codestra/validate-release-intent.py`, tests.

What it gives the staging lane (verified by reading the diff):

* one parser for DSN/TLS (`build_database_connection_authority`); target/identity query overrides rejected; `sslcert`/`sslkey` atomic; absolute paths; key permission check
* staging/production refuse `sslmode != verify-full` (no silent downgrade)
* runtime engine, Alembic engine and direct asyncpg connections share the exact native DSN and `application_name`
* `codestra-middleware-staging-v1` gains `database_alternates` matching the real Docker topology (host `postgres`, db `middleware_staging`, four roles, full TLS tuple) and `redis_alternates`
* no schema change; head remains 0067

Why it is **not consumable yet** (exact-head CI on `61c30e1` is RED):

1. `tests/test_staging_intake_observability_contract_validation.py::test_committed_staging_contract_is_valid` → `ContractError: staging runtime profile drift`. `scripts/validate_staging_intake_observability_contract.py` pins `EXPECTED_PROFILE` for `codestra-middleware-staging-v1` byte-for-byte; #304 changes that profile without updating the validator. Fails in Middleware CI (source head + merge result + docker-test-build), Required exact-SHA CI, and the Historical Stage 6 contract workflow.
2. `tests/test_release_authority.py::test_trust_derivation_check_passes` → `STALE release EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256`. #304 rewrote the Middleware closure line (`221f35f5… → b1594935…`); main now carries #301's closure (`96701332…`). Must be re-derived on the rebased tree, not hand-edited.
3. Needs rebase onto `8ecf6e9` (post-#301) before re-derivation.

Additional review findings on #304 content (owner: PAS-79/PAS-80 lane):

* F-03 — no certificate expiry / expected-identity check (PAS-79 acceptance item); DB-04/DB-05 must own it or #304 must add it before staging execution relies on it.
* F-05 — `redis_alternates` admits `redis://redis:6379/0` (plaintext, no username) for staging while the main profile and the historical staging contract require `rediss` (`redis_tls_required: true`). Either justify as a staging-only alternate or lock `rediss`.
* Positive: the `POSIX_PRIVATE_KEY_PERMISSIONS` skip-register entry for the new test is gated to `docker-test-build`, consistent with existing policy.

Decision recorded: #304 is a hard prerequisite for a canonical image to boot
against the real staging DB with a locked profile. It stays in this lane; it is
not to be merged or rebased into #301 (already merged) or into the PAS-27 RC
repair.

## 6. Least-privilege roles

| Item | State |
|---|---|
| Target runtime roles | `middleware_api`, `middleware_worker`, `middleware_reconciler`, `middleware_scheduler` (PR #304 profile; `deploy/compose.runtime.yaml` already mounts one `…-database-url` secret per unit, so per-role DSNs are the established pattern) |
| Migration/DDL role | separate owner role required for the Alembic bridge + `migrate_runtime.py`; runtime roles must not own DDL. Name `LIVE_READBACK_PENDING` / owner decision. |
| Role provisioning source | **none in repo** (no `CREATE ROLE`/grant script found for these four roles) → F-04. Owner: DB program (PAS-77). |
| Current legacy roles | `LIVE_READBACK_PENDING` (`\du`, grants on `middleware_staging`) |
| RLS | readback via `/internal/v1/database/security/rls` after deploy; no RLS policy authority in repo for the four roles |

## 7. Environment secret references (verify, do not read values)

| Secret | Host path (per `deploy/compose.runtime.yaml`) | Mount |
|---|---|---|
| per-unit DATABASE_URL | `/etc/codestra/secrets/middleware-runtime/middleware-<unit>-database-url` | `/run/secrets/database_url` |
| DB CA / client cert / client key | to be created: `/etc/codestra/secrets/middleware-staging/db/{ca.crt,client.crt,client.key}` (proposed) | `/run/secrets/middleware-staging-db-{ca.crt,client.crt,client.key}` (#304 tuple) |
| redis_url / middleware_secret / webhook_shared_secret | `/etc/codestra/secrets/codestra-compose/{redis_url,middleware_secret,webhook_shared_secret}` | compose `secrets:` |
| runtime env file | `/opt/codestra/env/middleware.env` (compose) vs `/etc/codestra-middleware/runtime.env` (deploy controller) — staging must pick one, root-owned `0600` | — |

Verification at P0 is existence + owner + mode only (`stat`), never content.

## 8. Health / readiness endpoints

| Endpoint | Purpose | Source |
|---|---|---|
| `GET /healthz` | liveness (compose healthcheck, port 8095) | `app/core/health.py` |
| `GET /readyz` | readiness; `HEALTH_REQUIRE_DATABASE=true` on `middleware-integration-api` → fails closed without PostgreSQL | `app/core/health.py`, compose |
| `GET /metrics` | scrape (worker healthcheck on `scraper-odoo-delivery-worker`) | compose |
| `GET /v1/runtime/safety` | effect-flag readback (`monitoring-readonly`, scope `health.read`) | staging contract |
| `GET /internal/v1/database/{health,readiness,status,schema,migrations,pool,security/tls,security/certificates,security/rls,performance,locks,capacity,backups,backups/latest,restores/latest}` | private read-only DB evidence (scope `platform.database.read`); `POST /internal/v1/database/migrations/verify` (scope `platform.database.verify`) — no SQL, no migration apply | `app/api/internal/database.py` (PAS-102) |
| worker liveness | `python -c "import os; os.kill(1, 0)"` | compose |

`readiness` returns true only when reachable ∧ single head == `schema_head` ∧
required tables present ∧ (`tls_required` → `tls_active`). That is the P6 gate.

## 9. Expected units

PAS-13 minimum (API / worker / scheduler / reconciler), mapped to canonical
services in `deploy/compose.runtime.yaml` and to DB roles:

| Canonical service | Command | DB role | Replaces legacy |
|---|---|---|---|
| `middleware-integration-api` | `app.entrypoints.integration_api` | `middleware_api` | `…-middleware-staging-1` |
| `middleware-notification-worker` | `app.entrypoints.notification_worker` | `middleware_worker` | `…-notification-worker-staging-1` |
| `middleware-scheduler` | `app.entrypoints.scheduler` | `middleware_scheduler` | `…-scheduler-staging-1` |
| `middleware-reconciliation-worker` | `app.entrypoints.reconciliation_worker` | `middleware_reconciler` | (new) |

Remaining canonical services (17) are out of PAS-13 scope and stay down/legacy
until their own certification: event-gateway, klyrow-mail-odoo-worker,
scraper-odoo-delivery-worker, policy-engine, sync-worker, n8n-runtime-worker,
social-n8n-delivery-worker, postly-polling-worker, odoo-result-worker,
odoo-campaign-saga-worker, evidence-runner, extension-allocator,
telephony-provisioning, vicidial-adapter, pjsip-adapter, webphone-session-issuer,
vicidial-odoo-projection. Legacy `callback`, `odoo-result-worker`, `scraper`,
and the three `social-*` workers are not restarted by this plan.

No staging compose template exists in Git (`deploy/compose.runtime.yaml` is the
production-shaped runtime template; `ENVIRONMENT: production` is hard-coded on
some workers). A reviewed staging overlay is an execution input (F-08).

## 10. Findings (blocking unless marked otherwise)

| ID | Finding | Owner | Blocks |
|---|---|---|---|
| F-01 | Signed RC not published: release run `35602170321` on `8ecf6e9` → `denied: permission_denied: read_package` on `ghcr.io/ingtrader21-spec/codestra-middleware`. Package/installation authority decision required. | PAS-27 | P0 |
| F-02 | PR #304 RED on exact head (staging-profile validator drift + stale trust closure) and one commit behind main. Rebase → update `EXPECTED_PROFILE` in `scripts/validate_staging_intake_observability_contract.py` (or its pin) in the same PR → re-derive closure → green → independent review. | PAS-79/80 | P0 |
| F-03 | #304 lacks certificate expiry / identity checks required by PAS-79. | PAS-79 (DB-04/05) | P4 (operator check as interim) |
| F-04 | No role-provisioning authority for the four runtime roles + migration owner role. | PAS-77 | P3/P5 |
| F-05 | #304 admits plaintext `redis://redis:6379/0` for staging; main profile and historical contract require `rediss`. | PAS-79/80 | P5 (decision) |
| F-06 | Rollback images exist only in the Server 1 Docker cache; GHCR legacy mirror `PENDING_SERVER_A_ACCESS`. A prune destroys rollback. Plan P1 `docker save`s all five families first. | staging operator | P1 |
| F-07 | `deploy/production/server/codestra-middleware-deploy` pins core SQL receipts to `1,2,3,4,5,6,7,8,9,10` (line 510) while main ships `0011_audit_timeline_indexes.sql` (receipt 11). Any controller-driven deploy fails at `middleware_migration_head_mismatch` after a successful migration. Pre-existing; file belongs to the release/trust set — **not edited by this lane**. | PAS-27 / release lane | any deploy through the controller |
| F-08 | No staging compose overlay in Git; staging profile on main is k8s-shaped. Execution needs a reviewed staging compose pinned to the RC digest + #304 profile. | PAS-13 owner | P5 |
| F-09 | Staging app plane exited at ~11:20Z today (two exit 137). Root cause unknown; must be explained (host memory / manual stop / OOM) before P5 — otherwise the new units inherit the same fate. | staging operator | P0 |
| F-10 | PR #304 body says live staging reconciliation "already completed through merged PR #297". SentinelX shows the canonical DB still at 0058; #297 was a disposable-restore rehearsal. Wording only, but it must not be used as evidence of a reconciled staging DB. | PAS-79/80 | — |
| F-11 (info) | The installed backup controller is production-shaped and its restore rehearsal expects `middleware_schema_migrations`; staging backup uses explicit `pg_dump`/`pg_restore` + physical tar (§4). | — | — |

## 11. Ownership fence honoured

* No edit to PR #301 files (merged meanwhile) or any `.codestra/` / release / trust file.
* No migration applied, no image replaced, no Caddy/Kong/Odoo/n8n reload, no provider/business effect enabled.
* No server command executed from this session (SSH denied; nothing attempted beyond one read-only `id/hostname` probe that was refused before running).
* Files in this directory are evidence/plan only.

## Files

* `README.md` — this packet
* `execution-plan.md` — fail-closed plan P0→P7, exact input matrix, rollback per phase
* `readback-commands.md` — read-only commands to resolve every `LIVE_READBACK_PENDING`
* `staging-preflight-packet.v1.json` — machine-readable packet
