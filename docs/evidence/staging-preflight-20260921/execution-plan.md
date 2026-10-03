# PAS-180 — Fail-closed staging execution plan

Scope: canonical Middleware staging on Server 1 (`65.109.65.169`), Compose project
`codestra-middleware-staging`, database `middleware_staging` in
`codestra-middleware-staging-postgres-1`.

Sequence: `P0 gates -> P1 freeze+backup -> P2 isolated rehearsal -> P3 0058→0067
reconciliation -> P4 verify-full TLS -> P5 exact signed image deploy -> P6
health/readback -> P7 hardening`. Every phase has an entry gate, an exact abort
condition and a rollback. Nothing in this plan is executed by the PAS-180 lane;
execution is PAS-13 after PAS-27 supplies the RC.

Conventions: `STOP` = abort the run, do not continue to the next phase, record
the failing key. All commands run as root on Server 1 through the restricted
deployment path; values are read into evidence files under
`/var/lib/codestra-middleware/staging-preflight/<RUN_ID>/`, never into Git.

## Exact input matrix

| Input | Value | Source | Status |
|---|---|---|---|
| `SOURCE_SHA` | protected main SHA the RC was built from | PAS-27 release manifest | `PENDING_PAS27` |
| `IMAGE_REFERENCE` | `ghcr.io/ingtrader21-spec/codestra-middleware@sha256:<64 hex>` | PAS-27 release manifest (`release-manifest.v1`) | `PENDING_PAS27` |
| `RELEASE_RUN_ID` / `RELEASE_ID` | `<run id>` / `<12 hex>-<12 hex>` | PAS-27 | `PENDING_PAS27` |
| `EXPECTED_SCHEMA_HEAD` | `0067_service_catalog_monitoring_state` | main | fixed |
| `EXPECTED_CORE_RECEIPTS` | `1,2,3,4,5,6,7,8,9,10,11` | main `migrations/00NN_*.sql` | fixed (see F-07) |
| `EXPECTED_AUTOMATION_RECEIPTS` | `1` | main | fixed |
| `LEGACY_HEAD` | `0058_odoo_delivery_sources` | reconcile script | fixed |
| `LEGACY_SOURCE_SHA` | `b29db772ed82c0d2f1adfdb8e6da58d4baa77524` | reconcile script | fixed |
| `POSTGRES_CONTAINER` | `codestra-middleware-staging-postgres-1` | SentinelX | re-read at P0 |
| `POSTGRES_DATABASE` | `middleware_staging` | reconcile script precondition | fixed |
| `DB_HOST_IN_DSN` | `postgres` (compose service name; must equal server-cert SAN) | #304 profile | fixed once #304 lands |
| `DB_ROLES` | `middleware_api`, `middleware_worker`, `middleware_reconciler`, `middleware_scheduler` | #304 profile | fixed once #304 lands |
| `DB_MIGRATION_ROLE` | owner/DDL role used only by P3 | owner decision (F-04) | `PENDING_OWNER` |
| `DB_TLS_TUPLE` | `sslmode=verify-full&sslrootcert=/run/secrets/middleware-staging-db-ca.crt&sslcert=/run/secrets/middleware-staging-db-client.crt&sslkey=/run/secrets/middleware-staging-db-client.key` | #304 profile | fixed once #304 lands |
| `RUNTIME_PROFILE_ID` / `APP_ENV` | `codestra-middleware-staging-v1` / `staging` | main | fixed |
| `STAGING_COMPOSE_FILE` | reviewed staging overlay of `deploy/compose.runtime.yaml` pinned to `IMAGE_REFERENCE` | PAS-13 (F-08) | `PENDING_REVIEW` |
| `LEGACY_COMPOSE_FILE` | `/opt/codestra/middleware-staging/compose.yaml` (+ `compose.scraper-canary.yaml`) | server | backed up at P1 |
| `EFFECT_FLAGS` | all `false`; `NATS_DISPATCH_MODE=disabled`; `TEMPORAL_WORKER_MODE=disabled`; `PRODUCTION_DIALING=DISABLED` | compose `x-runtime` | fixed |
| `BACKUP_ROOT` | `/opt/codestra/backups/middleware-staging/<RUN_ID>/` | plan | created at P1 |
| `RUN_ID` | `<UTC yyyymmddThhmmssZ>` | plan | assigned at P0 |

## P0 — Entry gates (read-only; all must hold, else STOP)

| # | Gate | Check | Abort condition |
|---|---|---|---|
| P0.1 | RC exists | PAS-27 records `IMAGE_REFERENCE`, cosign identity/issuer verified, SLSA subject == digest, SBOM bound, Grype/Trivy PASS, single Alembic head 0067 | any missing → STOP (F-01) |
| P0.2 | #304 accepted | `SOURCE_SHA` contains #304's successor (green exact-head CI incl. staging contract validator; independent review) | not on main → STOP (F-02) |
| P0.3 | Deploy controller receipt pin | if the controller is used: line 510 accepts `1..11` | still `1..10` → STOP (F-07) |
| P0.4 | Current state == packet | run `readback-commands.md` §1–§4; compare: container name, image ID `b81c1252…`, `alembic_version = 0058_odoo_delivery_sources`, `SHOW ssl = off`, database `middleware_staging` | any drift → STOP and re-baseline this packet |
| P0.5 | Exit cause of 11:20Z | `docker inspect` `State.ExitCode/FinishedAt/OOMKilled`, `journalctl -k` around 11:20Z, `free -m` | unexplained exit 137 / OOM → STOP (F-09) |
| P0.6 | No live writers | `pg_stat_activity` shows no non-superuser connections to `middleware_staging` | active legacy writers → STOP (app plane must stay stopped) |
| P0.7 | Secrets referenced | `stat` on every path in packet §7 (owner root/10001, mode 0600/0640, no symlink); **no content read** | missing → STOP |
| P0.8 | Certificates ready | CA / server cert / client cert exist; `openssl x509 -noout -checkend 2592000`; server SAN contains `DNS:postgres`; client cert CN maps to a role (if `clientcert=verify-full` with cert map) | any FAIL → STOP (F-03) |
| P0.9 | Roles provisioned | four runtime roles + migration role exist with least privilege (no SUPERUSER/CREATEDB/CREATEROLE on runtime roles) | missing → STOP (F-04) |
| P0.10 | Host capacity | disk for tar + dump (≥ 2× data dir), memory headroom for 4 units at `mem_limit 512m` | insufficient → STOP |
| P0.11 | Provider effects | `/v1/runtime/safety` on any running canonical unit (none expected) = all false; no `PRODUCTION_ACTIVATION_ID` | any true → STOP |

## P1 — Freeze and backup (mutation: files only; no DB, no images changed)

1. Assign `RUN_ID`; `install -d -m 0700 $BACKUP_ROOT`.
2. Confirm the 9 legacy app containers are stopped (they are, per SentinelX); do **not** start them.
3. Config backup: copy `/opt/codestra/middleware-staging/compose*.yaml`, env files (mode-preserving, no content in evidence), `pg_hba.conf`, `postgresql.conf` (from inside the postgres container) → `$BACKUP_ROOT/config/`; `sha256sum` all.
4. Rollback images: `docker save` each of the five legacy image IDs (§1.2 of README) → `$BACKUP_ROOT/images/<id>.tar`; `sha256sum`; verify with `docker load --input` dry read (`tar -tf`). (F-06)
5. Logical backup: `docker exec -u postgres $POSTGRES_CONTAINER pg_dump --format=custom --compress=9 --no-owner --no-acl --dbname=middleware_staging > $BACKUP_ROOT/middleware_staging.dump`; `pg_restore --list` catalog check; `sha256sum`.
6. Physical backup: `docker exec … pg_ctl` **not** used; instead `docker stop $POSTGRES_CONTAINER` is **not** allowed here (shared healthy service). Take a consistent physical copy with `pg_basebackup -D - -Ft -X fetch` executed inside the container as `postgres` streaming to `$BACKUP_ROOT/postgres-base.tar`; `sha256sum`. (Mirrors #297's `postgres-data.tar` intent without stopping the DB.)
7. Record: `BACKUP_TIMESTAMP`, `BACKUP_DUMP_SHA256`, `BACKUP_BASE_SHA256`, `IMAGE_ARCHIVE_SHA256[5]`, `CONFIG_SHA256[]`.

Abort: any `sha256sum` mismatch or empty file → STOP (nothing to roll back yet).

## P2 — Isolated restore rehearsal (mutation: disposable container only)

The reconcile script hard-requires `current_database() == 'middleware_staging'`,
so the rehearsal runs in a **disposable PostgreSQL container** (same major version
as the canonical one, read at P0) on an isolated network — exactly as #297 did —
never in a second database inside the canonical container.

1. `docker run -d --name middleware-staging-rehearsal-$RUN_ID --network none …` (same image as `POSTGRES_CONTAINER`); `createdb --template=template0 middleware_staging`.
2. `pg_restore --exit-on-error --no-owner --no-acl --dbname=middleware_staging < $BACKUP_ROOT/middleware_staging.dump`.
3. Readback on the copy: `alembic_version = 0058_odoo_delivery_sources`; `ck_odoo_result_delivery_one_source` constraint signature; provider endpoint id `55000000-0000-4000-8000-000000000021` unique; counts of `odoo_result_delivery`, `integration_event`, `outbox_event` equal to P1.
4. Bridge rehearsal from a checkout at exactly `SOURCE_SHA`:
   `DATABASE_URL_FILE=<0600 file> python scripts/reconcile_legacy_staging_database.py --execute --expected-base-sha 8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692 --expected-source-sha $SOURCE_SHA --evidence-dir $BACKUP_ROOT/rehearsal/`
   Expect `RECONCILIATION_STATUS=PASS`, `TO_HEAD=0067…`, `BUSINESS_ROW_COUNTS_PRESERVED=YES`.
5. Then on the same disposable DB: `APP_ENV=staging DATABASE_URL=<DSN> python scripts/migrate_runtime.py` (execute, not `--verify-only`: the legacy DB has no SQL receipt tables) → expect `RUNTIME_MIGRATION=PASS`, `RUNTIME_SCHEMA_VERIFIED=PASS`, receipts `1..11` and automation `1`. (`APP_ENV=staging` makes the #304 authority demand `verify-full`; if the disposable container has no TLS, run this step with `APP_ENV=test` and record that TLS enforcement is proven at P4/P6, not here.)
6. `docker rm -f middleware-staging-rehearsal-$RUN_ID`. Record `ISOLATED_RESTORE_RESULT=PASS`.

Abort: any FAIL → STOP; canonical DB untouched.

## P3 — Canonical 0058 → 0067 reconciliation (mutation: canonical DB, single transaction)

Entry: P0–P2 PASS in this `RUN_ID`; still no live writers (`pg_stat_activity`).

1. `DATABASE_URL_FILE` for the **migration role** pointing at `middleware_staging` via the compose network (plaintext is still the only mode at this point — TLS is P4; the reconcile script itself does not enforce sslmode). Run from a checkout at `SOURCE_SHA`:
   `python scripts/reconcile_legacy_staging_database.py --execute --expected-base-sha 8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692 --expected-source-sha $SOURCE_SHA --evidence-dir $BACKUP_ROOT/reconcile/`
   The script takes `pg_advisory_xact_lock('codestra.middleware.legacy-staging-reconcile')`, validates the exact legacy signature, archives legacy provider-route rows to `legacy-provider-route-before.json`, moves the marker to `0056_klyrow_delivery_events`, removes only the obsolete `odoo.provider_activities.create` registry identities, upgrades to 0067, checks 11 canonical tables, row counts and `version_num VARCHAR(64)`. Any failure rolls the transaction back.
2. Apply SQL receipts: `APP_ENV=staging DATABASE_URL=<migration-role DSN> python scripts/migrate_runtime.py` → `RUNTIME_MIGRATION=PASS`, `RUNTIME_SCHEMA_VERIFIED=PASS`, `RUNTIME_ALEMBIC_HEAD=0067…`. (Uses `pg_try_advisory_lock(742603070118)`; refuses unknown lineage — which is why step 1 must precede it.)
3. Readback: `alembic_version` = exactly `0067_service_catalog_monitoring_state`; `middleware_schema_migrations` = `1..11`; `middleware_automation_schema_migrations` = `1`; 4 platform tables present; row counts unchanged from P1.

Abort/rollback: step 1 failure → automatic transaction rollback, verify head still 0058, STOP. Step 2/3 failure → restore `middleware_staging` from `$BACKUP_ROOT/middleware_staging.dump` (terminate connections, `dropdb`/`createdb`, `pg_restore`), verify head 0058 and counts, STOP.

## P4 — verify-full TLS on the canonical PostgreSQL (mutation: postgres config, reload only)

Entry: P3 PASS.

1. Install server cert/key/CA into the postgres container's data/config volume (owner postgres uid, key `0600`); `postgresql.conf`: `ssl=on`, `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file`, `ssl_min_protocol_version='TLSv1.2'`.
2. `pg_hba.conf`: **add above** existing lines
   `hostssl middleware_staging middleware_api,middleware_worker,middleware_reconciler,middleware_scheduler <compose subnet> scram-sha-256 clientcert=verify-full`
   (and the migration role if it will use TLS). Do **not** remove plaintext `host` lines yet (rollback safety; removal is P7).
3. `SELECT pg_reload_conf();` — no restart of the shared container.
4. Readback: `SHOW ssl` = `on`; from a disposable client container on the compose network: `psql "host=postgres dbname=middleware_staging user=middleware_api sslmode=verify-full sslrootcert=… sslcert=… sslkey=…" -c "select ssl, version, cipher from pg_stat_ssl where pid=pg_backend_pid()"` → `ssl=t`; a `sslmode=disable` attempt for the same role over the `hostssl` rule must be rejected only once P7 removes plaintext lines (record current behaviour either way).
5. Record `POSTGRES_TLS=verify-full`, TLS version/cipher, cert fingerprints (not keys).

Abort/rollback: reload fails or `SHOW ssl` ≠ on or verify-full handshake fails → restore `postgresql.conf`/`pg_hba.conf` from `$BACKUP_ROOT/config/`, `pg_reload_conf()`, verify `SHOW ssl` back to previous, STOP (DB stays at 0067 — acceptable, it is forward-compatible with the legacy app being stopped; a full rollback to 0058 follows the P3 rollback path if the run is abandoned).

## P5 — Deploy the exact signed image (mutation: staging Compose project only)

Entry: P4 PASS; `IMAGE_REFERENCE` is the PAS-27 digest.

1. Registry read-only login with a scoped token via stdin; `docker pull $IMAGE_REFERENCE`; verify labels `org.opencontainers.image.revision == SOURCE_SHA`, `version == sha-$SOURCE_SHA`, user `65532`, arch `amd64`; `cosign verify` identity/issuer against the RC evidence; digest read-back equals `IMAGE_REFERENCE`.
2. Write the four per-unit DSN secrets (`/etc/codestra/secrets/middleware-runtime/middleware-{integration-api,notification-worker,scheduler,reconciliation-worker}-database-url`, owner uid `10001`, mode `0400`) with the exact `DB_TLS_TUPLE`; mount CA/client cert/key read-only at the #304 paths; key file uid `10001` mode `0600`.
3. Render `STAGING_COMPOSE_FILE` with `MIDDLEWARE_IMAGE=$IMAGE_REFERENCE`, `RUNTIME_PROFILE_ID=codestra-middleware-staging-v1`, `APP_ENV=staging`, `HEALTH_REQUIRE_DATABASE=true`, every effect flag `false`; `docker compose --project-name codestra-middleware-staging -f … config --quiet`.
4. Start **only** `middleware-integration-api`; wait for `healthy` (compose healthcheck = `/healthz` + `/readyz`).
5. Start `middleware-scheduler`, `middleware-notification-worker`, `middleware-reconciliation-worker`; wait for `healthy`.
6. Record container IDs, image digest per container, `RestartCount=0` after `OBSERVATION_SECONDS ≥ 60`.

Abort/rollback: image label/signature mismatch → STOP before any container starts. Any unit not healthy within its `start_period + retries×interval` → `docker compose … rm -sf` the new units, STOP; DB/TLS remain (forward-compatible), decide on full rollback (P3/P4 paths) or repair.

## P6 — Health / readback (read-only)

| Check | Expected |
|---|---|
| `GET /healthz`, `GET /readyz` on `middleware-integration-api` | 200 |
| `GET /internal/v1/database/readiness` (scope `platform.database.read`) | `ready=true`, `alembic_head=0067_service_catalog_monitoring_state`, `head_count=1`, `missing_required_tables=[]`, `tls_required=true`, `tls_active=true` |
| `GET /internal/v1/database/security/tls` | `dsn_policy.sslmode=verify-full`, `hostname_verification=true`, `client_certificate_configured=true`, `tls_version` ≥ TLSv1.2 |
| `GET /internal/v1/database/security/certificates`, `/security/rls`, `/migrations`, `/pool` | recorded |
| `GET /internal/v1/database/backups/latest`, `/restores/latest` | reflect P1/P2 evidence if `database_certification_evidence_dir` is configured |
| `GET /v1/runtime/safety` | every effect flag false; `PRODUCTION_DIALING=DISABLED` |
| `docker inspect` labels on each running unit | revision == `SOURCE_SHA` |
| PAS-102 Postman collection (Staging environment, secret-free) | PASS → `DB_POSTMAN_STAGING=PASS` (owned by PAS-102) |
| Provider/business counters | zero movement (`PROVIDER_EFFECTS=0`) |

Any expectation unmet → STOP; new units stopped (`rm -sf`); keep evidence; decide rollback.

## P7 — Hardening (after P6 PASS and PAS-13 sign-off)

1. Remove plaintext `host` lines for the four roles from `pg_hba.conf`; add `hostnossl middleware_staging <four roles> all reject`; `pg_reload_conf()`; verify a `sslmode=disable` attempt is rejected.
2. Retire legacy containers per convergence `retirementOrder` (one family at a time, rollback proof first) — separate ticket; images stay archived.

## Rollback summary

| From | To | Procedure |
|---|---|---|
| P5/P6 failure | pre-run | stop/remove the 4 new units; restore `pg_hba.conf`/`postgresql.conf` (P4 backup) + reload; restore `middleware_staging` from `$BACKUP_ROOT/middleware_staging.dump` (or `postgres-base.tar` if logical restore fails); verify `alembic_version=0058_odoo_delivery_sources` and P1 row counts; `docker load` legacy image archives if any image was pruned; `docker compose -f <legacy compose backup> up -d` the legacy units only if the pre-run app plane is to be restored (it was down before the run — restoring it is a separate decision). |
| P3 failure | pre-run | automatic; verify head 0058. |
| P4 failure | P3 state | config restore + reload. |

Rollback is rehearsed by P2 (restore) and by the `docker save`/`tar -tf` check in P1. `RUNTIME_MUTATION` for this packet = 0; the first mutation of any kind is P1 step 3.
