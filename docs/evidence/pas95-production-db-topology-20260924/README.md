# PAS-95 — DB-18 production-shaped database topology, all effects OFF

Linear: https://linear.app/passion-fruit/issue/PAS-95 (parent PAS-77; blocked by PAS-92, PAS-94; blocks PAS-55, PAS-96).
Source: protected main `0606b0db9ff59802f8da3824d209d2effc13f87d`, schema head `0067_service_catalog_monitoring_state`.
Run: `4e0b7d089b6e`, 2026-09-25T01:09:57Z → 01:11:19Z, recorded in [certification-run.v1.json](certification-run.v1.json).

```text
PRODUCTION_DATABASE_MUTATIONS=0
PROVIDER_EFFECTS=0
PRODUCTION_EFFECTS=0
RESIDUAL_RESOURCES=0
CHECKS: PASS=86 FAIL=10 BLOCKED=9
PAS95_DB18_VERDICT=FAIL          # RC defects reproduced (below); plus runtime-only items BLOCKED
PRODUCTION_TOUCHED=NO            # no production host, database, registry, secret or provider was contacted
```

The verdict is **not** a production go. The disposable topology behaves as designed: mTLS, role split, RLS,
schema head, receipts, exporter and the private DB API all work. The exact RC cannot yet be certified on
it: the repository defects under Findings stand in the way. Two high-severity ones are new (the backup
script and restore admission).

## How it was run

Only disposable local resources were used. [`scripts/certify_production_db_topology.py`](../../../scripts/certify_production_db_topology.py)
drives everything, with inputs in [`scripts/production_db_topology/`](../../../scripts/production_db_topology/):

1. **Release candidate.** The RC was built locally from the exact source (`Dockerfile.runtime --target runtime`)
   as `sha256:ac3f3219…20be0f`. It carries OCI revision `0606b0d`, user `65532:65532`, `amd64`, and a single
   Alembic head `0067_service_catalog_monitoring_state` (the `release.yml` probe). It is **not** the signed
   artifact; no signed RC exists (see Blocked).
2. **Server.** A disposable `postgres:17-bookworm` (17.11) ran on an **internal** Docker network with no
   egress, no published ports and a run label on every resource.
   * `ssl=on`, `ssl_min_protocol_version=TLSv1.2`, `password_encryption=scram-sha-256`.
   * [`pg_hba.conf`](../../../scripts/production_db_topology/pg_hba.conf): every login is
     `hostssl … scram-sha-256 clientcert=verify-full clientname=CN`. All other network paths are rejected,
     and the superuser gets a local socket only. This is the live staging class recorded by PAS-180,
     applied to the `codestra-middleware-production-v1` profile: host `postgresql.middleware-production.svc.cluster.local`,
     database `codestra_production`, role `middleware_production`.
3. **Per-run PKI.** Each run creates its own CA, a server certificate (SAN = profile host) and one
   CN-bound client certificate per role. It also creates a rogue-CA certificate and an expired
   certificate for the negative checks. All of it is destroyed at teardown.
4. **Roles.** [`bootstrap_roles.sql`](../../../scripts/production_db_topology/bootstrap_roles.sql) and
   [`grant_runtime.sql`](../../../scripts/production_db_topology/grant_runtime.sql) create:
   * `middleware_migration`: database/schema owner.
   * `middleware_production`, `middleware_worker`, `middleware_scheduler`, `middleware_reconciler`:
     DML via `middleware_runtime`.
   * `middleware_backup`: `pg_read_all_data`.
   * `postgres_exporter`: `pg_monitor`.
   * The migrations' grant roles `middleware_app`, `mw_*`, created `NOLOGIN` before migrating.

   None of these roles is superuser, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS.
5. **What the RC image did.** Each step ran as `65532` with a read-only root filesystem, `cap-drop ALL`,
   credentials mounted as files at the profile prefix `/run/secrets/middleware-production-*`, and the
   canary compose environment (36 effect flags `false`/`disabled`):
   * migrator ×2 plus `--verify-only`;
   * the locked-profile gate;
   * the connection matrix;
   * role isolation using the PAS-96/97 query from `d7ab51e`;
   * RLS;
   * both RC pools;
   * the canonical `/internal/v1/database` router (hosted bare, with the exception layer FastAPI installs) over a real mTLS pool.

   Every probe write ran inside a rolled-back transaction.
6. **Backup and restore.** `deploy/production/server/codestra-middleware-backup` ran from a root helper
   against the disposable server. It was then run again with a two-token correction (below). A
   role-based `pg_dump` was attempted as `middleware_backup`. Finally the dump was restored into a
   `--network none` server and the RC's `migrate_runtime --verify-only` was run against it.
7. **Exporter.** The pinned exporter `postgres-exporter@sha256:9fca39a4…` ran twice: over mTLS as
   `postgres_exporter`, and with the repository's as-shipped configuration. The repository alert
   conditions were evaluated from the scrape.
8. **Teardown.** All containers, volumes, the network and the PKI directory were removed; residual 0.

## Results by PAS-95 requirement

| Requirement | Status | Evidence (check ids) |
|---|---|---|
| Exact RC | PASS local / **BLOCKED** signed | `rc.source_revision`, `rc.single_alembic_head`, `rc.runtime_user`; `rc.signed_digest` |
| TLS | **FAIL** (RC config) | Server side PASS: plaintext, hostname mismatch and as-shipped compose DSN all rejected (`reject.*`). RC side FAIL: `profile.process_dsn_passes_its_own_profile` (F-01), `profile.compose_canary_requires_tls` (F-03) |
| mTLS | **FAIL** (RC config) | All 7 roles accepted over TLSv1.3 with `client_dn=/CN=<role>`. Rejected: no cert, cross-role CN, untrusted CA, expired, wrong password, superuser over network. `profile.admits_ca_and_client_certificate` FAIL (F-02): the locked profile refuses every DSN that can carry a client cert |
| Roles | PASS | All 6 non-owner roles `runtime_role_isolated=true`, `rls_bypass_possible=false`. The owner owns every object and cannot bypass FORCE RLS. The runtime role cannot CREATE, DROP, disable ledger triggers, drop FORCE RLS, set `session_replication_role`, `SET ROLE` the owner, DELETE or TRUNCATE the ledger, or run the migrator (`InsufficientPrivilegeError`). The repository's `mw_*` grants took effect once the roles were pre-created (PAS-78 F-05) |
| Schema head | PASS | `migration.apply_1`, `apply_2_idempotent` and `verify_only` each reported `RUNTIME_ALEMBIC_HEAD=0067_service_catalog_monitoring_state` and `RUNTIME_SCHEMA_VERIFIED=PASS`; history `sha256:c06b0231…` |
| Migration receipts | PASS readback / **FAIL** controller | Core `1..11`, automation `1`. The deploy controller still asserts `1..10` (PAS-27 F-07) |
| Pool | **FAIL** (2 of 6) | asyncpg 1–20/10 s bounded (21st acquire times out), all 20 sessions TLS. SQLAlchemy 8+4/5 s bounded. Budget 66 ≤ 97. FAIL: `application_name` empty (F-07); `statement_timeout`/`lock_timeout`/idle-in-tx all 0 (F-09) |
| RLS | PASS | 4 FORCE-RLS callback tables with policies. Tenant A sees 1 row; tenant B, an unscoped session and an unassigned agent each see 0. Cross-tenant insert rejected (42501). The schema owner sees 0 without scope |
| Backup evidence | **FAIL** | Repository script fails (F-A). The corrected copy passes: 217 tables, in-place restore rehearsal PASS, rehearsal DB dropped. Isolated restore gives table/row parity. RC `--verify-only` on the restored copy fails (F-B). The role-based dump fails (F-C). Off-host copy and PITR BLOCKED |
| Monitoring / alerts | PASS / **BLOCKED** routing | mTLS exporter `pg_up=1`, 390 metric families, both alert conditions quiet. The as-shipped exporter (`sslmode=disable`, `codestra_monitoring`) gets `pg_up=0`, so `CodestraPostgresDown` would fire at an mTLS cut-over (F-14/F-03) |
| Secret references | **FAIL** (1 of 5) | No generated secret appears in any container environment, API response or this evidence. Mounts sit under the profile prefix, file modes are 0400. FAIL: `DATABASE_URL_FILE` is not bound to the profile prefix (F-12) |
| Private DB APIs | PASS routes / **BLOCKED** auth | 16 routes 200 over the real mTLS pool. `readiness` is ready at head 0067 with `tls_required`/`tls_active`; `security/tls` reports verify-full on TLSv1.3; `client_certificate_configured=true`; `migrations/verify` is read-only. `apply`/`sql`/`query`/`restores` return 404, `DELETE backups` returns 405. Scopes are exactly `read` and `verify`. Backup/restore evidence is reflected faithfully. `/security/roles` is absent until PR #327 lands; the real token verifier is BLOCKED |
| Effects | PASS | Internal network, all connection targets disposable, 36 canary flags off. Row counts across 217 tables were unchanged from the post-migration baseline. Only the migration-seeded `social_providers` (2 rows) is non-empty among effect-named tables |

## Findings

New in this lane. Each is recorded here and fixed nowhere; each needs its own governed change.

| ID | Severity | Finding | Owner lane |
|---|---|---|---|
| **F-A** | High | `deploy/production/server/codestra-middleware-backup:103,122` pass `-` to `pg_restore`. PostgreSQL 14, 16 and 17 open it as a file named `-` (`could not open input file "-"`), so the script always stops at `backup_catalog_invalid`. Because `codestra-middleware-deploy:485` runs it before migrating, **every controller-driven deploy aborts** at `backup_or_restore_rehearsal_failed`. Removing the two `-` tokens makes it pass. Pinned by strict xfail `test_backup_script_reads_the_dump_from_stdin` | Release/deploy owner (trust-covered file) |
| **F-B** | High | A logical dump/restore re-deparses varchar `IN (…)` CHECK constraints (`ANY ((ARRAY[…])::text[])` becomes `ANY (ARRAY[(…)::text, …])`). The two forms are semantically identical, but `scripts/runtime_sql_schema.py` hashes the `pg_get_constraintdef` text. The restored copy therefore fails the RC's own admission (`SchemaDriftError` in `campaign_design_current`, `campaign_design_failure`, `campaign_design_revision`, `campaign_event_inbox`). **Restore-based recovery cannot pass `migrate_runtime` or the deploy controller.** Bears directly on PAS-92 | Schema-contract owner / PAS-92 |
| **F-C** | Medium | `pg_dump` as a least-privilege backup role (`pg_read_all_data`, NOBYPASSRLS) fails on FORCE-RLS tables (`query would be affected by row-level security policy`). The only working backup identity is the local `postgres` superuser (extends PAS-78 F-13). A production backup role needs BYPASSRLS by explicit owner decision | Backup/DR owner |
| F-D (host) | Info | This host's snap Docker refuses `exec` under `--security-opt no-new-privileges:true`. That one canary flag was omitted locally; all other hardening flags were applied. Not an RC defect | — |

Reproduced from PAS-78 (`origin/pas-78/db-path-evidence-map-20260924`, PR #328), now on a running topology:

* **F-01**: process DSN rewritten to `+asyncpg`, which then fails its own profile.
* **F-02**: no client-certificate or CA path through the locked profile.
* **F-03**: the compose canary profile is plaintext-only.
* **F-05**: grant roles are not provisioned; the grants work once they are.
* **F-07**: no `application_name`.
* **F-09**: no statement/lock timeouts.
* **F-12**: `DATABASE_URL_FILE` is not bound to the profile prefix.
* **F-13**: superuser-only backups, no PITR.
* **F-14**: exporter identity and TLS.

Also reproduced: PAS-27 **F-07**, receipts `1..10` vs `1..11`.

PAS-78 **F-04** (migrator and runtime share one role) is shown to be *solvable*: with the split roles
the runtime role cannot migrate, own objects, or disable the append-only triggers or FORCE RLS. The
repository still has no role-provisioning authority to enforce this; these bootstrap files are
certification input only.

## Blocked (runtime-only; not attempted)

| Item | Why |
|---|---|
| Signed RC digest (cosign/SLSA/SBOM) | PAS-27: no successful release run. `35613442378` (`0606b0d`) never started (Actions billing lock); `35602170321` failed at push (`read_package`) |
| Live production readback: server version, pg_hba, certificate fingerprints/expiry, role attributes | Needs the production host; this lane does not touch production |
| Real production backup restore, Middleware start, TEST_SYN | PAS-92 (in progress) |
| Restart / failure / connection chaos, certificate rotation | PAS-94 (not started) |
| Prometheus evaluation and Alertmanager routing on the live plane | Needs the live monitoring stack |
| Private DB API behind the real Keycloak verifier and private edge | Needs the production identity provider. The router ran with a recording verifier; scopes were asserted |
| Off-host backup copy, PITR | Host decision / PAS-78 F-13 |
| `/internal/v1/database/security/roles` | PR #327 (PAS-96/97) not merged; its query ran directly |

## Reproduce

```bash
git checkout 0606b0db9ff59802f8da3824d209d2effc13f87d   # or this branch
docker build -f Dockerfile.runtime --target runtime \
  --build-arg SOURCE_REVISION=$(git rev-parse HEAD) --build-arg SOURCE_VERSION=sha-$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=2026-09-24T00:00:00Z -t codestra-middleware:pas95-rc-0606b0d .
docker pull docker.io/prometheuscommunity/postgres-exporter@sha256:9fca39a4307092387b7de884bed4b62205cb88a6a5fdb423b9a70ea80b34efb3
printf 'FROM docker:29-cli\nRUN apk add --no-cache bash coreutils util-linux gawk\n' \
  | docker build -t pas95-backup-helper:local -
python3 scripts/certify_production_db_topology.py --rc-image codestra-middleware:pas95-rc-0606b0d \
  --output docs/evidence/pas95-production-db-topology-20260924/certification-run.v1.json
pytest tests/test_production_db_topology_certification.py            # static + evidence
PAS95_LIVE_DB_TOPOLOGY=1 PAS95_RC_IMAGE=codestra-middleware:pas95-rc-0606b0d \
  pytest tests/test_production_db_topology_certification.py -k live  # disposable live run
```

The harness refuses to start in these cases:
* `DOCKER_HOST` is not a local unix socket.
* Any of `DATABASE_URL`, `DATABASE_URL_FILE`, `PGHOST`, `PGPASSWORD` or `PGSERVICE` is set.
* A connection target is not one of its own resources.

Before writing, it scans the evidence for its generated passwords, DSNs and keys. The backup helper is
given the local Docker socket because the repository script operates through `docker exec`. It only
targets the run's own container.

## Merge note

This change adds tracked files, so `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256` for
`ingtrader21-spec/Middleware-` moves (PAS-27 07). Following the PAS-78 and PAS-180 precedent, this lane
does not edit `.codestra/`. The merging PR must run `scripts/derive_trust_pins.py --apply-candidate` on
the final head.
