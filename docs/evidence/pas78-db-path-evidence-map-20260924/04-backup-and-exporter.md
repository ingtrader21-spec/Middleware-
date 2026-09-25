# 04 — Backup tooling, superuser shell paths, postgres-exporter

## 1. Backup and restore

| Tool | Location | Identity / transport | Scope |
| --- | --- | --- | --- |
| Pre-migration backup | `deploy/production/server/codestra-middleware-backup:92-135`, called from `codestra-middleware-deploy:484-490` | root → `docker exec -u postgres` (peer auth; no DSN, no TLS) | `pg_dump --format=custom --compress=9 --no-owner --no-acl --dbname=$POSTGRES_DATABASE` (`codestra_middleware_appolon`); `pg_restore --list`; restore rehearsal into `mw_restore_<ts>` with `createdb`, `pg_restore`, `psql` checks, then `dropdb`. Output `/var/backups/codestra-middleware*`, mode 0600, sha256 digest. Off-host copy optional |
| Scheduled off-server backup | `deploy/scraper/scraper-middleware-offserver.sh:30-56`, timer 04:15 UTC (`codestra-scraper-middleware-backup.timer:5`) | `docker exec codestra-postgres-1 pg_dump -U postgres` | **hard-coded `codestra_middleware`** (F-13); gpg-encrypted; scp to `codestra-vicidial` with remote sha256 verification |
| CI rehearsal | `.github/workflows/required-ci.yml:251-266`; connector `test_postgres.sh:74-102` | disposable CI service | dump / restore / verify |
| Deployment validator | `scripts/validate_production_runtime_deployment.py:249` | static | requires `pg_dump`, `pg_restore`, `createdb`, `dropdb`, `RESTORE_STATUS=PASS` |
| `make backup` | `Makefile:21-22` | — | tars the **source tree**, not the database |

**Absent:** `pg_basebackup`, WAL archiving (`archive_command`), wal-g, pgBackRest, barman, point-in-time
recovery. Backups are logical dumps only.

## 2. Superuser shell paths (outside the application roles)

`deploy/production/server/codestra-middleware-deploy` reads back the following with
`docker exec -u postgres … psql -X -v ON_ERROR_STOP=1`:
- `middleware_schema_migrations` (`:506-510`)
- `public.alembic_version` (`:514-518`)
- `middleware_automation_schema_migrations` (`:520-524`)
- the four `platform_*` tables (`:526-530`)
- per-table row-count snapshots (`:533-552`), where table names are regex-checked before interpolation

These paths use the database superuser over the container's local socket. They never go through
`DATABASE_URL` or the runtime role.

## 3. postgres-exporter

| Item | Value | Evidence |
| --- | --- | --- |
| Image | `prometheuscommunity/postgres-exporter@sha256:9fca39a4…` | `deploy/monitoring/odoo-readiness/compose.yaml:3` |
| DSN | `DATA_SOURCE_URI=codestra-postgres-1:5432/postgres?sslmode=disable` | `:5` (pinned by `test_exporter_target.py:9`) |
| Role | `DATA_SOURCE_USER=codestra_monitoring`. **Not created and not granted `pg_monitor` anywhere in the repo** | `:6` |
| Secret | `DATA_SOURCE_PASS_FILE=/run/secrets/postgres_monitoring_password` | `:7,54` |
| Scrape and rules | `postgres-exporter:9187`; `pg_up`, `pg_stat_database_numbackends` | `prometheus.yml:19`, `rules/odoo-readiness.rules.yml:15,20` |
| Inventory | listed as "unverified" | `integrated-monitoring-inventory.json:557-565,801-806`; no postgres entry in `monitoring-integration.v1.json` |
| Divergent design | OpenBao-rendered `DATA_SOURCE_*_FILE` under `observability/exporters/postgres/monitoring-role`, with gate status NOT_DEPLOYED | `docs/evidence/monitoring-openbao-integration-20260916/EXPORTERS.md:8`, `docs/evidence/monitoring-openbao-runtime-20260917/FINAL-GATE.md:31` |
| App-side probe | `pg_up` in the collector | `app/monitoring/collector.py:53,60` |
