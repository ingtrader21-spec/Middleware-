# PAS-180 — Read-only readback commands (Server 1)

Purpose: resolve every `LIVE_READBACK_PENDING` field in `README.md` and satisfy
gate P0.4 of `execution-plan.md`. Every command below is read-only: no `docker
start/stop/rm/pull`, no SQL other than `SELECT`/`SHOW`, no file writes outside
`/root/pas180-readback/`. Secrets are never printed (`stat` only).

Run as root on `65.109.65.169`; keep output in
`/root/pas180-readback/$(date -u +%Y%m%dT%H%M%SZ).txt` (mode 0600). Replace the
values in the packet only from this output.

```bash
set -Eeuo pipefail
umask 077
OUT=/root/pas180-readback; install -d -m 0700 "$OUT"
PG=codestra-middleware-staging-postgres-1
DB=middleware_staging
```

## 1. Staging Compose inventory (fills §1.2 image/containers, P0.4, P0.5)

```bash
docker compose ls
docker ps -a --filter label=com.docker.compose.project=codestra-middleware-staging \
  --format 'table {{.Names}}\t{{.Label "com.docker.compose.service"}}\t{{.Image}}\t{{.Status}}'
for c in $(docker ps -a --filter label=com.docker.compose.project=codestra-middleware-staging -q); do
  docker inspect "$c" --format \
'NAME={{.Name}} IMAGE={{.Config.Image}} IMAGE_ID={{.Image}} STATUS={{.State.Status}} EXIT={{.State.ExitCode}} OOM={{.State.OOMKilled}} FINISHED={{.State.FinishedAt}} RESTARTS={{.RestartCount}} HEALTH={{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}} REV={{index .Config.Labels "org.opencontainers.image.revision"}} CONFIG={{index .Config.Labels "com.docker.compose.project.config_files"}} WD={{index .Config.Labels "com.docker.compose.project.working_dir"}}'
done
# Legacy image IDs must match the packet (b81c1252…, 57a4a3a2…, ed7accf6…, dc97c48f…, 8e4a1afa…)
docker images --digests --no-trunc --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Digest}}' | grep -E '^codestra/middleware:'
```

Optional, repository-owned equivalent (prints only non-secret facts):

```bash
sudo env MIDDLEWARE_CONTAINER=codestra-middleware-staging-middleware-staging-1 \
  bash /srv/codestra-middleware/repository/scripts/discover_middleware_runtime.sh
```

Optional, repository-owned provenance trace for the legacy revision (read-only:
never queries the database, never changes containers; works on the stopped API
container because it only uses `docker inspect`/filesystem export):

```bash
sudo env MIDDLEWARE_CONTAINER=codestra-middleware-staging-middleware-staging-1   MIGRATION_REVISION=0058_odoo_delivery_sources OUTPUT_DIR="$OUT/provenance-0058"   bash /srv/codestra-middleware/repository/scripts/collect_staging_migration_evidence.sh
```

## 2. Exit cause of the ~11:20Z app-plane stop (P0.5, F-09)

```bash
journalctl -k --since '2026-09-21 11:00' --until '2026-09-21 11:40' --no-pager | grep -iE 'oom|killed process|out of memory' || echo NO_KERNEL_OOM_LINES
journalctl -u docker --since '2026-09-21 11:00' --until '2026-09-21 11:40' --no-pager | tail -50
free -m; df -h /var/lib/docker /opt/codestra
```

## 3. Canonical database readback (fills CURRENT_STAGING_DB_*, roles; P0.4, P0.6)

```bash
docker inspect "$PG" --format 'PG_IMAGE={{.Config.Image}} PG_IMAGE_ID={{.Image}} STATUS={{.State.Status}} HEALTH={{if .State.Health}}{{.State.Health.Status}}{{end}}'
docker inspect "$PG" --format '{{range .Mounts}}{{printf "%s\t%s -> %s\tRW=%t\n" .Type .Source .Destination .RW}}{{end}}'
docker inspect "$PG" --format '{{range $n,$v := .NetworkSettings.Networks}}{{printf "%s\t%s\n" $n $v.IPAddress}}{{end}}'
Q() { docker exec -u postgres "$PG" psql -X -v ON_ERROR_STOP=1 --dbname="$DB" --tuples-only --no-align --command="$1"; }
Q "select current_database(), version()"
Q "select string_agg(version_num, ',' order by version_num) from public.alembic_version"        # expect 0058_odoo_delivery_sources
Q "select character_maximum_length from information_schema.columns where table_name='alembic_version' and column_name='version_num'"
Q "select to_regclass('public.middleware_schema_migrations') is not null"                       # expect f on legacy
Q "select count(*) from odoo_result_delivery"; Q "select count(*) from integration_event"; Q "select count(*) from outbox_event"
Q "select endpoint_id from integration_endpoint where endpoint_key='odoo.provider_activities.create' order by 1"   # expect 55000000-0000-4000-8000-000000000021
Q "select pg_get_constraintdef(oid) from pg_constraint where conname='ck_odoo_result_delivery_one_source'"
Q "select rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin from pg_roles where rolname !~ '^pg_' order by 1"
Q "select datname, usename, application_name, ssl.ssl from pg_stat_activity a left join pg_stat_ssl ssl using (pid) where datname='$DB' and pid<>pg_backend_pid()"   # expect no rows while the app plane is down
Q "select pg_database_size('$DB')"
```

## 4. TLS state (fills CURRENT_STAGING_DB_TLS, POSTGRES_* readiness; P0.8)

```bash
Q "show ssl"; Q "show ssl_cert_file"; Q "show ssl_key_file"; Q "show ssl_ca_file"; Q "show ssl_min_protocol_version"
Q "show hba_file"; Q "show data_directory"
docker exec -u postgres "$PG" sh -c 'grep -vE "^\s*(#|$)" "$(psql -X -At -c "show hba_file")"'    # rules only, no secrets
for f in "$(Q 'show ssl_cert_file')" "$(Q 'show ssl_ca_file')"; do
  docker exec -u postgres "$PG" sh -c "test -f '$f' && openssl x509 -in '$f' -noout -subject -issuer -dates -ext subjectAltName -fingerprint -sha256 || echo 'ABSENT $f'"
done
docker exec -u postgres "$PG" sh -c 'k="$(psql -X -At -c "show ssl_key_file")"; test -f "$k" && stat -c "KEY %U %a %n" "$k" || echo "ABSENT $k"'
# Host-side client material (existence/owner/mode only — never cat):
for p in /etc/codestra/secrets/middleware-staging/db /etc/codestra/secrets/middleware-runtime /etc/codestra/pki; do
  [ -e "$p" ] && find "$p" -maxdepth 2 -printf '%M %u:%g %p\n' || echo "ABSENT $p"
done
```

## 5. Recorded snapshot digest (fills RECORDED_SNAPSHOT_DIGEST)

```bash
ls -la /opt/codestra/backups/middleware-db-reconcile/20260920T212950Z/
cat /opt/codestra/backups/middleware-db-reconcile/20260920T212950Z/SHA256SUMS
( cd /opt/codestra/backups/middleware-db-reconcile/20260920T212950Z && sha256sum -c SHA256SUMS )
```

## 6. Secret references and env files (P0.7 — `stat` only)

```bash
for p in /opt/codestra/env/middleware.env /etc/codestra-middleware/runtime.env /etc/codestra-middleware/deploy.conf \
         /etc/codestra/secrets/codestra-compose/redis_url /etc/codestra/secrets/codestra-compose/middleware_secret \
         /etc/codestra/secrets/codestra-compose/webhook_shared_secret \
         /etc/codestra/secrets/middleware-runtime/middleware-integration-api-database-url \
         /etc/codestra/secrets/middleware-runtime/middleware-notification-worker-database-url \
         /etc/codestra/secrets/middleware-runtime/middleware-scheduler-database-url \
         /etc/codestra/secrets/middleware-runtime/middleware-reconciliation-worker-database-url; do
  if [ -L "$p" ]; then echo "SYMLINK $p"; elif [ -e "$p" ]; then stat -c '%A %U:%G %n' "$p"; else echo "ABSENT $p"; fi
done
```

## 7. Isolated PAS-102 candidate (record only; must not be promoted)

```bash
docker ps -a --filter name=middleware-pas102 --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker exec -u postgres middleware-pas102-staging-db psql -X -At -c 'show ssl' -c 'select version_num from alembic_version' 2>/dev/null || echo PAS102_DB_NOT_REACHABLE
```

## 8. Deploy controller / backup tool identity (F-07 evidence)

```bash
sha256sum /usr/local/sbin/codestra-middleware-deploy /usr/local/sbin/codestra-middleware-backup 2>/dev/null || echo CONTROLLER_NOT_INSTALLED
grep -n '1,2,3,4,5,6,7,8,9,10' /usr/local/sbin/codestra-middleware-deploy 2>/dev/null || echo PIN_LINE_NOT_FOUND
```

Record `READBACK_TIMESTAMP`, `READBACK_OPERATOR`, and attach the output file
reference (not the content, if it contains hostnames you consider sensitive) to
PAS-180. If §3 shows a head other than `0058_odoo_delivery_sources`, or §4 shows
`ssl=on`, the packet's "current state" is stale: stop and re-baseline before P1.
