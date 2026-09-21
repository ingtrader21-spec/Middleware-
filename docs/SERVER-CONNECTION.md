# Connect Application Server A to the middleware repository

## Server and repository

```text
Server: 65.109.65.169
Role: Codestra Application Server A
Repository: ingtrader21-spec/Middleware-
Read-only checkout: /srv/codestra-middleware/repository
Deployment account: middleware-deploy
```

The middleware shares this host with Odoo, n8n, PostgreSQL, Redis, Keycloak, Caddy, Kong, and related Codestra services. Discovery and deployment must target the exact middleware Compose project and service names. Never restart the entire Docker host or a shared Compose project merely to deploy this application.

## Mandatory safety boundary

The repository is currently public. Change it to **private** before importing live source or operational configuration.

Git may contain application code, workers, migrations, tests, Dockerfiles, non-secret Compose templates, workflow exports without credentials, and operational documentation. Keep these outside Git:

- live `.env` or Compose override files;
- database, Redis, outbox, inbox, queue, dead-letter, webhook, or customer data;
- Keycloak, Odoo, n8n, VICIdial, Kong, Caddy, SMS, email, provider, or database credentials;
- private keys, private-key bundles, and live certificates;
- production logs, packet captures, backups, and secret-bearing evidence.

A Git rollback cannot reverse a database migration, an externally delivered event, or a consumed queue message. Data-changing releases require matching recovery points and tested rollback procedures.

## Intended GitOps flow

```text
feature branch
  -> pull request
  -> locked dependency install
  -> lint, type, unit, integration, migration, security, and container tests
  -> merge protected main
  -> build image once for exact commit SHA
  -> publish immutable image digest
  -> deploy digest to staging with all external writes disabled
  -> run smoke, replay, idempotency, integration, and rollback tests
  -> explicit production approval
  -> deploy the identical accepted image digest to production
```

Do not deploy a mutable branch, `latest` tag, locally edited checkout, or image rebuilt after staging acceptance.

## 1. Make the repository private

In GitHub:

```text
Middleware- -> Settings -> General -> Danger Zone
-> Change repository visibility -> Make private
```

Do this before importing the live middleware source.

## 2. Create a separate read-only deploy key

GitHub deploy keys are repository-specific. Do not reuse the Odoo repository deploy key.

Run on Application Server A:

```bash
ssh root@65.109.65.169
set -Eeuo pipefail

id middleware-deploy >/dev/null 2>&1 || \
  useradd --system --create-home --shell /bin/bash middleware-deploy

install -d \
  -m 0700 \
  -o middleware-deploy \
  -g middleware-deploy \
  /home/middleware-deploy/.ssh

if [[ ! -f /home/middleware-deploy/.ssh/github_middleware_readonly ]]; then
  sudo -u middleware-deploy -H ssh-keygen \
    -t ed25519 \
    -C "middleware-deploy@$(hostname)" \
    -f /home/middleware-deploy/.ssh/github_middleware_readonly \
    -N ''
fi

printf '\n===== ADD THIS PUBLIC KEY TO THE MIDDLEWARE REPOSITORY =====\n'
cat /home/middleware-deploy/.ssh/github_middleware_readonly.pub
```

In GitHub:

```text
Middleware- -> Settings -> Deploy keys -> Add deploy key
Title: Codestra Middleware Application Server A
Allow write access: leave unchecked
```

Create a dedicated SSH alias:

```bash
cat >/home/middleware-deploy/.ssh/config <<'EOF'
Host github-middleware
  HostName github.com
  User git
  IdentityFile /home/middleware-deploy/.ssh/github_middleware_readonly
  IdentitiesOnly yes
EOF

chown middleware-deploy:middleware-deploy \
  /home/middleware-deploy/.ssh/config
chmod 0600 /home/middleware-deploy/.ssh/config
```

Capture GitHub's host key and compare its fingerprint with GitHub's officially published SSH fingerprints before installing it:

```bash
ssh-keyscan -t ed25519 github.com 2>/dev/null \
  > /tmp/github-middleware-ed25519-known-host
ssh-keygen -lf /tmp/github-middleware-ed25519-known-host
```

After verifying the fingerprint:

```bash
install \
  -m 0600 \
  -o middleware-deploy \
  -g middleware-deploy \
  /tmp/github-middleware-ed25519-known-host \
  /home/middleware-deploy/.ssh/known_hosts
rm -f /tmp/github-middleware-ed25519-known-host

sudo -u middleware-deploy -H git ls-remote \
  git@github-middleware:ingtrader21-spec/Middleware-.git HEAD
```

Do not add `middleware-deploy` to the `docker` group. Docker access is effectively root access. Future automation should invoke one root-owned, allowlisted deployment command through tightly restricted `sudo`.

## 3. Clone the read-only server checkout

```bash
install -d \
  -m 0750 \
  -o middleware-deploy \
  -g middleware-deploy \
  /srv/codestra-middleware

sudo -u middleware-deploy -H git clone \
  git@github-middleware:ingtrader21-spec/Middleware-.git \
  /srv/codestra-middleware/repository

sudo -u middleware-deploy -H \
  git -C /srv/codestra-middleware/repository status --short
sudo -u middleware-deploy -H \
  git -C /srv/codestra-middleware/repository rev-parse HEAD
```

This checkout is a deployment input, not a place for manual production editing. Its deploy key must remain read-only.

## 4. Discover the live runtime without changing it

Run the included read-only inventory:

```bash
sudo bash \
  /srv/codestra-middleware/repository/scripts/discover_middleware_runtime.sh \
  | tee /root/middleware-git-discovery.txt
```

When automatic selection finds the wrong container, specify the exact running middleware container:

```bash
sudo env MIDDLEWARE_CONTAINER=<exact_container_name_or_id> bash \
  /srv/codestra-middleware/repository/scripts/discover_middleware_runtime.sh \
  | tee /root/middleware-git-discovery.txt
```

The report records only non-secret runtime facts:

- middleware container name, image, image ID, and repository digest;
- Compose project, service, working directory, and configuration files;
- source/config/data mounts and whether each is writable;
- published ports and container networks;
- health, restart count, container user, privileged mode, and read-only root filesystem state;
- an allowlist of non-secret safety flags;
- related Odoo, n8n, PostgreSQL, Redis, Keycloak, Kong, Caddy, callback, and worker containers.

It does not print the full container environment or read database passwords.

Record at minimum:

```text
MIDDLEWARE_CONTAINER_NAME=
MIDDLEWARE_IMAGE=
MIDDLEWARE_IMAGE_DIGEST=
COMPOSE_PROJECT=
COMPOSE_SERVICE=
COMPOSE_WORKING_DIR=
COMPOSE_CONFIG_FILES=
SOURCE_OR_BUILD_CONTEXT=
DATABASE_SERVICE=
REDIS_SERVICE=
WORKER_SERVICES=
CALLBACK_SERVICE=
HEALTH_ENDPOINT=
CURRENT_SAFE_FLAG_NAMES=
```

Do not alter mounts, images, Compose files, or service names until these values are confirmed.

## 5. Import the authoritative source without giving production Git write access

The production server should not push branches. Use one of these paths:

1. **Preferred:** import the authoritative source from a trusted development machine that already has GitHub write access.
2. **Source exists only on the server:** create a sanitized, read-only export on the server, transfer it to the trusted development machine, and open the import pull request there.

Do not add a write-enabled deploy key or a broad GitHub personal token to the production server.

### 5.1 Create a sanitized server export

Identify the verified host source directory or image build context from the discovery report. Prefer the host source tree used to build the running image. Do not treat a container filesystem as authoritative unless no source tree exists and the export is independently reviewed.

```bash
set -Eeuo pipefail

export EXISTING_SOURCE=/actual/verified/middleware/source
export EXPORT_DIR=/root/codestra-middleware-source-export
export EXPORT_ARCHIVE=/root/codestra-middleware-source-export.tar.gz

rm -rf "$EXPORT_DIR" "$EXPORT_ARCHIVE"
install -d -m 0700 "$EXPORT_DIR"

rsync -a \
  --delete \
  --exclude='.git/' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='*.env' \
  --exclude='*.env.*' \
  --exclude='secrets/' \
  --exclude='credentials/' \
  --exclude='__pycache__/' \
  --exclude='.venv/' \
  --exclude='venv/' \
  --exclude='node_modules/' \
  --exclude='logs/' \
  --exclude='runtime/' \
  --exclude='backups/' \
  --exclude='*.log' \
  --exclude='*.dump' \
  --exclude='*.backup' \
  --exclude='*.sql.gz' \
  --exclude='*.sql.zst' \
  --exclude='*.sqlite*' \
  --exclude='*.rdb' \
  --exclude='*.aof' \
  --exclude='*.key' \
  --exclude='*.p12' \
  --exclude='*.pfx' \
  --exclude='*.jks' \
  --exclude='*.keystore' \
  --exclude='*.har' \
  --exclude='*.pcap' \
  --exclude='*.trace' \
  "$EXISTING_SOURCE"/ "$EXPORT_DIR"/
```

Review the exported file list before creating an archive:

```bash
find "$EXPORT_DIR" -type f -printf '%P\n' | sort \
grep -RIl --binary-files=without-match \
  -E 'BEGIN ([A-Z]+ )?PRIVATE KEY|github_pat_|gh[pousr]_[A-Za-z0-9]{30,}|(AKIA|ASIA)[0-9A-Z]{16}' \
  "$EXPORT_DIR" || true
```

A matching line is a stop condition requiring manual review and removal. This grep is only a basic preflight; the development import must run a dedicated secret scanner.

Create a deterministic archive and checksum:

```bash
tar \
  --sort=name \
  --mtime='UTC 1970-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$EXPORT_DIR" \
  -czf "$EXPORT_ARCHIVE" .

sha256sum "$EXPORT_ARCHIVE" \
  | tee "${EXPORT_ARCHIVE}.sha256"
chmod 0600 "$EXPORT_ARCHIVE" "${EXPORT_ARCHIVE}.sha256"
```

Transfer the archive over an authenticated channel to the trusted development machine. Delete the temporary server export only after the imported pull request is safely created and independently checked.

### 5.2 Create the import branch on the trusted development machine

```bash
set -Eeuo pipefail

export ARCHIVE=./codestra-middleware-source-export.tar.gz
export WORKTREE=./codestra-middleware-import

rm -rf "$WORKTREE"
git clone git@github.com:ingtrader21-spec/Middleware-.git "$WORKTREE"
tar -xzf "$ARCHIVE" -C "$WORKTREE"

cd "$WORKTREE"
git switch -c import/live-middleware-baseline
bash scripts/run_ci.sh
git status --short
```

Review every imported file. Search for embedded credentials, private URLs containing passwords, webhook samples, production payloads, customer data, TLS material, and generated artifacts. Add a dedicated secret scanner and the actual locked dependency/test pipeline in this same import pull request.

The source import pull request must identify:

- application framework and runtime version;
- API, worker, scheduler, and callback entry points;
- package manager and lock files;
- migration framework and current migration head;
- PostgreSQL and Redis responsibilities;
- outbox, inbox, idempotency, retry, replay, and dead-letter behavior;
- Keycloak/OIDC, Odoo, n8n, VICIdial, Kong/Caddy, SMS, email, and webhook integrations;
- health/readiness endpoints;
- external-write and kill-switch controls;
- tests that pass and tests still missing.

## 6. Replace the bootstrap test hook

The bootstrap workflow runs `scripts/run_ci.sh`. The source import must add an executable:

```text
scripts/project_ci.sh
```

It must use the repository's locked dependency mechanism and run, as applicable:

```text
format/lint check
static type checking
unit tests
PostgreSQL integration tests
Redis/queue integration tests
migration upgrade and rollback tests
outbox/inbox, retry, lease, idempotency, replay, and dead-letter tests
cross-tenant and authorization tests
webhook signature, timestamp, replay, and deduplication tests
Odoo/n8n/VICIdial adapter contract tests
container build, health, readiness, and graceful-shutdown tests
secret, dependency, and container vulnerability scans
```

Do not silently skip unavailable services. Report unsupported or missing test categories explicitly.

## 7. Keep runtime secrets outside Git

Use a dedicated secret manager or root-readable server files, for example:

```text
/etc/codestra-middleware/runtime.env
/etc/codestra-middleware/credentials/
/etc/codestra-middleware/tls/
```

Recommended ownership and permissions:

```text
root:root
runtime.env: 0600
credential files: 0600
credential directories: 0700
```

The repository may contain `.env.example` files with variable names and safe placeholders, never live values.

## 8. Stage with fail-closed capabilities

`config/preproduction-safety.env.example` is a control baseline, not proof that the current application recognizes every variable. Map it to the actual code and add startup validation that fails closed when required controls are missing or malformed.

At staging startup, externally effective behavior must remain disabled:

```text
SEND_EVENTS=false
ENABLE_EXTERNAL_DELIVERY=false
LIVE_WRITE=false
LIVE_WRITES=false
ODOO_WRITE=false
CALLBACK_DISPATCH=false
N8N_DELIVERY_ENABLED=false
VICIDIAL_WRITES_ENABLED=false
EXTERNAL_DIAL_ENABLED=false
PRODUCTION_CALLBACKS_ENABLED=false
N8N_PRODUCTION_WORKFLOWS_ENABLED=false
PRODUCTION_DIALING=DISABLED
```

Verify effective values from the running staging container. Do not accept an example file as runtime evidence.

## 9. Build once and deploy an immutable image

The production target is:

```text
reviewed commit SHA
  -> GitHub-hosted CI build
  -> tests and scans
  -> GHCR image digest
  -> staging deployment by digest
  -> accepted digest
  -> production deployment of the same digest
```

A production Compose template should require a digest-bearing value:

```yaml
services:
  middleware:
    image: ${MIDDLEWARE_IMAGE:?set immutable image digest}
    env_file:
      - /etc/codestra-middleware/runtime.env
```

The deployed value should resemble:

```text
ghcr.io/ingtrader21-spec/codestra-middleware@sha256:<digest>
```

Do not use `latest`, an unpinned branch tag, or an image rebuilt separately after staging acceptance.

## 10. Scope deployment on the shared server

After discovery confirms the Compose directory and service names, use service-scoped commands:

```bash
cd <COMPOSE_WORKING_DIR>

docker compose \
  -f <CONFIRMED_COMPOSE_FILE> \
  pull <MIDDLEWARE_SERVICE> <WORKER_SERVICES>

docker compose \
  -f <CONFIRMED_COMPOSE_FILE> \
  up -d --no-deps <MIDDLEWARE_SERVICE> <WORKER_SERVICES>
```

Do not run broad commands such as:

```bash
docker compose down
docker system prune -a
docker restart $(docker ps -q)
```

Those commands can interrupt unrelated Odoo, n8n, PostgreSQL, Redis, Keycloak, Caddy, Kong, and provider services.

## 11. Minimum staging evidence

Before production approval, capture evidence tied to the exact commit SHA and image digest:

- clean repository and exact SHA;
- immutable digest and build provenance;
- database backup/restore and migration rollback;
- Redis/outbox/inbox recovery behavior;
- API health and readiness;
- authentication, authorization, and tenant isolation;
- idempotency and duplicate-request handling;
- webhook signature, timestamp, replay, and deduplication controls;
- Odoo and n8n duplicate-delivery behavior;
- VICIdial write denial while disabled;
- external delivery and dialing denial while disabled;
- worker retry, lease expiry, dead-letter, and replay behavior;
- Kong/Caddy routing, TLS, mTLS, rate limits, and allowlists;
- rollback to the prior image and matching data recovery point.

## 12. GitHub deployment automation

Use a GitHub-hosted runner that connects to a restricted server account and invokes one root-owned deployment command. Do not install a general-purpose self-hosted Actions runner on this shared production server.

Separate staging and production GitHub environments. Typical environment secrets are:

```text
MIDDLEWARE_DEPLOY_HOST
MIDDLEWARE_DEPLOY_PORT
MIDDLEWARE_DEPLOY_USER
MIDDLEWARE_DEPLOY_SSH_KEY
MIDDLEWARE_DEPLOY_HOST_KEY
MIDDLEWARE_GHCR_READ_TOKEN
```

Keep application and integration credentials on the server or in a dedicated secret manager, not in workflow YAML. Protect production with exact-head automated CI, signed immutable release evidence, the repository-controlled production admission workflow, and deployment only from protected `main`. Human reviews remain available but are not mandatory.
