# Server A Git synchronization

Target host: `65.109.65.169`

Repository: `ingtrader21-spec/Middleware-`

This runbook synchronizes reviewed Git metadata, contracts, route inventory, and operational discovery scripts to Server A. It does not activate contract-only middleware APIs and does not change the working Caddy/Keycloak runtime path.

## Preconditions

Require all of the following before synchronizing `main`:

```text
PR_CI=PASS
PR_REVIEW=PASS
MERGED_MAIN_SHA=KNOWN
SERVER_WORKTREE_CLEAN=PASS
AUTH_PUBLIC_OPENID_DISCOVERY=HTTP_200
AUTH_PUBLIC_TLS_VERIFY=0
AUTH_ISSUER=https://auth.codestra.co/realms/codestra
```

The verified auth topology is:

```text
auth.codestra.co
 -> host Caddy on 65.109.65.169
 -> 127.0.0.1:18103
 -> codestra-caddy-upstream-gateway
 -> codestra-identity-keycloak-1:8080
```

No Caddy reload or Keycloak restart is required for a Git-only synchronization when this path remains healthy.

## Server checkout

Preferred checkout:

```text
/srv/codestra-middleware/repository
```

If the checkout does not exist, clone it with the repository-specific Middleware deploy key. Do not reuse Odoo or Keycloak deploy keys.

## Exact merged-SHA synchronization

From a root/operator shell on Server A:

```bash
set -Eeuo pipefail
REPO=/srv/codestra-middleware/repository
DEPLOY_USER=middleware-deploy

test -d "$REPO/.git"

test -z "$(git -C "$REPO" status --porcelain)" || {
  echo 'ERROR=SERVER_WORKTREE_NOT_CLEAN' >&2
  exit 1
}

runuser -u "$DEPLOY_USER" -- \
  env HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)" \
  git -C "$REPO" fetch --prune origin

runuser -u "$DEPLOY_USER" -- \
  env HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)" \
  git -C "$REPO" checkout main

runuser -u "$DEPLOY_USER" -- \
  env HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)" \
  git -C "$REPO" pull --ff-only origin main

git -C "$REPO" rev-parse HEAD
```

Compare the resulting SHA to the exact reviewed merged `main` SHA. A mismatch is a hard stop.

## Post-sync validation

Run repository validation from the synchronized checkout:

```bash
cd /srv/codestra-middleware/repository
bash scripts/run_ci.sh
```

Then run the read-only auth discovery:

```bash
bash scripts/discover_auth_codestra_edge.sh
```

Require the public discovery and local gateway checks to remain healthy.

## Runtime boundary

`config/api-webhook-contracts.json` defines middleware ingress contracts including:

```text
/api/v1/odoo/events
/api/v1/n8n/results
/api/v1/vicidial/events
/api/v1/telnexa/events
/api/v1/klyrow/events
/api/v1/kyqra/results
/api/v1/kyqra/progress
/api/v1/postly/events
```

These contracts define authentication, audiences, scopes, idempotency, webhook signatures, replay controls, and event types. They are not evidence that an executable middleware API currently implements these routes.

Until authoritative middleware runtime source is present and project-specific CI proves those routes, do not:

- publish new API listeners;
- add Kong routes that assume the endpoints exist;
- enable Odoo/n8n/VICIdial/Telnexa/Klyrow/Kyqra/Postly delivery to them;
- build or deploy a container claiming to implement them.

## No-change boundaries

A Git-only synchronization must leave these unchanged:

```text
CADDY_RELOAD=NO
KEYCLOAK_RESTART=NO
ODOO_CHANGED=NO
N8N_CHANGED=NO
BOOKED4SEASONS_CHANGED=NO
EXTERNAL_DELIVERY_CHANGED=NO
```
