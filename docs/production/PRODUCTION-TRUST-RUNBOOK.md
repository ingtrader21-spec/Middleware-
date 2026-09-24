# Production trust preparation

This runbook prepares private trust but does not authorize production delivery.
`LIVE_WRITES_ENABLED`, Odoo/VICIdial writes, callback dispatch, broad delivery,
and production n8n workflows remain false until an exact-SHA authorization is
signed by the protected workflow.

## Private boundary

- `codestra-internal-integration` is internal-only and uses `10.254.41.0/28`.
- Only the Middleware integration API, Odoo, n8n, and the internal reverse
  proxy may join it.
- `n8n.internal.codestra.agency` and `odoo.internal.codestra.agency` are Docker
  aliases on the reverse proxy. They are not public DNS records.
- The internal CA and keys live under
  `/etc/codestra/pki/internal-integration`; private keys are root-owned `0600`.
- Middleware trusts the mounted CA explicitly and internal HTTP clients ignore
  ambient proxy variables.

The only Odoo mutation route exposed by the private proxy is
`POST /api/v1/integration/results`. The retired
`/codestra/integration/v1/results` path is not routed. n8n never receives Odoo
credentials or database access.

## Credentials

The approved service-client manifest is
`deploy/internal-n8n/keycloak-service-clients.json`. Create or rotate clients
only through an authenticated Keycloak administration path. Never create a
local secret that is not bound to the corresponding identity-provider client.
Secret files are mounted from `/etc/codestra/secrets/internal-n8n` and must not
be committed or logged.

## Workflow governance

`production-workflow-inventory.json` is authoritative for candidate
classification. `INACTIVE_UNCLASSIFIED` workflows stay inactive. Source review
alone is not production authorization.

The protected `production-canary-authorization.yml` workflow requires:

1. an exact open PR head and exact-head required CI;
2. an exact-head approval from `kazan555`;
3. separate protected Release Owner and Security Owner environment decisions;
4. exact image digest, internal destination, 5–10 call bounds, one-hour maximum
   execution window, rollback SHA, and allowlisted flags;
5. an OIDC-signed authorization artifact.

## Legacy outbox disposition

The five historical `event.accepted` rows have no recoverable tenant binding.
They have zero attempts because the generic outbox is an internal transaction
journal and no external dispatcher owns that topic;
`OUTBOX_WORKER_ENABLED` was correctly disabled. They are classified `EXPIRED`
and must not be replayed. Odoo and n8n delivery use their dedicated durable
outboxes and workers.

## Activation order

1. Verify exact image labels, digest, CI, PR review, both owner decisions, and
   the signed authorization.
2. Verify private DNS, CA chain, hostname validation, Keycloak token issuance,
   Odoo 401/403 negative cases, n8n HMAC/replay negative cases, and empty dead
   letters.
3. Enable only flags listed in the signed request.
4. Execute only 5–10 company-controlled `TEST_SYN` calls.
5. Disable all activated flags immediately on any loss, duplicate, auth error,
   unexpected destination, or scope drift.

## Rollback

Disable delivery flags first. Stop result and n8n delivery workers, restore the
prior immutable Middleware digest, restore the backed-up Compose/Caddy files,
and preserve all PostgreSQL outbox, result, audit, and dead-letter rows. Never
delete queue evidence during rollback.
