# Application and provider site architecture

## Scope

This document extends the canonical middleware registry with the sites and stacks supplied from the application and provider servers.

The reviewed machine-readable sources are:

```text
architecture/workstreams.py
architecture/routes.py
architecture/site_architecture.py
```

They define supplemental workstreams, dependencies, communication links, routes, provider stacks, and form/crawler/scraper lead sources. They do not authorize deployment. Live changes still require source ownership, exact image or commit identity, credentials outside Git, staging evidence, rollback, and approval.

## Application Server A and Caddy

| Route | Workstream | Current status |
|---|---|---|
| `codestra.co` | `site/codestra` | active |
| `www.codestra.co` | `site/codestra` | redirect to root |
| `auth.codestra.co` | `site/codestra-auth` | active: verified OIDC discovery and TLS |
| `social.codestra.co` | `site/codestra-social` | active Postiz/social application |
| `ai.codestra.co` | `site/codestra-ai` | active AI console |
| `beyvra.com` | `site/beyvra` | active |
| `www.beyvra.com` | `site/beyvra` | active |
| `platform.beyvra.com` | `site/beyvra` | active |
| `api.beyvra.com` | `site/beyvra` | active API |
| `admin.beyvra.com` | `site/beyvra` | active admin |
| `staging.beyvra.com` | `site/beyvra` | active staging |
| `booked4seasons.com` | `site/booked4seasons` | active |
| `www.booked4seasons.com` | `site/booked4seasons` | degraded: TLS handshake failure |
| `breero.com` | `site/breero` | active production |
| `www.breero.com` | `site/breero` | redirect to root |
| `api.breero.com` | `site/breero` | active production API |
| `staging.breero.com` | `site/breero` | active staging |
| `api-staging.breero.com` | `site/breero` | active staging API |

`platform/caddy` owns the application-server edge. `operations/application-host` owns host service inventory, safe restart boundaries, backups, route evidence, and change records.

The verified `auth.codestra.co` route is `65.109.65.169` host Caddy -> `127.0.0.1:18103` -> `codestra-caddy-upstream-gateway` -> `codestra-identity-keycloak-1:8080`. End-to-end OpenID discovery returned HTTP 200 with TLS verification result 0 and issuer `https://auth.codestra.co/realms/codestra`; the previously recorded 502 is no longer reproducible. The remaining Booked4Seasons TLS failure stays explicit in Git and is outside this auth recovery scope.

## Provider host and Nginx

### Klyrow — `site/klyrow`

Components:

- main gateway/API and worker;
- billing API, billing worker, and scheduler;
- SMTP relay;
- Mautic and Postal;
- RabbitMQ, PostgreSQL, and MariaDB;
- Prometheus and Grafana.

Routes:

```text
klyrow.com
www.klyrow.com
app.klyrow.com
api.klyrow.com
track.klyrow.com
bounce.klyrow.com
```

### Telnexa — `site/telnexa`

Components:

- Telnexa/Jasmin SMS path;
- billing API and worker;
- Keycloak;
- RabbitMQ, Redis, and PostgreSQL;
- Prometheus and Node Exporter;
- internal mTLS route.

Routes:

```text
sms.telnexa.co
api.telnexa.co
status.telnexa.co
```

### Kyqra Crawler — `site/kyqra-crawler`

Components:

- crawler API;
- HTTP crawler worker;
- browser crawler worker;
- callback worker;
- PostgreSQL and Redis.

Route:

```text
crawler.kyqra.com
```

The inventory proves crawler workers, but not the exact Crawlee or Playwright package/image. `integration/crawlee` and `testing/playwright` therefore remain technology-verification workstreams.

### Private App Integration — `site/private-app-integration`

The gateway is exposed only on loopback and through the internal mTLS Nginx route. It has no public hostname.

### Codestra Business Scrapper — `site/codestra-business-scrapper`

Source exists at:

```text
/opt/codestra-business-scrapper
```

It is not deployed as an application. PostgreSQL 17 and Redis 7.4 containers are recorded as disposable pull-request validation dependencies, not production services.

`platform/nginx-provider` owns provider-host public and private routes. `operations/provider-host` owns Docker/containerd inventory, Fail2ban, SSH, cron, logging, updates, backups, and host health.

## Supplemental workstreams

This architecture adds isolated branches for:

```text
integration/postiz-social
integration/codestra-ai-console
platform/nginx-provider
platform/mariadb
integration/klyrow-smtp-relay
integration/provider-billing
core/lead-intake-normalization
integration/private-app-gateway
integration/web-form-intake
integration/codestra-business-scrapper
operations/provider-host
operations/application-host
site/klyrow
site/telnexa
site/kyqra-crawler
site/private-app-integration
site/codestra-business-scrapper
site/codestra
site/codestra-auth
site/codestra-social
site/codestra-ai
site/beyvra
site/booked4seasons
site/breero
```

The supplied provider-host inventory also changes RabbitMQ, Mautic, Postal, Jasmin, and Kyqra from middleware-host verification-only observations to declared remote-provider scope. Beyvra becomes declared active scope because its Caddy routes were supplied as active.

## API and webhook identity contracts

The middleware API/webhook contract set binds service-to-service traffic to the canonical Keycloak issuer `https://auth.codestra.co/realms/codestra`, client-credentials machine tokens, audience checks, scopes, idempotency, signed webhook envelopes, replay retention, and the following middleware ingress paths:

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

These are contract definitions and security requirements. They must not be represented as executable/live middleware endpoints until the authoritative runtime source implements them and project-specific CI proves them.

## Form, crawler, and scraper intake to Odoo

```text
public site form
  -> Caddy or provider Nginx
  -> integration/web-form-intake
  -> integration/private-app-gateway
  -> core/webhook-inbox-replay
  -> core/lead-intake-normalization
  -> core/event-ledger-outbox
  -> integration/odoo-19
  -> Odoo CRM
```

Kyqra crawler and future approved scrapper results enter the same durable normalization and outbox path.

Rules:

- no site or worker holds Odoo credentials;
- no site, crawler, scraper, provider service, or n8n workflow writes directly to Odoo;
- form leads start `new` only after schema, tenant, consent, and suppression validation;
- crawler and scraper leads start `review_pending`;
- discovered leads have `review_required=true` and `allow_external_contact=false`;
- provenance and source references are mandatory;
- duplicate delivery reuses the original result;
- a timeout is reconciled before retry;
- external delivery remains disabled until separately approved.

Schemas:

```text
contracts/lead-intake.schema.json
contracts/odoo-lead-command.schema.json
```

## Fail-closed staging

The architecture does not itself enable forms, crawler delivery, scraper delivery, SMS, email, social publication, or crawling. Runtime activation requires real application controls, credentials outside Git, exact-SHA staging, and test evidence.

## Branch synchronization

After the architecture pull request merges, every base and supplemental workstream branch must contain the reviewed merged `main` SHA. Clean branches are fast-forwarded. Active branches with unique commits are never force-overwritten.

Use after fetching all remote branches:

```bash
python3 scripts/audit_all_workstream_sync.py --require-exact
```

## Release rule

```text
workstream branch
  -> exact-head CI and review
  -> merge into protected main
  -> immutable artifact from merged SHA
  -> staging with external effects disabled
  -> route, lead, duplicate, replay, migration, backup and rollback evidence
  -> explicit approval
  -> production deployment of the identical digest
```
