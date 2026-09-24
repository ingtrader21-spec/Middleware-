# Provider and site transport conventions

## Scope

These conventions govern communication between the middleware, the application-host Caddy routes, the provider-host Nginx routes, provider components, and Odoo.

Repository contracts do not prove live reachability. Runtime evidence still requires read-only discovery, credential configuration outside Git, staging tests, and explicit activation approval.

## Edge ownership

- `platform/caddy` owns the public routes on Application Server A.
- `platform/nginx-provider` owns the public and private mTLS routes on the provider host.
- A public hostname has exactly one owning `site/*` branch and one edge branch.
- A private route has no public hostname and must be loopback-only, private-network-only, or mTLS-protected.
- Degraded routes remain declared with an explicit issue; they must never be represented as healthy.

## Public request path

```text
browser or API client
  -> Caddy or provider Nginx
  -> Kong or private integration gateway where applicable
  -> authenticated middleware endpoint
  -> durable inbox or synchronous read-only handler
```

Public form submissions use anti-abuse controls at the edge and a service identity for the edge-to-middleware hop. The browser never receives Odoo credentials and never writes directly to Odoo.

## Private mTLS path

```text
provider service
  -> private Nginx mTLS route
  -> integration/private-app-gateway
  -> durable signed inbox
  -> normalized internal event
```

The gateway validates the client certificate, expected service identity, tenant mapping, request signature when configured, timestamp, idempotency key, and payload schema.

## RabbitMQ

RabbitMQ connections require:

- TLS or a private network with authenticated service identities;
- dedicated virtual hosts and least-privilege users;
- publisher confirms;
- explicit consumer acknowledgements;
- bounded redelivery;
- dead-letter exchanges and queues;
- stable event IDs and idempotent consumers;
- queue depth, unacked-message, connection, disk, and memory alerts.

RabbitMQ does not replace Redis or PostgreSQL merely because a branch exists. Broker ownership and migration require an approved architecture record.

## PostgreSQL, MariaDB, and Redis

- Databases are never exposed publicly.
- Each service uses a least-privilege role.
- Schema changes are versioned and tested for upgrade and rollback.
- PostgreSQL remains the durable middleware ledger and outbox store.
- MariaDB is limited to provider applications that already depend on it.
- Redis stores temporary queues, leases, caches, and retry scheduling; it is not the durable system of record.

## SMTP and email

`integration/klyrow-smtp-relay` submits through authenticated SMTP to the approved mail path. Postal lifecycle callbacks are handled through signed or authenticated delivery events.

Requirements:

- tenant and domain ownership mapping;
- suppression before send;
- stable message and idempotency IDs;
- bounce, complaint, delivery, and deferral normalization;
- no credentials in Git;
- no direct website-to-SMTP submission;
- reconciliation before repeating a timed-out send.

## SMS and SMPP

Telnexa is the middleware-facing SMS integration. Jasmin is the underlying provider component on the provider host.

Requirements:

- authenticated HTTP or SMPP service identity;
- tenant and sender-ID authorization;
- stable message and idempotency IDs;
- delivery receipt normalization;
- inbound message authentication and mapping;
- suppression, rate limiting, and consent checks;
- reconciliation before retrying an unknown submission outcome.

## Crawlers and browser workers

Crawler jobs use tenant and job isolation, allowlisted policies, bounded concurrency, deterministic callbacks, and provenance. Browser workers may use Playwright only after package/runtime verification.

Crawler and scraper output must not trigger automatic outreach. The result enters the lead-intake pipeline as `review_pending` with external contact disabled.

## Health and release identity

Every deployable API or worker exposes or records:

```text
service
component
environment
release_sha
image_digest
schema_or_migration_head
started_at
```

Health checks prove process liveness. Readiness checks prove required private dependencies are reachable without performing external writes.

## Rollback

A source rollback does not reverse:

- database migrations;
- delivered SMS or email;
- consumed queue messages;
- crawler activity;
- Odoo record mutations.

A release record must identify the prior image digest, matching data recovery point, migration reversal strategy, queue handling, and reconciliation plan.
