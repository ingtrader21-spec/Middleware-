# Middleware connectivity and communication architecture

## Objective

All middleware workstreams share one reviewed contract baseline and one explicit dependency graph. Branches remain isolated for implementation and review, but they communicate through canonical HTTP, event, identity, persistence, queue, and observability contracts rather than inventing incompatible behavior independently.

This document defines repository architecture. It does not claim that every configured service is installed, reachable, authenticated, or production-ready. Live connectivity still requires source import, read-only runtime discovery, credential configuration outside Git, staging tests, and explicit activation approval.

## Canonical communication hub

The shared workstream is:

```text
core/integration-contracts
```

It owns:

- the canonical system and connection registry;
- the event envelope schema;
- HTTP, webhook, authentication, tenant, correlation, causation, and idempotency rules;
- compatibility and error semantics;
- common observability names and release identity;
- cross-system contract tests.

Every other workstream depends directly or transitively on this branch. Shared contract changes merge first into `main`; affected branches are then refreshed from the new `main` before their implementation changes continue.

## Logical topology

```text
Public and private clients
          |
          v
     platform/caddy
          |
          v
      platform/kong <------ integration/keycloak
          |
          v
 core/integration-contracts
    |          |          |
    v          v          v
 event      webhook     workers
 ledger      inbox      scheduler
    |          |          |
    +-----+----+----+-----+
          |         |
    PostgreSQL     Redis
          |
          v
 NATS JetStream <---- canonical events
          |
          v
       workers ----> Temporal workflows

 RabbitMQ: provider-local only (Klyrow/Telnexa), never the central bus

 core/integration-contracts
          |
          +--> Odoo 19
          +--> n8n
          +--> VICIdial
          +--> Asterisk/PJSIP
          +--> Telnexa SMS
          +--> Klyrow email
          +--> Postly social
          +--> Mautic                verification only
          +--> Postal email          verification only
          +--> Jasmin SMS            verification only
          +--> Crawlee               verification only
          +--> Kyqra                 runtime unverified
          +--> Beyvra                runtime unverified

 Exporters and middleware metrics --> Prometheus --> Alertmanager
                                      |       
                                      +------> Grafana
 Middleware structured logs --------> Loki ----> Grafana
 Blackbox Exporter -----------------> Caddy/Kong health paths
 Playwright ------------------------> Caddy edge, no-write tests only
```

## Machine-readable sources

```text
config/integration-branches.json
config/connectivity-map.json
contracts/event-envelope.schema.json
contracts/http-conventions.md
contracts/observability-conventions.md
```

CI validates that:

1. every declared workstream has a dependency declaration;
2. the dependency graph has no cycles;
3. every workstream is connected to `core/integration-contracts`;
4. every central workstream participates in at least one declared communication connection; provider-local inventory branches are explicitly exempt;
5. every connection names its transport, authentication, reliability, owner, runtime status, and contract;
6. verification-only systems cannot be represented as active connections;
7. required event metadata is present in the canonical envelope;
8. workstream branches are never treated as deployment branches.

## Communication requirements

### Identity and authorization

Keycloak is the canonical identity authority and uses `https://auth.codestra.co` as the issuer. Kong and middleware services validate issuer, audience, signature, expiry, roles or scopes, and tenant authorization. Service-to-service access uses short-lived identities and least privilege.

### Tenant isolation

Every externally meaningful command, event, inbox record, outbox record, job, retry, mapping, audit entry, and provider result carries an authoritative tenant identifier. Caller-provided tenant values are checked against the authenticated identity and local mapping.

### Correlation and causation

Every flow preserves:

```text
correlation_id
causation_id
traceparent when available
```

A downstream retry reuses the original correlation and causation context rather than creating an unrelated operation.

### Idempotency and duplicate control

Externally effective operations require a stable idempotency key. Webhook events use a provider event ID plus body digest or equivalent authoritative key. Duplicate delivery returns or reuses the original outcome and never repeats SMS, email, dialing, social publication, crawler execution, or CRM mutation.

### Durable delivery

Database changes that must produce external work use a transactional outbox. Inbound callbacks are stored in a durable inbox before acknowledgment. Workers use leases, bounded retries, dead-letter handling, reconciliation, and controlled replay.

### Webhook security

Webhooks require a versioned signature, signed timestamp, bounded clock-skew policy, replay protection, durable deduplication, tenant mapping, and safe quarantine for unknown or conflicting events.

### Failure semantics

A timeout is an unknown outcome. The adapter reconciles with the provider before retrying an externally effective command. Retries are bounded by attempt count and age. Exhausted work becomes an operational exception with an audited replay path.

## Branch dependency order

The preferred merge sequence is:

```text
1. core/integration-contracts
2. platform/postgresql, platform/redis, platform/nats-jetstream and platform/temporal
3. integration/keycloak
4. core/event-ledger-outbox
5. core/webhook-inbox-replay
6. core/workers-scheduler
7. application and provider adapters
8. platform/kong
9. platform/caddy
10. exporters, Prometheus, Loki, Alertmanager and Grafana
11. testing/playwright
```

RabbitMQ remains provider-local to Klyrow and Telnexa and is forbidden as a central middleware transport. Mautic, Postal, Jasmin, Crawlee, Kyqra, and Beyvra remain verification-only until runtime ownership, source, network, credentials, data responsibility, rollback, and activation controls are confirmed.

## Keeping branches up to date

A clean workstream with no unique commits is fast-forwarded to the latest reviewed `main` SHA. A workstream with active commits must first confirm that `main` is an ancestor or rebase in a trusted development environment, resolve conflicts, and rerun exact-head CI.

Trusted development workflow:

```bash
git fetch origin
git switch <workstream>
git merge --ff-only origin/main
```

When the branch has unique commits and cannot fast-forward:

```bash
git rebase origin/main
# resolve conflicts
git push --force-with-lease origin <workstream>
```

The production server is read-only and must not rebase, force-push, resolve conflicts, or author source changes.

## Pull-request communication evidence

Every system pull request identifies:

- the owning workstream;
- dependency branches and merge order;
- affected connection IDs from `config/connectivity-map.json`;
- request, event, webhook, or queue schemas changed;
- authentication and tenant-isolation behavior;
- idempotency, replay, retry, reconciliation, and rollback tests;
- exact reviewed head SHA;
- protected merged SHA and immutable image digest when released.

A branch is not considered connected merely because its name exists. Connection is demonstrated by reviewed contracts, implementation tests, staging runtime evidence, and the effective disabled-by-default safety configuration.

## Release rule

```text
workstream branch
  -> exact-head CI and review
  -> protected merge into main
  -> one immutable image from merged SHA
  -> staging by digest with external effects disabled
  -> connectivity, duplicate, replay and rollback evidence
  -> explicit production approval
  -> production deployment of the identical digest
```

No workstream branch, mutable tag, locally edited checkout, or unverified service is deployed directly.
