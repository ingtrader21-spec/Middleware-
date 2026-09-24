# Middleware integration workstreams

## Purpose

Each middleware-connected system and every major platform, shared-core, testing, or observability concern has an isolated Git workstream. Workstream branches are for implementation and review; they are not staging or production deployment branches.

The canonical machine-readable list is [`config/integration-branches.json`](../config/integration-branches.json). Dependency and communication relationships are defined in [`config/connectivity-map.json`](../config/connectivity-map.json) and explained in [`CONNECTIVITY-AND-COMMUNICATION.md`](CONNECTIVITY-AND-COMMUNICATION.md).

## Runtime status meanings

| Status | Meaning |
|---|---|
| `declared_active_scope` | The architecture declares an active responsibility. Live source, paths, and credentials still require runtime confirmation. |
| `required_shared_primitive` | A required cross-system middleware capability. |
| `configured_worker_not_observed` | Configuration references exist, but the expected worker was not observed. |
| `configured_runtime_not_confirmed` | Configuration references exist, but active runtime and ownership are not confirmed. |
| `not_observed_on_middleware_host_verification_only` | The branch exists for contracts, tests, inventory, and verification only. It does not authorize installation or activation. |
| `provider_local_not_central_verification_only` | A provider-owned component recorded for compatibility; it cannot become a central middleware dependency. |

## Canonical shared contract workstream

| Branch | Scope |
|---|---|
| `core/integration-contracts` | Canonical API and event contracts, connection registry, identity and tenant metadata, correlation, causation, idempotency, compatibility, error semantics, release identity, and cross-system contract tests. |

Every other workstream depends directly or transitively on `core/integration-contracts`. A shared contract change merges first; affected workstreams then refresh from the new `main` before implementation continues.

## Active application and integration workstreams

| Branch | System | Scope |
|---|---|---|
| `integration/odoo-19` | Odoo 19 | CRM, contacts, leads, activities, campaigns, callbacks, appointments, delivery results, reconciliation, and adapter tests. |
| `integration/n8n` | n8n | Workflow automation, normalized events, signed webhooks, inactive-by-default exports, replay protection, and adapter tests. |
| `integration/vicidial` | VICIdial | Campaigns, agents, dispositions, call results, callbacks, restricted commands, read-back comparison, and write-denial tests. Direct database writes are prohibited. |
| `integration/asterisk-pjsip` | Asterisk/PJSIP | Endpoints, extensions, trunks, call infrastructure, authentication, routing contracts, health, and telephony tests. |
| `integration/telnexa-sms` | Telnexa | SMS submission, delivery callbacks, inbound events, signatures, replay protection, suppression, rate limits, and reconciliation. |
| `integration/klyrow-email` | Klyrow | Email submission, lifecycle events, bounces, complaints, suppression, templates, deduplication, callbacks, and reconciliation. |
| `integration/postly-social` | Postly | Social polling, publishing and delivery events, account isolation, retries, callbacks, and reconciliation. |
| `integration/keycloak` | Keycloak | OIDC/JWKS validation, service identities, roles, claims, audience and issuer enforcement, authorization policy, and tests. The canonical issuer is `https://auth.codestra.co`. |

## Platform workstreams

| Branch | Platform | Runtime status | Scope |
|---|---|---|---|
| `platform/kong` | Kong | Active scope | API services, routes, plugins, authentication, mTLS, rate limits, allowlists, transformations, and gateway tests. |
| `platform/caddy` | Caddy | Active scope | Middleware-side route compatibility and edge validation. Canonical production Caddy desired state is `appolon1908-hue/codestra-production-platform:operations/caddy/`. |
| `platform/postgresql` | PostgreSQL | Active scope | Durable records, event ledger, outbox, audit, mappings, schema, migrations, least-privilege roles, backup/restore, and rollback. |
| `platform/redis` | Redis | Active scope | Temporary queues, cache, leases, idempotency state, locks, retry scheduling, recovery, and integration tests. |
| `platform/nats-jetstream` | NATS JetStream | Required shared primitive | Canonical event subjects, durable consumers, replay, service credentials, acknowledgements, deduplication, and central event transport. |
| `platform/temporal` | Temporal | Required shared primitive | Durable workflows, task queues, retries, timeouts, signals, workflow identity, and operational recovery. |
| `platform/rabbitmq` | RabbitMQ | Provider-local only | Compatibility inventory for Klyrow and Telnexa. It is forbidden as a central Codestra event transport or Middleware dependency. |

RabbitMQ does not replace NATS JetStream or supplement Redis merely because its branch exists. A central transport change requires a reviewed architecture decision, migration and rollback plan, queue-semantics tests, operational ownership, and runtime evidence.

## Verification-only application and testing workstreams

| Branch | System | Allowed scope before runtime confirmation |
|---|---|---|
| `integration/mautic` | Mautic | Contact, campaign, segment, API/webhook contracts, authentication, idempotent synchronization, event mapping, reconciliation tests, and inventory. |
| `integration/postal-email` | Postal | Email submission and lifecycle contracts, bounces, complaints, suppression, signatures, deduplication, reconciliation tests, and inventory. |
| `integration/jasmin-sms` | Jasmin | HTTP/SMPP submission, delivery receipts, inbound-message contracts, authentication, replay protection, suppression, rate limits, tests, and inventory. |
| `integration/crawlee` | Crawlee | Crawl-job contracts, policies, tenant/job isolation, queue ownership, result ingestion, retries, deterministic fixtures, and inventory. |
| `testing/playwright` | Playwright | Browser end-to-end tests, authentication tests, synthetic no-write canaries, deterministic test data, and safe trace/artifact handling. |
| `integration/kyqra` | Kyqra | Contracts, tests, and runtime verification against canonical source `appolon1908-hue/kyqra-crawler`; the legacy `appolon1908-hue/kyqra` repository is retired. |
| `integration/beyvra` | Beyvra | Contracts, tests, and runtime verification until the active service, endpoint, source path, owner, and deployment path are confirmed. |

Postal and Jasmin may be underlying provider-host components while Klyrow and Telnexa remain the middleware-facing product integrations. The verification branches own middleware contracts and tests unless a separate architecture decision assigns underlying service source and deployment ownership to this repository.

Playwright is testing infrastructure, not a production middleware service. It uses no-write or isolated targets unless an approved controlled test explicitly permits writes.

## Shared middleware core

| Branch | Scope |
|---|---|
| `core/event-ledger-outbox` | Normalized events, durable event ledger, transactional outbox, leases, retries, dead letters, audit, and reconciliation. |
| `core/webhook-inbox-replay` | Signed durable inbox, timestamp bounds, replay protection, idempotency, deduplication, quarantine, and controlled replay. |
| `core/workers-scheduler` | Workers, schedulers, concurrency, queue ownership, graceful shutdown, retries, health, readiness, and restart behavior. |

## Operations and monitoring workstreams

| Branch | Component | Scope |
|---|---|---|
| `observability/prometheus` | Prometheus | Scrapes, recording rules, retention, middleware metrics, and validation. |
| `observability/grafana` | Grafana | Dashboards, data sources, access control, release identity, and provisioning. |
| `observability/alertmanager` | Alertmanager | Routing, grouping, inhibition, receiver contracts, escalation, and notification tests. |
| `observability/loki` | Loki | Structured logs, labels, retention, queries, tenant boundaries, and secret redaction. |
| `observability/blackbox-exporter` | Blackbox Exporter | HTTP, HTTPS, TCP and TLS no-write probes and alerts. |
| `observability/node-exporter` | Node Exporter | Host, filesystem and network metrics with restricted collectors. |
| `observability/cadvisor` | cAdvisor | Container resource metrics, labels, access restrictions, and alerts. |
| `observability/postgresql-exporter` | PostgreSQL Exporter | Least-privilege monitoring role, metrics, custom queries, and alerts. |
| `observability/redis-exporter` | Redis Exporter | Restricted authentication, memory, queue, replication metrics, and alerts. |

## Dependency and merge order

Preferred sequence:

```text
1. core/integration-contracts
2. platform/postgresql, platform/redis, platform/nats-jetstream and platform/temporal
3. integration/keycloak
4. core/event-ledger-outbox
5. core/webhook-inbox-replay
6. core/workers-scheduler
7. confirmed application adapters
8. verification-only adapters after runtime confirmation
9. platform/kong
10. platform/caddy
11. testing/playwright against staging or isolated targets
12. exporters, Prometheus, Loki, Alertmanager and Grafana
```

Use stacked pull requests when dependencies are unavoidable. Each PR identifies its dependency branches, connection IDs, exact merge order, and compatibility evidence.

## Branch rules

1. Every workstream starts from the latest reviewed `main`.
2. `main` must remain an ancestor of active work.
3. Direct system commits to `main` are prohibited; merge through a pull request.
4. A branch changes only its declared scope and minimum required shared contracts.
5. Shared contract changes belong in `core/integration-contracts`; shared persistence, inbox/outbox, worker, database, cache, or broker behavior belongs in its corresponding core or platform branch.
6. Secrets, live `.env`, keys, certificates, database/queue data, customer payloads, logs, packet captures, and secret-bearing browser traces are prohibited.
7. Authentication, authorization, tenant isolation, idempotency, retry/replay, duplicates, recovery, and disabled-capability behavior are tested where applicable.
8. Verification-only branches cannot add a production service, route, port, credential, database, queue, or capability without architecture and activation approval.
9. No workstream branch is deployed directly. Releases are built from a protected merged SHA and deployed by immutable digest.
10. The production server remains read-only and may not author, rebase, force-push, or resolve source conflicts.

## Keeping workstreams current

For a clean branch:

```bash
git fetch origin
git switch <workstream-branch>
git merge --ff-only origin/main
```

For a branch with unique commits, rebase only from a trusted development environment, resolve conflicts, rerun exact-head CI, and use `--force-with-lease` if the reviewed workflow permits it.

After fetching all remote refs, audit synchronization with:

```bash
python3 scripts/audit_workstream_sync.py
```

Use `--require-exact` only when intentionally resetting all clean workstreams to the same `main` SHA.

## Staging and release safety

Staging starts fail closed with external delivery, live writes, callbacks, n8n delivery, Odoo/VICIdial writes, SMS, email, social publication, crawler execution, browser writes, and dialing disabled. Effective runtime values—not example files—are evidence.

```text
workstream branch
  -> exact-head CI and review
  -> protected merge into main
  -> immutable image from merged SHA
  -> staging by digest with external effects disabled
  -> communication, duplicate, replay, backup/restore and rollback evidence
  -> explicit production approval
  -> production deployment of the identical digest
```
