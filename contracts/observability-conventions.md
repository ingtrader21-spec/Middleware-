# Middleware observability conventions

## Purpose

Every middleware workstream must expose enough telemetry to prove release identity, request flow, queue health, delivery safety, and failure recovery without exposing secrets or customer data.

## Required release identity

Services, workers, dashboards, alerts, and evidence records must identify:

```text
service
component
environment
release_sha
image_digest
schema_or_migration_head
started_at
```

A mutable tag such as `latest` is not release identity.

## Metrics

Use low-cardinality labels. Recommended labels include `service`, `component`, `environment`, `operation`, `provider`, `result`, and `release_sha`. Do not use raw customer IDs, phone numbers, email addresses, message bodies, URLs containing tokens, correlation IDs, or unbounded exception text as metric labels.

Each affected component provides applicable metrics for:

```text
request count, status and latency
active requests and worker concurrency
authentication and authorization denials
rate-limit decisions
outbox backlog, lease age and delivery result
inbox accepted, duplicate, rejected and quarantined events
retry attempts, age and exhaustion
dead-letter count and oldest age
provider timeout and reconciliation outcome
queue depth and oldest item age
scheduled-job delay and duration
database pool, transaction and migration state
Redis connection, memory, lease and command failures
external-effect denial while capability flags are disabled
release information
```

Counters are monotonic. Histograms use bounded buckets appropriate to the operation. Gauges represent current state and must not be treated as event counters.

## Structured logs

Logs are structured JSON and include, when applicable:

```text
timestamp
level
service
component
event
operation
tenant_reference
correlation_id
causation_id
trace_id
provider
result
retryable
release_sha
image_digest
```

Tenant references must be stable internal identifiers, not names or personal information. Logs must redact tokens, credentials, private keys, signed callback material, database URLs, message bodies, email addresses, phone numbers, and browser session data.

Repeated failures use aggregation or rate limiting so one bad event cannot exhaust storage.

## Tracing

Propagate W3C `traceparent` where supported. Spans use safe operation names and include correlation and causation identifiers as attributes only when the tracing backend is access controlled and retention is approved. Do not attach raw payloads or credentials.

## Prometheus and exporters

- Exporters use least-privilege credentials and private or authenticated endpoints.
- PostgreSQL Exporter uses a dedicated monitoring role without application write privileges.
- Redis Exporter uses a dedicated ACL identity limited to required read-only commands.
- Node Exporter and cAdvisor expose only required collectors and remain source restricted.
- Scrape configurations identify exact targets and do not discover arbitrary public endpoints.
- Recording and alerting rules are versioned in Git and validated before deployment.

## Blackbox checks

Blackbox probes test the public and private paths without creating external effects. Probes may verify DNS, TCP, TLS, HTTP status, headers, `/health`, `/ready`, and `/version`. They must not submit leads, send SMS or email, start dialing, publish social content, create crawler jobs, or mutate Odoo/n8n state.

## Alerts

Alerts cover at minimum:

```text
service unavailable or restart loop
readiness failure
release identity mismatch
certificate expiry and TLS failure
authentication or authorization anomaly
rate-limit failure
outbox or inbox backlog age
retry storm or dead-letter growth
worker lease expiration
PostgreSQL or Redis unavailability
queue depth or consumer failure
external delivery unexpectedly enabled
VICIdial, SMS, email, social or crawler writes occurring while disabled
backup, restore or migration failure
```

Alertmanager grouping and inhibition prevent duplicate storms. Receiver credentials stay outside Git. Every production alert has an owner, severity, runbook, and clear recovery or escalation action.

## Grafana and Loki

Grafana dashboards are provisioned from Git and display the exact release SHA and image digest. Data sources use least-privilege credentials. Loki labels remain low-cardinality; correlation IDs belong in structured log fields rather than labels unless a bounded policy explicitly permits otherwise.

## Evidence and retention

Operational evidence records the exact commit SHA, image digest, environment, timestamp, test result, and operator or automation identity. Evidence must not contain secrets or unredacted customer payloads. Retention follows the approved operational and compliance policy.

## Branch ownership

Exporter configuration belongs to the corresponding `observability/*-exporter` branch. Prometheus rules belong to `observability/prometheus`; alert routing belongs to `observability/alertmanager`; dashboards belong to `observability/grafana`; log pipeline and retention belong to `observability/loki`. Cross-cutting metric names and release fields are controlled through `core/integration-contracts`.
