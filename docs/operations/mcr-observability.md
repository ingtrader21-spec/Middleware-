# MCR-L observability and deliverability

MCR telemetry is collected only by the existing authenticated private `/metrics`
surface. It uses a dedicated registry, never the default/public registry. No
new HTTP route, collector target, provider capability, deployment, or catalog
registration is activated by this change. The service catalog descriptor in
`contracts/campaign-recycling/observability.v1.json` is pending certification.

Decision counters count unique reasons per candidate evaluation (including read
and plan), not unique leads. Empty candidate sets use channel `none`. The block
counter separates suppression, channel health, and exposure/cycle caps. All
labels are fixed enums; unknown values collapse to `unknown`/`UNKNOWN`. Tenant,
lead, campaign, sender, address, payload, hashes and provider identifiers are
excluded entirely. Tenant separation is enforced at readback query boundaries;
metrics are operational aggregates, never a tenant-facing data source.

Local completed spans use generated trace/span IDs, operation, elapsed time and
sanitized enum attributes. These are JSON log records, not a configured OTLP
export pipeline. No incoming trace baggage, exception text or provider payload
is logged. Projection outcomes are observed after transaction exit, so a commit
failure increments `failed`, never `applied`. Metrics are best-effort process
counters, not an audit ledger. Restart resets counters. The database is authority.

Delivery SLO: 99% of completed projections within 300 seconds of `received_at`
over 30 days. This histogram alone excludes stuck pending rows; inspect the
scoped database readback as well. Readback evidence expires after 60 seconds;
partial projections, lag over 300 seconds, missing evidence, and dead letters
block readiness. A query/storage failure is unavailable, never an empty healthy
result. `ready` never authorizes a provider effect. The HTTP OpenAPI is a future
private binding only; current callers use the tenant-checked store method and
must supply `authorized_tenant_id` from a verified principal, not request input.

The existing delivery ledger supports pending/partial/applied, but has no durable
MCR dead-letter authority. Readback therefore returns `dead_letter: null` and
`ready: false`; the availability gauge remains zero and alerts. Do not substitute
zero for unknown or infer dead-letter depth from process error counters. A future
durable dead-letter implementation and certification are required before this
gate can pass. This change intentionally cannot activate delivery.

For projection/lag alerts, inspect scoped inbox evidence and dependency health.
Repair missing exposure/lifecycle mapping before retrying the exact same event
identity and payload hash. Applied duplicates are no-ops; partial retries may
complete, and altered evidence is rejected. Never bypass suppression, health,
capability, consent or policy checks to clear alerts. Do not log raw events while
investigating. For replay spikes, check source retry behavior before any retry.
For missing telemetry, verify private monitoring identity, scrape health and
registry attachment. Do not expose `/metrics` on public ingress to restore it.

Validation: `python -m pytest -q tests/test_mcr_observability*.py
 tests/test_campaign_recycling_engine.py tests/test_campaign_recycling_contracts.py
 tests/test_observability.py` and `python scripts/validate_mcr_observability.py`.

## Delivery health and reconciliation

`codestra_mcr_delivery_health_total{channel,event_type}` counts completed
normalized event projections: delivered, deferred, soft/hard bounce, complaint,
unsubscribe and engagement signals use the frozen delivery taxonomy. Partial,
failed and rejected attempts and applied duplicates do not increment it. A
partial retry increments it when it completes. These are event counts, not a
unique-message delivery rate: do not divide delivered events by all events or
interpret open/read as conversions. Completion lag likewise excludes partials.

`codestra_mcr_readback_total{outcome}` reports ready, blocked, unavailable, denied
or unknown attempts without tenant labels. These counters describe observations,
not current fleet readiness. Use scoped pending/partial/oldest/sample evidence
for reconciliation. No polling worker is installed; no requests means no
readback coverage. Never publish a last-tenant-wins aggregate queue-depth gauge.
A database error increments unavailable and propagates; it cannot become zero
backlog. Reconcile source inbox identity/hash with the normalized ledger and
exposure/health/lifecycle authorities through authorized scoped readbacks.

The connector catalog includes Klyrow/email, Telnexa/SMS, Evolution/WhatsApp,
VICIdial/voice, Odoo/conversion and Middleware/normalization. All registrations
remain pending. The catalog records authority boundaries, not proof of live
connector health; Evolution remains dependency-blocked and VICIdial contract-only.

## Staging evidence procedure

`reports/mcr-l-staging-evidence.json` records unexecuted staging checks explicitly.
Offline unit tests are not staging certification. In an isolated staging runtime,
record revision, UTC observation time and sanitized evidence references for each
check: anonymous scrape denied; verified monitoring scrape accepted; synthetic
secret excluded from metrics and span logs; tenant mismatch denied; pending,
partial, stale and missing evidence blocked; storage failure unavailable;
duplicate no-op and partial retry; alert firing/recovery and telemetry absence.
Run the same cases for each implemented connector mapping. Do not enable provider
effects. Dead-letter certification cannot pass until a durable authority exists.
Readback polling coverage must be certified before claiming fleet readiness.

The 30-day projection SLI is
`sum(increase(codestra_mcr_projection_lag_seconds_bucket{le="300"}[30d])) /
sum(increase(codestra_mcr_projection_lag_seconds_count[30d]))`.
A zero denominator is no evidence, not 100% success. This completion SLI must be
reviewed together with scoped backlog and missing-evidence gates. The p99 alert
is an operational early warning, not proof that the 30-day SLO passed.

## Rollback observability

Before a separately authorized staging rollback, save the revision, private
scrape availability, counter baselines, alert state and sanitized tenant-scoped
readback. Keep execution/provider gates closed. Roll back the application build
through its approved release procedure; preserve inboxes, normalized ledger,
identity/hash records and suppression/health state. Never delete evidence or
replay provider sends to make dashboards green. This change adds no migration.

After rollback, repeat authenticated scrape and scoped reconciliation checks.
Counter resets are expected on restart and are not delivery loss; compare durable
ledger state. Removal of MCR metrics must leave the absent-evidence alert firing,
not mark the service healthy. Keep the alert rules until replacement monitoring
is certified. Verify duplicate replay remains a no-op and partial projections
remain visible. Record observed revision, timestamp, alert outcome and unresolved
backlog in staging evidence. No rollback or deployment was executed here.
