# Odoo runtime contract

Odoo exposes authenticated health readiness, versioned capabilities, outbox claim/read/renew/ack/fail/release, result create/read/reconcile, desired-state reads, trace, audit, and metrics. Service JWTs require exact issuer, audience, client allowlist, scope, expiry, and signature. Replay-sensitive requests additionally bind timestamp, nonce, body SHA-256, trace context, request, correlation, causation, and idempotency identifiers.

Required least-privilege scopes are `odoo.integration.outbox.claim`, `.read`, `.renew`, `.acknowledge`, `.fail`, `odoo.integration.results.write`, desired-state/read scopes, `monitor.read`, and `service.attest`. A credential covering one operation must not imply another.

The sync worker negotiates capabilities before every claim cycle. It accepts only
canonical payloads whose SHA-256 matches the Odoo envelope, commits the event and
redacted audit record to PostgreSQL, then acknowledges the lease. Concurrent
duplicate intake is resolved by the durable unique Odoo event ID; a changed hash
for that ID is a permanent conflict.

The staging source of truth is `Codestra-SRL/codestra-odoo-addons` at the reviewed `main` commit. The deployment mount is `/root/codestra-ai-platform-source-20260801T210000Z/codestra-odoo-addons:/mnt/extra-addons:ro`.

## Campaign-control and provider-activity routes (registry revision 0066)

Source of truth: `contracts/odoo/campaign-control.v1.json` (every
Middleware-to-Odoo operation, outbox allowlist, effective states, readback
fields). Migration `0066_reconcile_odoo_campaign_scope` embeds a static
snapshot of the rows it seeds and pins the catalog's canonical SHA-256; the
Alembic run never reads the JSON file.

### Delivery direction

Odoo is authoritative for campaign configuration. Middleware never originates
a campaign command.

| Step | Actor | Mechanism |
| --- | --- | --- |
| 1 | Odoo | Writes a campaign-control event to its transactional outbox. |
| 2 | Middleware sync worker | Claims, persists and acknowledges the event through the existing outbox contract (`outbox.claim` / `.read` / `.renew` / `.acknowledge` / `.fail` / `.release`). The ack only proves durable intake. |
| 3 | Middleware | Creates exactly one `odoo_campaign_saga` row per accepted allowlisted event (`uq_odoo_campaign_saga_event`). |
| 4 | Saga | Executes the operation through the configured adapter (`odoo_campaign_saga_adapter`, default `synthetic`). |
| 5 | Middleware | Reports the observed result to Odoo via `campaign.actual_state.write`. |

Completion is proven only by the actual-state readback (step 5), never by the
outbox acknowledgement (step 2). Events outside the allowlist are stored
durably and never dispatched to a provider.

### Outbox event allowlist

| Event type | Saga operation | Synthetic adapter result state |
| --- | --- | --- |
| `campaign.provision.requested.v1` | `provision` | `provisioned_disabled` |
| `campaign.synthetic_test.requested.v1` | `synthetic_test` | `synthetic_tested` |
| `campaign.activate.requested.v1` | `activate` | `active` |
| `campaign.disable.requested.v1` | `disable` | `disabled` |
| `campaign.reconcile.requested.v1` | `reconcile` | none (reports the state it observes) |

Required payload fields on every allowlisted event: `command_id`,
`organization_public_id`, `business_unit_public_id`, `campaign_public_id`,
`configuration_version`, `manifest_ref`, `manifest_hash`.

### Routes registered by 0066

Every request carries the common headers (`Idempotency-Key`,
`X-Codestra-Request-ID`, `X-Codestra-Correlation-ID`, `X-Codestra-Causation-ID`,
`X-Codestra-Timestamp`, `X-Codestra-Nonce`, `X-Codestra-Body-SHA256`,
`traceparent`) and a canonical JSON body. Reads are `POST .../read` because
the registry has no path parameters and the scope payload travels in the body.

| Operation | Method and path | Scope | Request schema | Required response echo | Receipt field |
| --- | --- | --- | --- | --- | --- |
| `automation_results.apply` | `POST /api/v1/integration/automation-results` | `odoo.integration.automation_results.write` | `internal://odoo/automation-results/v1` | `status`, `event_id`, `execution_id`, `correlation_id` | `receipt_id` |
| `provider_activities.create` | `POST /api/v1/integration/provider-activities` | `odoo.integration.provider_activities.write` | `internal://odoo/provider-activities/v1` | `status`, `event_id`, `operation`, `correlation_id` | `message_id` |
| `campaign.actual_state.write` | `POST /api/v1/integration/campaigns/actual-state` | `odoo.campaign.actual_state.write` | `internal://odoo/campaigns/actual-state/v1` | `status`, `event_uuid`, `command_id`, `configuration_version`, `effective_state`, `correlation_id` | `readback_id` |
| `campaigns.read` | `POST /api/v1/integration/campaigns/read` | `odoo.campaign.control.read` | `internal://odoo/campaigns/read/v1` | n/a (read) | n/a |
| `desired_state.read` | `POST /api/v1/integration/desired-state/read` | `odoo.campaign.control.read` | `internal://odoo/desired-state/read/v1` | response fields `campaign_public_id`, `configuration_version`, `desired_state`, `manifest_ref`, `manifest_hash` | n/a |

Echo fields must equal the request; otherwise Middleware records
`RESPONSE_BINDING_MISMATCH` and dead-letters the delivery. Writes are
`idempotency_required`, reads are `stale_read_safe`; all rows use
`BOUNDED_TRANSIENT_RETRY` with `retry_limit=3`.

Retired route:

| Operation | Method and path | Registered by | Retired by | Reason |
| --- | --- | --- | --- | --- |
| `campaign_actions.apply` | `POST /api/v1/integration/campaign-actions` | 0054 | 0066 (`kill_switch=true` on endpoint version `54000000-0000-4000-8000-000000000023`) | Path collided with Odoo's own campaign lifecycle command route. n8n automation results now use `automation_results.apply`. The 0054 rows are neither rewritten nor removed; `downgrade` of 0066 never re-enables them. |

### Actual-state readback contract

`campaign.actual_state.write` body, all fields required:

| Field group | Fields |
| --- | --- |
| Identity | `event_uuid`, `command_id`, `idempotency_key`, `attempt` |
| Scope | `organization_public_id`, `business_unit_public_id`, `campaign_public_id` |
| Version | `configuration_version`, `operation`, `effective_state` |
| Manifest | `manifest_ref`, `manifest_hash` |
| Evidence | `evidence`, `observed_at` |
| Tracing | `correlation_id`, `causation_id` |

Effective-state vocabulary: `unknown`, `absent`, `provisioned_disabled`,
`synthetic_tested`, `active`, `disabled`. Note that `synthetic_test` is an
operation and `synthetic_tested` is a state; they are never interchanged.

| Rule | Behaviour |
| --- | --- |
| Idempotency | The `Idempotency-Key` header equals body `idempotency_key`. |
| Transport retry | Reuses the same `idempotency_key` and `attempt`. |
| New adapter result | A newly observed adapter result gets a new key (and increments `attempt`). |
| Stale version | Odoo answers `409` when `configuration_version` is older than its current version. Middleware dead-letters the saga with `STALE_CONFIGURATION_VERSION` and never retries. |
| Odoo 5xx / unreachable | Bounded transient retry under the saga lease (`odoo_campaign_saga_lease_seconds`, `odoo_campaign_saga_retry_limit`). |

### Binding and kill-switch policy

| Environment | Reads (`campaigns.read`, `desired_state.read`) | Writes (`automation_results.apply`, `provider_activities.create`, `campaign.actual_state.write`) |
| --- | --- | --- |
| staging | unscoped binding, active | binding scoped to TEST_SYN only (organization `TEST_SYN_TENANT`, business unit `TEST_SYN`, campaign `TEST_SYN`), active |
| production | unscoped binding, active | unscoped binding, `kill_switch=true` until a separate reviewed activation revision |

The saga worker itself is off by default (`odoo_campaign_saga_enabled=False`;
compose service `middleware-odoo-campaign-saga-worker`). In staging the worker
also dead-letters at enrollment (`SCOPE_NOT_ALLOWED`, no Odoo or provider call)
any control event whose scope triple is not the TEST_SYN binding above; the
binding is the catalog's `registry_policy_0066.staging.write_binding` and
migration 0066 snapshots it. Downgrading 0066 removes only the `66000000-*`
rows and refuses to drop `odoo_campaign_saga` while rows exist; the 0054
campaign-actions route stays kill-switched and is never reactivated.

### Saga durability rules

- One saga per `integration_event` (`uq_odoo_campaign_saga_event`); a losing
  concurrent enroller rolls back and skips.
- `attempts` increments only when a claim starts. Lease recovery and failure
  recording never touch it; recovery dead-letters at the retry limit.
- Every write after the claim (lease renewal, observation, terminal
  transition) is an `UPDATE ... WHERE status='RESERVED' AND attempts=<claim>
  AND reserved_at=<claim>`; zero rows means the reservation was lost to lease
  recovery or another worker and the dispatch aborts before any further side
  effect. The row is re-read from the database at dispatch start, never from
  the session identity map.
- Each enrollment and terminal transition writes an `audit_event`
  (`odoo.campaign_saga.enrolled|completed|stale|retry|dead_letter`).

### Scopes

| Purpose | Scope |
| --- | --- |
| Actual-state readback | `odoo.campaign.actual_state.write` |
| Automation results (n8n CRM actions) | `odoo.integration.automation_results.write` |
| Provider activities (VICIdial/Telnexa projection) | `odoo.integration.provider_activities.write` |
| Campaign-control reads | `odoo.campaign.control.read` |
| n8n submission to Middleware | `n8n.results.submit` |
| n8n readback from Middleware | `n8n.results.read` |
| Caller reads through Middleware (`GET /api/v1/integrations/odoo/campaigns/...`) | `odoo.campaigns.read` |

Middleware must never receive `odoo.campaign.control.write`. Keycloak desired
state for every direction is `deploy/keycloak/campaign-control-service-clients.v1.json`
(validated against this catalog and the edge contract by
`tests/test_keycloak_campaign_control_grants.py`).

### Edge exposure (Caddy -> Kong -> middleware-integration-api)

`deploy/public-api-route-contract.json` (pinned by
`deploy/public-api-route-contract.sha256`) is the only list of method+path
pairs the edge exposes for this service. The in-process guard policy shared by
`app.main` and the deployed `integration_api` entrypoint lives in
`app/core/route_policy.py`; `scripts/audit_release_endpoints.py` fails on any
drift between contract, policy and runtime, and
`scripts/probe_edge_route_contract.py` proves the live staging path forwards
exactly those routes, enforces the JWT inside Middleware, and no longer
serves the retired campaign-actions/campaign-commands paths. Campaign reads
accept only the dedicated reader clients in `ODOO_CAMPAIGN_READER_CLIENT_IDS`
(never the agent-UI client list) and pin the token's `environment` claim.
