# Master Lead Lifecycle & Campaign Recycling Engine — Runtime & Product Design

Status: MCR-C implementation design. MCR-A remains frozen at `b3f44dd4b8ad8976f10394051d2f13cc17443155`. This document describes runtime implementation but does not authorize provider effects or change frozen business authority.

## Product objective

The engine must answer: for this lead, what is the next legitimate campaign/channel action, why is it allowed or blocked, when can it happen, and what durable evidence proves the decision and every later effect?

Canonical flow:

`Lead intake -> validation -> lifecycle/channel health -> suppression check -> campaign/version candidates -> deterministic policy decision -> dry-run plan -> authorized execute reservation -> command/outbox -> provider adapter -> delivery event -> exposure/lifecycle projection -> Odoo/human handoff or cooldown -> reactivation/suppression`

Provider execution is not authorized by this MCR-C runtime phase.

## Authority boundaries

| Authority | Owns | Must not own |
| --- | --- | --- |
| Leads | lead identity, lifecycle truth, channel state, journey UI/read-model visibility | provider transport or campaign execution |
| Middleware | deterministic policy decision, next-action, exposure ledger, command/idempotency, normalized delivery events, reconciliation/readback | campaign content, CRM opportunity truth, sender creation |
| Klyrow | email/SMS campaign definitions and immutable versions, templates, approved sender identities, email delivery authority | master lead lifecycle or CRM |
| Codestra WhatsApp | WhatsApp campaign/template/audience/contact/consent/business-sender truth | Middleware policy decision |
| Evolution | thin WhatsApp transport/session/webhook adapter | campaign or policy authority |
| Telnexa | SMS transport/sender/provider state | cross-channel decisioning |
| VICIdial | voice execution/call state | master MCR lifecycle |
| Odoo | CRM, opportunity, salesperson/human-sales state and conversion facts | bulk campaign scheduler |
| N8N | post-acceptance workflow automation | canonical business decisioning or direct database authority |
| Thunderbird | human reply/mail client | automated campaign sending |
| Keycloak | user/service identity, audience, roles/scopes | business decisioning |
| OpenBao | secret references/rotation policy | application business logic |
| Kong | authenticated routing, scope/rate/size policy, anti-spoofing | business authority |
| Caddy | public TLS and host/path edge allowlist | application authorization |
| Observability | metrics/logs/traces/SLO and incident evidence | decision input or raw PII storage |

## Lifecycle state machine

Canonical states:

`NEW -> VALIDATED -> ELIGIBLE -> ACTIVE_CYCLE -> ENGAGED / COOLING / REACTIVATION / CONVERTED / SUPPRESSED`

Rules:
- only ELIGIBLE, ACTIVE_CYCLE, ENGAGED and REACTIVATION are contactable;
- CONVERTED is outreach-terminal and routes to human/CRM ownership;
- SUPPRESSED is absorbing in v1;
- only global suppression changes lifecycle to SUPPRESSED;
- channel/campaign suppression blocks eligibility without destroying unrelated valid channels;
- voice eligibility remains separate from MCR lifecycle eligibility.

## Channel health and suppression

Channel health is independent per address/channel:
`unknown, valid, possible, soft_bounce, hard_bounce, complained, unsubscribed, suppressed, invalid`.

Suppression is evaluated before normal eligibility.

Scope precedence: global, channel, campaign, campaign_channel.

Reason precedence: legal_hold, data_subject_request, do_not_contact_request, complaint, unsubscribe, consent_revoked, dialing_do_not_call, operator_block.

Positive engagement never lifts suppression. A global suppression and lifecycle transition to SUPPRESSED must commit atomically.

## Deterministic decision flow

1. Load tenant-bound lifecycle snapshot.
2. Load channel health using opaque address references.
3. Load active suppressions.
4. Load exposure history.
5. Load reviewed policy version.
6. Load campaign/version candidates from the correct business authority.
7. Normalize candidates into Middleware Candidate inputs.
8. Evaluate fail-closed conditions.
9. Evaluate suppression.
10. Evaluate lifecycle/contactability.
11. Evaluate consent/dialing/channel health.
12. Evaluate campaign/version/sender authority.
13. Evaluate duplicate touch.
14. Evaluate cooling/reactivation rules.
15. Evaluate lifetime/recent/channel/campaign caps.
16. Sort deterministically by priority, namespaced campaign ID, version, channel order and touch index.
17. Produce one selected action or an ordered reason-code result.
18. Compute decision_hash over all material decision inputs and outputs, excluding only decision_id, evaluated_at and correlation_id.
19. Serialize to frozen next-action.v1 when a caller needs the wire shape.

There are no hidden business defaults. An unconfigured policy fails closed with POLICY_NOT_CONFIGURED.

## Exposure identity and exactly-once intent

Natural touch identity:
`tenant_id x lead_id x campaign_id x campaign_version x channel x touch_index`

Exposure idempotency key:
`mcr1: + sha256(canonical natural-key JSON)`

Rules:
- reservation is insert-if-absent;
- natural-key and idempotency uniqueness are durable;
- execute reservation and command/outbox intent must be atomic;
- losing concurrent writer emits no new effect;
- same idempotency key + same request returns prior result;
- same key + different digest returns 409 and is quarantined;
- provider calls never occur directly from decision logic.

## Canonical API behavior

### POST /platform/v1/campaign-engine/plan
Pure dry-run planning. Requires middleware-api audience, campaign.engine.plan scope, X-Tenant-ID, X-Correlation-ID and strict PlanRequest. No provider call or durable effect. Currently fail-closed until certified tenant-bound campaign/version candidate authority is wired.

### POST /platform/v1/campaign-engine/execute
Re-evaluates an approved plan, checks stale-plan hash, then would atomically reserve exposure + command/outbox. Current phase always returns 403 production_not_authorized; no config toggle may silently open this boundary.

### GET /platform/v1/leads/{lead_id}/journey
Tenant-bound read model returning lifecycle, transitions, channel health and exposures. Uses a signed opaque cursor bound to tenant, lead and limit. Weak/missing cursor signing key fails closed.

### GET /platform/v1/leads/{lead_id}/next-action
Read-mode dry-run decision with provider_effects=none. Candidate details require the separate candidate-read scope. Currently fail-closed until candidate authority is certified.

### GET /platform/v1/campaigns/{campaign_id}/eligible-leads
Governed campaign eligibility projection using namespaced MCR campaign IDs only. No VICIdial raw-ID substitution. Currently fail-closed until candidate/audience authority is certified.

### POST /platform/v1/delivery-events
Service JWT + publish scope, raw-body signature before JSON parse, timestamp window, event/header binding, Idempotency-Key `<source>:<event_id>`, tenant/source/correlation/causation binding and canonical payload hash. Same replay returns duplicate=true; changed evidence returns 409 replay_conflict. Events requiring channel-health address evidence fail closed until the normalized contract carries a certified opaque address_ref.

### POST /platform/v1/suppressions
Exact write scope, tenant/correlation headers, Idempotency-Key and strict frozen request. Key hash includes tenant. Same request replay returns original ack; different request under the same key returns 409. Global suppression + lifecycle transition commit together; narrower suppression never mutates lifecycle.

### GET /platform/v1/campaign-engine/status
Non-secret readback remains contract_only with engine_enabled=false, execute_enabled=false, production_authorized=false and all provider capabilities false.

## Authentication and tenant isolation

Every operation must enforce bearer token presence, canonical Keycloak validation, middleware-api audience, exact operation scope, X-Tenant-ID binding, no body tenant override, duplicate-header rejection and 503 on missing durable dependencies. Delivery publishers additionally bind azp to the approved source mapping.

## Error model

Canonical envelope: code, bounded message, correlation_id, retryable and details. Never return raw SQL, stack traces, tokens, signatures, addresses or secret values.

Important mappings:
- 400 invalid_request / invalid_cursor
- 401 authentication_required / signature_invalid / timestamp_out_of_window
- 403 scope_denied / tenant_scope_denied / production_not_authorized
- 404 lead_not_found / campaign_not_found
- 409 idempotency_conflict / replay_conflict / plan_stale / lifecycle_version_conflict
- 422 contract_violation / unsupported_schema_version
- 503 policy_not_configured / dependency_unavailable / engine_disabled

## UI / operator experience

MCR-B must expose journey timeline, lifecycle, independent channel-health states, suppression reason/scope, exposure timeline, next action/reason, next eligible time, campaign/version/channel/sender attribution and human-handoff state.

Every async surface needs explicit loading, empty, error, retry, permission-denied and stale/readback-conflict states. Never render a successful empty state for auth/dependency/reconciliation failure.

## Recovery and reconciliation

Required: durable exposure readback by natural/idempotency key, command/operation readback, unknown outcome -> reconciliation_required, dead-letter evidence, authenticated/audited replay, safe replay of partial delivery-event projection, restart-safe lifecycle/exposure/suppression truth and rollback that never deletes durable MCR evidence.

## Observability

Metrics: decisions by reason, eligible leads, plan requests, execution denied/reserved, suppressions by scope/reason, delivery events by source/type, duplicate events, replay conflicts, exposure status, cooldown/reactivation depth, reconciliation_required, dead letters, dependency failures and latency/error rate.

Logs/traces use correlation-safe opaque identifiers and policy/result metadata. Never log bearer tokens, webhook signatures, raw addresses or secret values.

## Dependency-safe mission chain

### MCR-C — Middleware
C2 canonical API/auth/error boundary.
C3 journey durable readback/cursor.
C4 delivery-event ingress/replay.
C5 suppression ingestion/idempotency/atomic lifecycle.
C6 certified campaign/version/audience candidate authority. The machine-readable readiness gate is config/campaign-recycling-candidate-authority.v1.json; current Klyrow campaign definitions/preflight are explicitly insufficient because they do not provide immutable campaign versions or authoritative per-lead audience membership.
C7 plan + next-action + eligible-leads runtime evaluation using C6.
C8 execute reservation/outbox with provider effects still disabled.
C9 readback/reconciliation/DLQ/replay evidence and observability.
C10 exact OpenAPI/Postman/route-authority parity and release handoff.

### MCR-B — Leads
Starts after stable C read contracts: lifecycle/channel/suppression authority reconciliation, journey UI, next-action UI, loading/error/empty/retry states and tenant/permission negative tests.

### MCR-D — Klyrow
Starts after C campaign/runtime contracts stabilize: immutable campaign/version API, candidate/audience read authority, approved sender identities, journey definitions and normalized delivery events. No live send until release approval.

### MCR-H/I/J/K — platform
Parallel only in clean worktrees: H Keycloak scopes/service clients; I OpenBao secret references; J Kong MCR routes/rate/size/signature policy; K Caddy TLS edge allowlist to Kong only.

### MCR-E — Odoo
After C normalized engagement/conversion events: CRM handoff, source attribution, owner assignment, human follow-up, conversion feedback and automation pause rules.

### MCR-F — N8N
After authoritative APIs exist: enrichment, notifications, assignment, result routing and retry-safe post-acceptance jobs. N8N never decides eligibility or writes canonical state directly.

### MCR-G — Thunderbird
After stable read APIs: human compose/reply workflow and governed activity callback. No bulk campaign engine.

### MCR-L — observability/deliverability
Metrics/logs/traces, provider/sender health, bounce/complaint alerts, reconciliation drift and aggregate campaign/sender deliverability.

### MCR-M — QA/staging/release
Exact SHA/digest, contract tests, auth/tenant negatives, concurrency/idempotency/replay, webhook signature tests, restart/recovery, rollback proof, approved synthetic recipients only, post-deploy readback and separate production-effect approval.

## Automatic completion handoff

An agent completion message is never sufficient.

Before marking complete:
1. inspect exact repo/worktree/branch;
2. record local HEAD and upstream/remote SHA;
3. verify intended dirty/clean state;
4. inspect changed files and ownership;
5. run lane tests and frozen validators;
6. run generated OpenAPI/schema/route checks;
7. run git diff --check;
8. verify commit from owning workstation terminal;
9. perform only normal non-force branch push;
10. read remote SHA and require exact local equality;
11. update Linear and Notion with evidence;
12. start only the next dependency-safe lane in a clean worktree.

If Git is blocked, record exact host/repo/worktree/branch/local SHA/remote SHA, dirty state, failed command/error, whether remote changed and safe next action. Never bypass through another write path.

## Continuous betterment gate

After every slice ask: can this flow be simpler, safer, more deterministic, easier to recover, or easier for an operator to understand without creating duplicate authority?

Review duplicate state/authority, hidden defaults, unnecessary hops, non-atomic writes, weak tenant binding, replay gaps, ambiguous errors, missing UI states, observability gaps, recovery gaps and generated-contract drift.
