# Master Lead Lifecycle and Campaign Recycling Engine v1 (MCR-A)

Status: **contract only**. MCR-A adds the contract and authority layer for the
engine. It adds no migration, runtime handler, route registration, provider
call, or production activation. `config/campaign-recycling-policy.v1.json`
records `lock_decision: NO_GO`. Existing channel capabilities remain `false` in
`config/capabilities.v2.json`; WhatsApp is contract-frozen but runtime-blocked until
Middleware PR #316 lands with `WHATSAPP_DELIVERY=false` and exact-head certification.

## Artifacts

| Artifact | Purpose |
| --- | --- |
| `contracts/campaign-recycling/authority.v1.json` | Authority matrix, reused foundations, sender identity rule, known conflicts |
| `contracts/campaign-recycling/lifecycle.v1.schema.json` | Cross-channel lifecycle transition record and legal transitions |
| `contracts/campaign-recycling/channel-health.v1.schema.json` | Per-channel health, suppression scope/precedence, suppression request |
| `contracts/campaign-recycling/exposure-ledger.v1.schema.json` | Durable touch identity, idempotency and concurrency invariant |
| `contracts/campaign-recycling/next-action.v1.schema.json` | Deterministic decision document and reason codes |
| `contracts/campaign-recycling/delivery-event.v1.schema.json` | Unified delivery/engagement taxonomy, dedupe and replay |
| `contracts/campaign-recycling/campaign-engine.openapi.yaml` | Canonical API (contract only) |
| `config/campaign-recycling-policy.v1.json` | Frequency, cooldown, cooling, reactivation, and sender policy |
| `scripts/validate_campaign_recycling_contracts.py` | Fail-closed validator |
| `tests/test_campaign_recycling_contracts.py` | Focused tests |

Validation: `python3 scripts/validate_campaign_recycling_contracts.py` and
`python3 -m pytest tests/test_campaign_recycling_contracts.py`.

## Reused foundations (referenced, not duplicated)

- `docs/operations/campaign-registry/lead-eligibility.md` — calling-specific
  identity and dialing eligibility. It stays the only dialing authority.
- `app/core/campaign_identity.py` — the immutable campaign-scoped lead ID. The
  `LeadId` pattern in the lifecycle schema is that module's `LEAD` format.
- `app/core/lead_automation.py` — the lead automation state machine. The
  exposure idempotency key uses the same `canonical_hash` canonicalization, and
  replay conflicts behave the same way (same digest returns the original result;
  a different digest is a conflict that is quarantined).
- `app/communications.py` — current runtime email/SMS/voice channel registry,
  `MessageStatus`, `CHANNEL_COMMAND`, and the generic send-time suppression set.
  The frozen desired channel set is `email`, `sms`, `whatsapp`, `voice`. WhatsApp
  execution remains blocked until Middleware PR #316 and Evolution are certified.
- `app/email_production_control.py` — email production authorization,
  approved domains and senders, kill switch, and quotas. Sender identity
  selection can only choose identities that this module has authorized.
- `migrations/versions/0056_klyrow_delivery_event_inbox.py` — durable Klyrow
  delivery inbox. Raw Klyrow events stay there. Normalized events carry
  `origin.inbox` so projecting the same row again cannot create a duplicate.
- `migrations/versions/0066_reconcile_odoo_campaign_scope.py` — Odoo campaign
  control and readback authority. The test policy profile uses the same
  `TEST_SYN` binding.
- Campaign design (`app/core/campaign_design_contract.py`), canonical
  command/event envelopes, `contracts/http-conventions.md`, and the default-deny
  capability registry.

## 1. Cross-channel lifecycle

States: NEW, VALIDATED, ELIGIBLE, ACTIVE_CYCLE, ENGAGED, COOLING,
REACTIVATION, CONVERTED, SUPPRESSED.

| From | Legal targets |
| --- | --- |
| (none) | NEW (`LEAD_REGISTERED`) |
| NEW | VALIDATED, SUPPRESSED |
| VALIDATED | ELIGIBLE, SUPPRESSED |
| ELIGIBLE | ACTIVE_CYCLE, CONVERTED, SUPPRESSED |
| ACTIVE_CYCLE | ENGAGED, COOLING, CONVERTED, SUPPRESSED |
| ENGAGED | ACTIVE_CYCLE, COOLING, CONVERTED, SUPPRESSED |
| COOLING | REACTIVATION, CONVERTED, SUPPRESSED |
| REACTIVATION | ACTIVE_CYCLE, ENGAGED, COOLING, CONVERTED, SUPPRESSED |
| CONVERTED | SUPPRESSED |
| SUPPRESSED | none (absorbing) |

The engine can contact a lead only in ELIGIBLE, ACTIVE_CYCLE, ENGAGED, or
REACTIVATION. The other states force `eligible=false` in every decision.

Terminal semantics: CONVERTED is outreach-terminal. After conversion, Odoo
human sales owns the lead, and the only legal exit is SUPPRESSED. SUPPRESSED is
absorbing and there is no release operation in v1. Only a `global` suppression
moves a lead to SUPPRESSED. Channel and campaign suppressions never change the
lifecycle state.

**Separation from dialing.** This lifecycle is not the dialing contract. The
identity states (ID_ASSIGNED … ARCHIVED) and the dialing states (NOT_ELIGIBLE …
CLOSED) stay in `lead-eligibility.md`. Lifecycle ELIGIBLE never implies dialing
ELIGIBLE. A voice candidate also needs dialing state ELIGIBLE, or it is rejected
with `DIALING_NOT_ELIGIBLE`. In v1, voice can be planned but not executed
(`CHANNEL_EXECUTION_NOT_SUPPORTED`).

## 2. Channel health

Per-channel states: `unknown`, `valid`, `possible`, `soft_bounce`,
`hard_bounce`, `complained`, `unsubscribed`, `suppressed`, `invalid`.

| State | Contact semantics |
| --- | --- |
| `unknown` | blocked until validated (fails closed) |
| `valid` | contactable |
| `possible` | allowed only when policy sets `possible_is_contactable` |
| `soft_bounce` | deferred for `soft_bounce_retry_after_seconds`; escalates to `hard_bounce` after `soft_bounce_escalation_count` |
| `hard_bounce`, `invalid` | blocked |
| `complained`, `unsubscribed`, `suppressed` | blocked, and a suppression record is required |

Every record carries `source`, `reason_code`, `occurred_at`, `recorded_at`,
and an `evidence` object (kind, hash, optional event/provider references).
Addresses appear only as opaque `address_ref` values.

**A bad email never invalidates SMS, WhatsApp, or voice.** Automatic signals are
channel-local (`cross_channel_effect: "none"`). A lead-wide block is only ever
an explicit `global` suppression from `operator`, `data_subject_request`, or
`leads_authority`.

**Suppression scope and precedence.** Scopes, from highest to lowest:
`global`, `channel`, `campaign`, `campaign_channel`. Reasons, from highest to
lowest: `legal_hold`, `data_subject_request`, `do_not_contact_request`,
`complaint`, `unsubscribe`, `consent_revoked`, `dialing_do_not_call`,
`operator_block`. Any suppression that matches blocks the candidate. When more
than one matches, the reported reason is chosen by scope, then reason, then
earliest `occurred_at`, then `suppression_id`. No positive signal lifts a
suppression. The existing communications suppression set stays in place as the
last-line send gate: `global` maps to its `(tenant_id, subject)` tuple and
`channel` maps to `(tenant_id, channel, subject)`.

## 3. Exposure ledger

Identity: `tenant_id × lead_id × campaign_id × campaign_version × channel ×
touch_index`. Each row carries status and outcome timestamps, `correlation_id`,
`command_id` (from the canonical command envelope), `provider_message_id`, and
`idempotency_key = "mcr1:" + sha256(canonical natural key)`.

**Dedupe and concurrency invariant.** Reservation is one insert-if-absent on
the natural key, which also makes `(tenant_id, idempotency_key)` unique. It
runs in the same transaction as the outbox command. The writer that loses a
race reads the existing row and emits nothing. If a replay arrives with the
same key but a different digest, the service returns 409 and quarantines it.
The same planned touch can therefore never be issued twice. Transport-terminal
statuses never regress, and engagement and negative outcomes can only move up
their rank.

## 4. Frequency and cooldown policy

`config/campaign-recycling-policy.v1.json` defines these parameters:

- a global contact cap per channel (`channel_caps.<channel>.max_touches` and
  `window_seconds`)
- a per-campaign cooldown and a touch budget per campaign version
- lifetime and recent-window exposure caps
- cooling entry and minimum cooling duration
- a reactivation cycle limit, where each reactivation must use a different
  campaign version
- soft-bounce handling

**Every value is configuration.** Only the synthetic `test` profile, which is
bound to `TEST_SYN`, has values. `staging` and `production` are `null`, so the
engine fails closed with `POLICY_NOT_CONFIGURED` until a reviewed change
supplies them. Code defaults are forbidden. Suppression always overrides
eligibility.

## 5. Next-action decision

Fields: `eligible`, `selected` (campaign, version, channel, sender identity,
touch index, exposure idempotency key), `next_eligible_at`, `policy_version`,
ordered `reason_codes`, and `candidates` with a disposition and reason codes
for each. Candidates are redacted unless the caller holds
`campaign.engine.candidates.read`. `provider_effects` is always `none`. The
`plan` and `read` modes are dry runs. `execute` only reserves exposures and
queues commands.

Reason codes, listed in evaluation order (a decision's `reason_codes` are
sorted in this order):

| Code | Class |
| --- | --- |
| `POLICY_NOT_CONFIGURED` | fail closed |
| `PRODUCTION_NOT_AUTHORIZED` | fail closed (execute only) |
| `KILL_SWITCH_OPEN` | fail closed |
| `EVIDENCE_STALE_OR_CONFLICTING` | fail closed |
| `SUPPRESSED_GLOBAL` | suppression |
| `SUPPRESSED_CHANNEL` | suppression |
| `SUPPRESSED_CAMPAIGN` | suppression |
| `SUPPRESSED_CAMPAIGN_CHANNEL` | suppression |
| `LIFECYCLE_TERMINAL` | blocking |
| `LIFECYCLE_NOT_CONTACTABLE` | blocking |
| `CONSENT_MISSING` | blocking |
| `DIALING_NOT_ELIGIBLE` | blocking |
| `CHANNEL_HEALTH_BLOCKED` | blocking |
| `CHANNEL_HEALTH_UNKNOWN` | blocking |
| `CHANNEL_HEALTH_POLICY_GATED` | blocking |
| `CHANNEL_HEALTH_DEFERRED` | temporal |
| `CAMPAIGN_NOT_ACTIVE` | blocking |
| `CAMPAIGN_VERSION_NOT_APPROVED` | blocking |
| `SENDER_IDENTITY_NOT_AUTHORIZED` | blocking |
| `SENDER_IDENTITY_UNAVAILABLE` | blocking |
| `CHANNEL_EXECUTION_NOT_SUPPORTED` | blocking |
| `DUPLICATE_TOUCH` | blocking |
| `COOLING_PERIOD_ACTIVE` | temporal |
| `REACTIVATION_LIMIT_REACHED` | blocking |
| `LIFETIME_EXPOSURE_CAP_REACHED` | blocking |
| `RECENT_WINDOW_CAP_REACHED` | temporal |
| `CHANNEL_CAP_REACHED` | temporal |
| `CAMPAIGN_COOLDOWN_ACTIVE` | temporal |
| `CAMPAIGN_VERSION_EXHAUSTED` | blocking |
| `NO_CANDIDATE` | blocking |
| `ELIGIBLE` | eligible |

`next_eligible_at` is `null` when the lead is eligible. It is also `null` when
unblocking needs a state change rather than time. Otherwise it is the earliest
time at which some candidate blocked only by temporal constraints clears all of
them.

## 6. Delivery and engagement events

Taxonomy: `accepted`, `queued`, `dispatched`, `delivered`, `deferred`,
`soft_bounce`, `hard_bounce`, `complaint`, `unsubscribe`, `open`, `read`,
`click`, `reply`, `conversion`. Every event carries `source`, `provider`, `event_id`,
`schema_version`, `occurred_at`, `received_at`, and `payload_hash`.

**Open/read events are weak signals.** Email machine prefetch/privacy proxies can
produce opens, and channel/provider behavior can produce read-like signals. Neither
open nor WhatsApp read changes the lifecycle, ends cooling, or resets a cap. Clicks
and replies are strong signals. A click
flagged `automated_suspected` counts as weak. Conversions are the strongest
signal. `complaint` and `unsubscribe` add a suppression on the same channel
only.

Dedupe identity is `(source, event_id)`. A replay with the same digest returns
`duplicate=true` and applies nothing. A replay with a different digest gets 409
`replay_conflict` and is quarantined. Effects do not depend on arrival order.
Operator replay goes through an audited command and never bypasses any check.
Every raw `KlyrowDeliveryEvent` type is mapped. A bounce with an unknown class
fails closed to `hard_bounce`.

## 7. Canonical API (contract only)

- POST /platform/v1/campaign-engine/plan
- POST /platform/v1/campaign-engine/execute
- GET /platform/v1/leads/{lead_id}/journey
- GET /platform/v1/leads/{lead_id}/next-action
- GET /platform/v1/campaigns/{campaign_id}/eligible-leads
- POST /platform/v1/delivery-events
- POST /platform/v1/suppressions
- GET /platform/v1/campaign-engine/status

These rules apply to every operation:

- **Auth:** a Keycloak JWT with audience `middleware-api` and exactly one
  OAuth scope per operation.
- **Required headers:** `X-Tenant-ID` and `X-Correlation-ID`.
- **Idempotency:** `Idempotency-Key` is required on execute, delivery-events,
  and suppressions.
- **Signatures:** delivery-events also requires the signed-webhook headers.
- **Pagination:** opaque, tenant-bound cursors.
- **Errors:** the canonical error envelope from `contracts/http-conventions.md`.

Plan, next-action, and eligible-leads are always dry runs with no effects.
`EngineStatus` pins `engine_enabled`, `execute_enabled`,
`production_authorized`, and the channel capabilities to `false` in v1.

## 8. Authority matrix

| System | Authority |
| --- | --- |
| Leads | identity, lifecycle, channel state, suppressions, journey read model |
| Middleware | policy decisioning, next-action, exposure ledger, command/idempotency, normalization, reconciliation, send-time suppression gate |
| Klyrow | email/SMS campaign business definitions and versions; email templates/sender identities/delivery events |
| Telnexa | SMS sender/transport/provider delivery state behind Middleware |
| Codestra WhatsApp | WhatsApp channel contacts, consent/suppression evidence, templates, campaigns/audiences, sender identity and conversations |
| Evolution API | thin WhatsApp provider/session/translation/webhook/health adapter behind Middleware; never command authority |
| VICIdial | voice execution/call state; MCR v1 voice execution remains unsupported |
| Odoo | CRM, opportunities, human sales, conversion facts, CRM campaign control |
| N8N | post-acceptance automation only; never decides, overrides suppression, or writes providers |
| Thunderbird | human mail client only; never sends campaign touches |
| Keycloak | identity and scope grants |
| OpenBao | secrets; contracts hold references only, never values |
| Kong | routing, traffic policy, rate limits |
| Caddy | public TLS and host allowlist |
| Observability | metrics/logs/traces keyed by correlation ID; never a decision input, and never raw addresses |

## 9. Sender identity rule

Sender identities are channel-specific but always legitimate, brand/campaign-owned,
verified for that channel, policy-governed, and recorded on every decision/exposure.
Email identity authority is Klyrow; SMS sender authority is Telnexa; WhatsApp
business sender identity is owned by Codestra WhatsApp and transported by Evolution;
voice caller identity is VICIdial-governed but v1 execution is unsupported.
`app/email_production_control.py` remains the email-specific production gate.

Rotating domains, identities, or address formats to evade spam filters,
reputation checks, or provider controls is forbidden. So is using lookalike or
throwaway domains. An unauthorized identity is rejected with
`SENDER_IDENTITY_NOT_AUTHORIZED`, and the engine never substitutes another one.

## Frozen architecture decisions / deferred dependencies

1. Campaign authority is channel-specific: Klyrow owns email/SMS business campaign
   definitions and versions; Codestra WhatsApp owns WhatsApp campaign/template/audience
   business state; Odoo remains CRM/human-sales authority.
2. The canonical campaign identifier is namespaced. Klyrow campaigns use
   `klyrow:<raw_id>` and WhatsApp campaigns use `whatsapp:<raw_id>`.
   Raw provider, Odoo, or VICIdial campaign IDs are rejected.
3. Leads and Thunderbird are mission-scoped authorities even though they are not yet
   registered in `system-ownership.v2.json`; registration is a Milestone 30 task and
   may not change the ownership frozen here.
4. WhatsApp is part of the desired channel contract. Provider execution is
   `blocked_pending_dependency` until Middleware PR #316 and the Evolution/WhatsApp
   integration contracts are merged and certified. Milestone 10 may implement pure
   lifecycle/planning logic without provider effects.
