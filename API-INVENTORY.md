# API Inventory — Milestone 1

Scope of this pass: the Milestone 2 core surface (session context, identity,
tenants, campaigns, channels), provisioning, the Keycloak lifecycle adapter,
telephony/WebRTC, calls, email, SMS, and provider-event ingestion. This is
the 20% of the canonical registry that everything else (billing, compliance,
operations, audit-as-a-product-feature, bulk, search, SDKs) depends on.
Those remaining areas are **not yet inventoried** — see "Not yet covered"
at the end.

Every row below is backed by a real file/route I read in this pass, not
assumed. `EXISTS` means real, running code; `BUILD` means genuinely absent;
`EXTEND` means a real implementation exists under a different shape/path
and the canonical layer should call it, not replace it.

## Session context & authorization

| Capability | Status | Evidence |
|---|---|---|
| Keycloak token validation | EXISTS | `app/core/jwt_auth.py` (`KeycloakValidator`), reused by `app/core/platform_auth.py` (human roles) and `app/core/provisioning_auth.py` (machine scope, built this session) |
| `GET /platform/v1/session/context` | BUILD | No route exists anywhere in Middleware. Must be built on top of the existing validator, not a new auth stack. |
| Centralized `authorize()` policy function | BUILD | Every existing check (`require_platform_scope`, `require_provisioning_scope`, Odoo's `_require_super_admin`/`_has_tenant_admin_scope`) is a local, per-model/per-route check today - real, tested, but not centralized. Centralizing is a real refactor, not a greenfield build. |
| Permission vocabulary / registry | BUILD | No `permission` string list or mapping exists in either repo today. |

## Identity / platform users

| Capability | Status | Evidence |
|---|---|---|
| `codestra.platform.user` (Odoo) | EXISTS | `codestra_identity_provisioning/models/platform_user.py` - `public_id`, `primary_email`, `keycloak_subject`, `platform_role`, `odoo_access_enabled`/`odoo_user_id`, channel enable flags, `status`, `provisioning_state`. Shipped this session (PR #120). |
| Global role (`platform_admin`/`platform_operator`) | EXISTS | `platform_role` field + `_sync_platform_role_group()`, three flat Odoo groups. Shipped this session. |
| `GET /platform/v1/users`, `/users/{id}` (Middleware) | BUILD | No route exists. Needs a live read into Odoo - see "Odoo read path" below. |
| `/users/{id}/memberships`, `/channels`, `/telephony`, `/activity` | BUILD | Same - no route, and "activity" specifically has no backing timeline model anywhere yet (see Activity below). |

## Tenants

| Capability | Status | Evidence |
|---|---|---|
| `codestra.tenant` (Odoo) | EXISTS | `codestra_identity_provisioning/models/tenant.py` |
| `codestra.tenant.membership` (Odoo, tenant_admin/member) | EXISTS | `codestra_identity_provisioning/models/tenant_membership.py`. Shipped this session. |
| `GET /platform/v1/tenants*` (Middleware) | BUILD | No route exists. |
| Subscription/limits/usage per tenant | BUILD | No subscription/plan/quota model exists anywhere in Odoo or Middleware. This is genuinely new (Milestone 6 territory), not misfiled. |

## Campaigns / campaign membership

| Capability | Status | Evidence |
|---|---|---|
| `cc.campaign` (Odoo) | EXISTS | `codestra_cc_core`, own menu/action (`action_cc_campaigns`) already reused by this session's Milestone 2 admin console. |
| `cc.campaign.membership` (role=supervisor/agent, username, email identity) | EXISTS | `codestra_cc_security/models/campaign_security.py` + `codestra_agent_onboarding` extensions. This is the canonical campaign-role source per the mission's own section 3 - already correctly reused, not duplicated, throughout this session. |
| `GET /platform/v1/campaigns*` (Middleware) | BUILD | No route exists. |

## Channels

| Capability | Status | Evidence |
|---|---|---|
| `codestra.agent.channel` (Odoo) | EXISTS | Field shape is an *exact* match for the canonical registry's channel response contract: `desired_enabled`, `requested_state`, `provisioned_state`, `effective_access`, `provider`, `provider_reference`, `last_verified_at`, `last_error_code`/`last_error_message`. This is not a coincidence - it was standardized to this shape earlier in this session. |
| `GET /platform/v1/users/{id}/channels[/{channel}]` (Middleware) | BUILD | No route; would project `codestra.agent.channel` rows read live from Odoo. |

## Provisioning

| Capability | Status | Evidence | 
|---|---|---|
| Provisioning saga (`REQUESTED→...→EFFECTIVE/PARTIAL/FAILED/RECONCILING/SUSPENDED/REVOKED`) | EXISTS | `app/api/v1/agent_provisioning.py`, built this session (PR #238, Mission 3). Full state machine, step tracking (`AgentProvisioningStep`), Idempotency-Key/X-Correlation-ID/X-Policy-Revision, reconcile/suspend/reactivate/revoke. |
| **Path collision — RESOLVED** | ✅ | **Decision: `/platform/v1/agent-provisioning/requests` is the permanent canonical path for the people/identity/channel provisioning saga. `/platform/v1/provisioning/requests` stays exactly as-is, unchanged, owned by the service-catalog feature.** Rationale: the service-catalog path isn't incidental - it's part of a deliberately designed, already-documented contract (`INTEGRATED-MONITORING-DESIGN.md` lists it alongside `GET/POST /platform/v1/services*`), backed by real migrations (`0057_platform_service_catalog`) and tests (`test_platform_contract.py`, `test_platform_verified_authority.py`, `test_platform_control_plane.py`). Renaming a shipped, documented, migrated HTTP contract to free up a string for an unrelated feature is strictly worse than giving the two genuinely different domains (infrastructure-service admission vs. human identity/channel provisioning) two distinct, clearly-named paths - which is also better API design than one ambiguous shared name would have been. No code change was needed: PR #238 already used the now-canonical path. |
| Plan/dry-run endpoint (`POST /platform/v1/provisioning/plans`) | EXTEND | `agent_provisioning.py`'s create endpoint already computes a plan-shaped honest response per step (skipped/blocked/ok) as part of `_advance_saga`; a dedicated dry-run-only endpoint would reuse the same step logic without executing it. |
| Keycloak lifecycle adapter (6 approved ops) | EXISTS | `app/adapters/keycloak/lifecycle_client.py`, built this session. Exactly the allowed-operations list this registry requires (query/create/update-approved-attributes/disable/enable/required-action-email/assign-approved-roles); no realm-admin/impersonation/client-management path exists in the client at all. |

## Telephony / extensions / WebRTC

| Capability | Status | Evidence |
|---|---|---|
| `codestra.extension.assignment`/`.pool` (Odoo) | EXISTS | Rich fields (`vicidial_user`, `incoming_allowed`, `outgoing_allowed`, `webrtc_enabled`, `max_webrtc_endpoints`/`max_active_sessions` pinned to 1, `active_session_reference`, `active_browser_reference`, `provider_reference`), plus `action_adopt_existing_phone_assignment()` for the 6101 bootstrap identity. Shipped this session. |
| `GET /platform/v1/telephony/extensions*`/`assignments*` (Middleware) | BUILD | No route; would read the above live from Odoo. |
| WebRTC session issuance/revoke | EXTEND, not BUILD | **Real, working implementation already exists**: `app/api/v1/webphone.py`, prefix `/webphone-api/v1` - `POST /provision`, `/provision/{id}/refresh`, `/provision/{id}/revoke`, `POST /session`, `POST /renew`, `GET /config`, `POST /revoke`. Currently hard-locked to the staging TEST_SYN/6101 contract (`agent_desktop/docs/provisioning-contract.md`). The canonical `/platform/v1/telephony/webrtc/sessions` should be this endpoint's production-scoped successor or a thin alias in front of it - **do not build a second, parallel WebRTC session issuer.** |
| Vicidialer-Codestra agent/campaign/call ops | EXISTS (agent-level only) | `codestra_vicidial/app.py`: `/v1/agents/sync\|provision-disabled\|disable\|actual-state\|availability`, `/v1/campaigns/validate\|provision-disabled\|disable\|actual-state`, `/v1/calls/originate`, `/v1/calls/internal/*`, `/v1/leads/*`, `/v1/callbacks/*`, `/v1/reconciliation/*`, `/v1/transfer-policies/sync`. `/v1/agents/provision-disabled` and `/v1/agents/availability/{user}/{ext}` are hard-locked to one synthetic break-glass identity (`appolon`/`6901`), not general-purpose despite the path names - confirmed by this session's Mission 4 work. |
| Phone-specific (as opposed to agent-level) or WebRTC-endpoint operations in Vicidialer-Codestra | BUILD | No `/v1/phones/*` or `/v1/webrtc/*` route exists there at all. `AgentSpec` (the general, reusable model) carries no extension/webrtc field - only the narrow synthetic `ProvisionAgentSpec` does. Confirmed this session. |
| Supervisor monitoring (monitor/whisper/barge) | BUILD, and unknown at the adapter layer | No route, model, or mention anywhere in Vicidialer-Codestra. Before building the Middleware API, confirm whether Asterisk/VICIdial itself exposes monitor/whisper/barge at all - this may be a bigger gap than an API wrapper. |

## Calls

| Capability | Status | Evidence |
|---|---|---|
| Call origination | EXISTS | Vicidialer-Codestra `/v1/calls/originate`, `/v1/calls/internal/{originate,{id},{id}/hangup}`; Middleware's own `app/adapters/vicidial/mtls_client.py.originate()` already calls it, fail-closed behind `vicidial_write_enabled`/`live_writes_enabled`/`external_dial_enabled`. |
| `GET /platform/v1/calls`, `/calls/{id}` (list/detail read) | BUILD | No generic call-list/detail read API exists anywhere. |
| Answer/hold/resume/transfer/DTMF | BUILD | Not found in Vicidialer-Codestra's route list. |
| Disposition save | EXISTS elsewhere | `codestra_vicidial_crm`/`codestra_cc_disposition` own disposition models in Odoo (`cc.disposition`, campaign-scoped) - the canonical `PUT /calls/{id}/disposition` should write through to these, not a new disposition store. |
| Recording metadata/playback | EXISTS elsewhere | `codestra_vicidial_recording` (Odoo module) - not inventoried in detail this pass. |

## Email (Klyrow)

| Capability | Status | Evidence |
|---|---|---|
| Organizations/workspace membership | EXISTS | `appolon1908-hue/klyrow.com`, `apps/gateway/app/production_api.py`: `GET/POST /v1/organizations/{id}/members`, `PATCH /v1/organizations/{id}/members/{id}`. |
| Domain/sender/SMTP-credential management | EXISTS | `apps/gateway/app/capabilities.py` + `provider.py`: `/v1/internal/email/domains/register`, `/v1/internal/email/senders/*` (including `/suspend`), `/v1/internal/email/smtp/credentials/*` (including `/revoke`). |
| Message send + idempotency + events + health + reputation | EXISTS | `/v1/internal/email/communications/messages` (POST, idempotent - confirmed by `test_communications_provider.py`), `GET .../messages/{id}`, `.../messages/{id}/events`, `.../domains`, `.../provider-health`, `.../reputation`. Also a named `/v1/internal/email/beyvra/send` path. |
| Klyrow's own architectural contract | EXISTS | `KLYROW_IDENTITY_AUTOMATION_ODOO_CONTROL_PLANE.md` in that repo independently states the *same* system-of-record boundaries this registry assumes (Keycloak=identity, Klyrow=product state, Middleware=only cross-system trust boundary, Odoo=back-office, n8n=non-authoritative). No architectural conflict. |
| Canonical `/platform/v1/email/*` (Middleware) | BUILD, thin adapter over the above | Middleware has no email route today; it should be a real adapter calling Klyrow's existing `/v1/organizations/*` and `/v1/internal/email/*` endpoints, not a reimplementation. |

## SMS (Telnexa)

| Capability | Status | Evidence |
|---|---|---|
| Sender profiles, opt-outs, campaigns, templates, contacts | EXISTS | `appolon1908-hue/telnexa`, `billing/product_api.py`, prefix `/api/v1`: `POST/GET /senders`, `POST/GET /opt-outs`, `POST /campaigns`, `POST /templates`, `POST/GET /contacts`. |
| Messages + webhooks + numbers + subaccounts + rates | EXISTS | `/messages/{id}[/events]`, `/webhooks` (GET/DELETE), `/numbers`, `/subaccounts`, `/rates`. |
| Admin: provider health/circuit-breaker/dispatch/reconciliation/send-gates/finance | EXISTS | `/admin/providers[/{id}[/health]]`, `/admin/providers/{id}/circuit/{action}`, `/admin/dispatch/jobs`, `/admin/provider-events`, `/admin/reconciliation`, `/admin/send-gates[/{id}/close]`, `/admin/finance/summary`. This is a materially more complete "drift/reconciliation/safety-gate" implementation than anything in this registry's Milestone 5/toolset - Telnexa's admin surface should likely inform the *shape* of Middleware's own drift/operations APIs, not be duplicated by them. |
| Provider event ingestion | EXISTS (outbound to Middleware) | `billing/app.py`: `POST /internal/v1/provider-events/jasmin` (Telnexa receiving from its own upstream Jasmin gateway) - not the same thing as Middleware receiving from Telnexa; see next row. |
| Canonical `/platform/v1/sms/*` (Middleware) | BUILD, thin adapter | No SMS route in Middleware today. |
| Canonical `POST /internal/v1/provider-events` (Middleware receiving from Telnexa/Klyrow) | BUILD, vs. two real existing routes | Middleware today has `POST /webhooks/vicidial/call-result/` and `POST /webhooks/sms/inbound/` (`app/api/v1/provider_webhooks.py`) - real, tested, but per-provider, not one normalized envelope. Consolidating under one path is a real refactor of working code, not a greenfield add; do this deliberately; don't run two parallel ingestion mechanisms for the same event once done. |

## Odoo adapter (Middleware side)

| Capability | Status | Evidence |
|---|---|---|
| Read operations wired to Odoo | PARTIAL | `app/adapters/odoo/client.py` declares read operations from `contracts/odoo/campaign-control.v1.json`. Only `campaigns.read` and `desired_state.read` have endpoint-registry rows (migration `0066_reconcile_odoo_campaign_scope`, registered as `POST /api/v1/integration/campaigns/read` and `POST /api/v1/integration/desired-state/read`, scope `odoo.campaign.control.read`) and are resolvable and callable. `agents.read`, `leads.read`, `traces.read`, `telephony.projections.read`, `telephony.mappings.read`, `reconciliation.runs.read`, `reconciliation.drifts.read`, `sales.lookup` and `sales.verification.read` are catalogued with `registered_by: null`: they have no registry rows, resolution fails closed, and they are not callable until a reviewed migration registers them. There is no Middleware `campaign-actions` or `campaign-commands` route; the 0054 `campaign_actions.apply` Odoo route is kill-switched by 0066 and n8n automation results go through `odoo.automation_results.apply`. |
| `GET /platform/v1/integrations/odoo/*` (canonical HTTP routes) | BUILD | No HTTP route wraps any of the above yet; building `/platform/v1/users`, `/tenants`, `/campaigns`, `/channels` should reuse this exact client/operation pattern (add new read operations here) rather than inventing a second Odoo-calling mechanism. |

## Not yet covered by this inventory pass

Billing/subscriptions/usage-metering, compliance/consent/suppression,
operations dashboards, audit-as-a-product-API (vs. the existing
`codestra.provisioning.audit`/Middleware audit tables), webhooks-as-a-
customer-facing-feature, API clients, bulk operations, global search,
OpenAPI/SDK generation, and the full observability/tracing stack have not
been inventoried against real code yet. Given the size of the full
registry (70+ endpoints across 6 repositories), treat this document as a
living artifact - extend it before building into any of those areas,
exactly as this section itself was built before building into the areas
above.
