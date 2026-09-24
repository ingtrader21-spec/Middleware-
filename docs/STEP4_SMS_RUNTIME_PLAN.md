# Step 4 — Communications API v1 SMS Runtime

Implementation status: provider-neutral API and command mapping implemented on
this branch on 2026-08-30. Production provider activation remains gated.

## Authority

Repository: `ingtrader21-spec/Middleware-`

Branch: `feat/communications-api-v1-sms-runtime`

Frozen SDK contract: `appolon1908-hue/SDK-repository@63c793e88cca5daecfb5c8a688b8674ab288c522`

Telnexa/Jasmin remains the SMS provider/runtime authority. Middleware remains the only privileged cross-system write authority.

## Scope

Implement the provider-neutral Communications API v1 SMS runtime mapping after Step 3 email passes.

Required behavior:

- canonical SMS submission through `/v1/communications/messages` with `channel=sms`;
- durable command/message state;
- tenant/actor authorization;
- mandatory effectful-write idempotency;
- consent/opt-out/suppression enforcement before provider submission;
- sender identity validation;
- Unicode/coding-aware request mapping;
- Telnexa adapter submission;
- DLR, inbound/MO and failure event normalization;
- provider reference retention;
- canonical status mapping;
- authoritative read-back/reconciliation for uncertain outcomes;
- provider health, usage and billing read-model mapping where contractually exposed;
- durable message timeline and audit evidence.

## Canonical statuses

Use the frozen contract states only: `accepted`, `queued`, `dispatched`, `delivered`, `failed`, `cancelled`, `suppressed`, `expired`, `indeterminate`.

Provider-specific Jasmin/SMPP states must be retained as evidence.

## Unknown outcome rule

If a provider submission may have succeeded but Middleware cannot prove the outcome, set the communication to `indeterminate`/reconciliation-required and perform provider/read-model reconciliation before any retry. Never blindly resend.

## Required tests

- request/schema validation;
- tenant isolation and denied scope;
- exact idempotent replay;
- conflicting idempotency reuse;
- opt-out and suppression blocking;
- sender identity validation;
- GSM/Unicode mapping;
- successful provider submission;
- provider rejection/failure;
- timeout-before-ack and timeout-after-possible-ack;
- indeterminate reconciliation without duplicate SMS;
- signed DLR verification and replay rejection;
- inbound/MO normalization;
- canonical failure/status mapping;
- message lookup and ordered event timeline;
- provider health/usage mapping;
- delivery kill-switch remains safe.

## Safety

Do not enable carrier routes, live external SMS, production credentials, production deployments, DNS/routing changes, or provider activation on this branch.

## Exit gate

Step 4 runtime work passes only after the paired Telnexa provider branch passes, exact SHAs are recorded, SDK compatibility is green, reconciliation is proven duplicate-safe, and live delivery remains disabled until Step 8.

## Current boundary

Middleware now owns the canonical SMS API, command intent, readback model,
signed Telnexa event ingestion, and duplicate-safe reconciliation behavior.
Telnexa remains the authority for billing reservations, approved sender and
route decisions, Jasmin credentials, carrier submission, DLR correlation, and
local STOP/HELP compliance. Middleware contains no Jasmin credential or direct
Jasmin transport.
