# Codestra Integration Fabric v2

## Binding decision

Middleware is the only cross-system write boundary. Kong and Caddy enforce traffic policy; Keycloak issues identities; n8n orchestrates; NATS transports durable events; Temporal owns critical long-running state machines; product systems retain their own authoritative records.

```text
Caddy -> Kong cell -> Middleware -> authorized adapter/service
                               -> durable event/outbox -> NATS
                               -> critical workflow -> Temporal
                               -> business orchestration -> n8n
```

No browser, n8n workflow, Odoo addon, provider callback, or product frontend may bypass Middleware for a cross-system mutation.

## Responsibilities

Middleware owns:

- tenant and service authorization;
- canonical request, command, event, and error contracts;
- idempotency and semantic conflict detection;
- authoritative correlation and causation identifiers;
- capability and kill switches;
- signed webhook inbox and replay protection;
- transactional outbox and delivery attempts;
- command and operation ledgers;
- provider and product adapters;
- consent and suppression enforcement;
- unknown-outcome reconciliation;
- bounded retry, dead letters, controlled replay, and audit;
- destination read-back before success.

Middleware does not own passwords, CRM records, Postal/Jasmin/social-provider credentials, workflow authoring, telephony databases, customer trading ledgers, wallet balances, or provider delivery truth.

## Isolation cells

- **core communications**: Odoo facade, Klyrow, Telnexa, Postly, Kyqra, public forms, support, and provisioning.
- **Beyvra**: isolated non-financial automation facade. Financial/trading operations are categorically unavailable to n8n.
- **telephony**: private restricted adapter for VICIdial/Asterisk. No public command surface.

Each cell has separate Kong policy, Keycloak clients, n8n runtime, Redis namespace, credentials, rate limits, and observability labels.

## Canonical transaction pattern

A mutating API request follows:

1. Kong authenticates and applies traffic policy.
2. Middleware derives tenant and actor from validated identity and resource mapping.
3. Middleware validates the versioned contract and capability.
4. Middleware inserts idempotency, command/operation, audit, and outbox records in one transaction.
5. The adapter submits the request with the same correlation and idempotency context.
6. Middleware records `SUBMITTED`, `UNKNOWN`, `COMPLETED`, or `FAILED`.
7. `UNKNOWN` is reconciled before another externally effective submission.
8. A successful response is exposed only after authoritative read-back or a durable accepted asynchronous operation.

## Provider webhooks

Provider callbacks terminate at Middleware, never n8n. Middleware verifies source identity, timestamp, signature, body digest, event ID, tenant mapping, and replay state before durable acceptance. The normalized event is then published through the outbox.

## n8n boundary

n8n may perform timing, branching, reusable orchestration, human approvals, and SLA escalation. It has one outbound trust destination: the private Middleware automation API. It receives no provider or application database credentials. It cannot mark a command successful; it waits for Middleware operation state.

## Temporal boundary

Temporal owns critical recoverable state machines such as multi-system provisioning, privacy deletion, credential rotation, and long-running reconciliation. n8n can request or observe these operations but is not their durable source of truth.

## APIs

The integration fabric exposes:

- tenant lifecycle, products, memberships, domains, capabilities, preflight, readiness, activation, and suspension;
- integration catalog, connection metadata, tests, rotation requests, disablement, and health;
- command, operation, event, delivery, audit, and dead-letter resources;
- private n8n run claim, heartbeat, step, result, approval, and cancellation APIs;
- provider-specific webhook inbox routes;
- product facades for CRM, email, SMS, social, crawler, telephony, provisioning, and Beyvra non-financial operations.

## Required headers

```text
Authorization: Bearer <short-lived token>
Idempotency-Key: <tenant-scoped key>       # mutations
X-Correlation-ID: <uuid>                   # accepted or generated
traceparent: <W3C context>                 # optional but preserved
```

Caller-supplied tenant or internal identity headers are assertions only and are never authoritative.

## Capability defaults

Every external effect remains disabled until a separate reviewed canary:

```text
EMAIL_DELIVERY=false
SMS_DELIVERY=false
SOCIAL_PUBLISH=false
CRAWLER_EXECUTION=false
CRAWLER_WRITEBACK=false
ODOO_WRITE=false
CALLBACK_DISPATCH=false
PRODUCTION_DIALING=false
BEYVRA_OPERATIONS_WRITE=false
BEYVRA_FINANCIAL_WRITE=false
PRIVACY_WRITE=false
DEAD_LETTER_REPLAY=false
```

## Branch program

```text
integration/n8n-control-plane-v2-20260827
  -> architecture/codestra-integration-fabric-v2
       -> feat/tenant-onboarding-api-v1
       -> feat/capability-registry-v1
       -> feat/command-operation-api-v1
       -> feat/webhook-inbox-v1
       -> feat/transactional-outbox-v1
       -> feat/event-delivery-ledger-v1
       -> feat/dead-letter-replay-v1
       -> integration/kong-cells-v1
       -> integration/keycloak-service-identities-v2
       -> integration/odoo-crm-facade-v1
       -> integration/klyrow-email-v1
       -> integration/telnexa-sms-v1
       -> integration/postly-social-v1
       -> integration/kyqra-crawler-v1
       -> integration/vicidial-telephony-v1
       -> integration/beyvra-nonfinancial-v1
       -> integration/provisioning-service-v1
```

Branches are review workstreams, not environments. No feature branch deploys directly.