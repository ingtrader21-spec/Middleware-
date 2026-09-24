# Middleware ↔ n8n automation control plane v2

## Accepted decision

Middleware adopts the governed `/v2/automation/*` contract. n8n remains an
orchestration client and Middleware remains the only cross-system write
authority.

```text
Provider/application event
  -> Middleware authenticated inbox
  -> canonical event + automation job + dispatch outbox
  -> private n8n wake
  -> POST /v2/automation/jobs/claim
  -> n8n leased orchestration
  -> POST /v2/automation/commands
  -> Middleware durable command + Temporal
  -> destination adapter and destination read-back
  -> Middleware reconciliation
  -> GET /v2/automation/commands/{command_id}
  -> n8n terminal job result
```

The existing `/v1/integrations/n8n/commands` and
`/v1/integrations/n8n/operations/{command_id}` endpoints remain deprecated
compatibility aliases only. They are not canonical for new workflows.

## Current source truth

The durable v1 integration core already exists: command ledger, idempotency,
inbox/outbox primitives, dead letters, replay controls, leases and
reconciliation support. The automation-v2 authorization policy, exact client
and prefix rules, and security invariant tests also exist in current source.

The complete thirteen-route automation-v2 runtime is not yet certified. The
conformance waiver register remains authoritative for routes not mounted in the
FastAPI runtime. A waived route is a tracked source gap, not a production-ready
endpoint.

```text
AUTOMATION_V2_DECISION=ACCEPTED
V1_COMPATIBILITY_ALIASES=DEPRECATED
V2_POLICY_AND_CONTRACTS=PRESENT
V2_RUNTIME_ALL_13_ROUTES=CERTIFICATION_PENDING
WORKFLOWS_ACTIVE=NO
EXTERNAL_EFFECTS_ENABLED=NO
```

## Authorization invariants

Middleware must independently validate the original Keycloak token even when
Kong has authenticated the request. The verified token and durable automation
job are authoritative for tenant, actor, workflow family and allowed scope.
Headers and body fields are assertions that must agree with those authorities.

Generic `automation.execute` and `automation.command` scopes are prohibited.
Client scopes are exact, with no implicit union. A client cannot claim another
workflow family or issue another family's command prefix.

CRM automation uses:

```text
client_id     = n8n-crm-automation
audience      = middleware-api
submit_scope  = automation.command.crm
read_scope    = automation.command.read
command_path  = POST /v2/automation/commands
status_path   = GET /v2/automation/commands/{command_id}
```

## Canonical Odoo command

Middleware exposes one canonical Odoo CRM mutation through the reviewed Odoo
bridge:

```text
command_type    = crm.lead.upsert
command_version = "1.0"
target          = odoo-19
capability      = ODOO_WRITE

POST /codestra/middleware/v1/commands/crm.lead.upsert
GET  /codestra/middleware/v1/commands/{command_id}/status
```

The direct Odoo CRM CRUD routes remain deprecated compatibility surfaces. New
CRM automations must use the canonical upsert command.

The Odoo payload requires a stable `source_record_id`, provenance, consent,
review/contact controls and the lead subject. Middleware derives target and
capability from policy. n8n never receives Odoo credentials or the Odoo HMAC
secret.

## Odoo message authentication

Middleware and Odoo share one byte-exact HMAC-SHA256 contract. Join the
following byte sequences with one newline in this order:

```text
X-Codestra-Timestamp
X-Codestra-Event-ID
HTTP method in uppercase
request path
X-Tenant-ID
X-Correlation-ID
Idempotency-Key
raw request body
```

The repository contains a synthetic golden vector in
`contracts/odoo-hmac-test-vector.v1.json`. It contains no runtime secret or
customer data. CI must compute the published digest from the vector.

## Unknown outcomes

A destination timeout is an unknown outcome, not a failed command. The Temporal
adapter execution has one attempt. Middleware then reconciles the Odoo command
status before any retry decision.

```text
blind resubmission after unknown outcome = prohibited
Odoo command-status read-back            = required
n8n automatic retry on timeout            = prohibited
```

If Odoo recorded the command, Middleware returns the recorded result. If Odoo
did not record it, the command remains unresolved until the reviewed policy
permits a retry with the same semantic identity.

## Durable job and command rules

The automation-v2 surface contains exactly thirteen operations:

1. claim a job;
2. read a job;
3. heartbeat;
4. record a step;
5. complete;
6. fail;
7. submit a command;
8. read a command;
9. request approval;
10. read approval;
11. request protected dead-letter replay;
12. reconcile jobs;
13. read effective capability state.

A current lease token and execution ID are mandatory for steps, commands,
completion and failure. Exact replays return the original result; semantic
conflicts are rejected without altering the original record.

## Human approvals and replay

Middleware owns approval state. n8n requests and reads approval but cannot
self-approve. Protected dead-letter replay requires the approval ID,
idempotency key, expected version, original-effect fingerprint, safe-replay
classification and replay reason. Replay authority is separate from effect
capability authority.

## Release posture

This branch changes source contracts, the Odoo adapter, validation and tests.
It does not mount the missing automation-v2 routes, migrate a live database,
activate n8n, provision Keycloak clients, deploy Middleware, enable
`ODOO_WRITE`, enable external delivery or mutate production.

Before runtime promotion:

- all thirteen route waivers must be removed only as their implementations land;
- exact-head and merge-result CI must pass;
- authorization and concurrency tests must pass;
- timeout-after-Odoo-commit must reconcile with zero duplicate writes;
- a write-disabled staging canary must prove zero downstream effects;
- backup, restore and rollback must be rehearsed;
- every capability and kill switch must remain false until separately approved.
