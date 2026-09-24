# n8n workflow contract

`POST /api/v1/n8n-runtime/dispatch` accepts
`codestra.n8n.dispatch.v1`. It requires tenant, source/event, trace,
correlation, causation, and idempotency identifiers plus a bounded payload.
Unknown fields and caller-provided destinations are rejected.

The registry binds workflow code/version, n8n workflow ID, event types, tenant
scope, enabled state, timeout, retry policy, result contract, owner, and a
relative allowlisted webhook path. Paths are combined only with the configured
private n8n base URL. Registry changes require normal migration/governance
review.

Dispatches are asynchronous. `202` creates one durable execution, `200`
returns an identical replay, and `409` rejects a changed payload under the same
idempotency scope.
