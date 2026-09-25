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

The dispatcher never targets the retired `8080` listener: a base URL on port
8080 dead-letters the execution with `LEGACY_PORT_8080` before any request is
sent, in every environment.

## Certification evidence (bearer-guarded, read-only)

`GET /api/v1/n8n-runtime/process` returns
`codestra.n8n.runtime-process.v1`: the serving process instance id and start
time (a restart changes both), the environment, whether the runtime is enabled,
and the dispatch-target posture (scheme, port, `legacy_8080`, `allowed`,
`reason`; never the host or credentials).

`GET /api/v1/n8n-runtime/executions/{execution_id}/evidence?tenant_id=` returns
`codestra.n8n.execution-evidence.v1` for one tenant-scoped execution: execution
identifiers and hashes, every result (id, status, hash, occurred_at), the
`n8n.runtime.*` audit trail, the accepted callback nonce count, Odoo result
deliveries, and the derived checks `correlation_continuous`,
`result_binding_intact`, `result_hashes_unique`, `reconciliation`
(`reconciled`, `divergent`, `awaiting_result`, `terminal_without_result`),
`synthetic_odoo_binding` and `odoo_result_deliveries`. Payloads and result
bodies are never echoed.

`python -m scripts.certify_test_syn_failure_paths --output DIR` drives one
synthetic TEST_SYN command through dispatch, rejected and accepted signed
results, and the evidence endpoint; `--phase after-restart` then proves restart
continuity (new process instance, unchanged durable evidence, dispatch and
result idempotency and nonce replay protection still enforced).
