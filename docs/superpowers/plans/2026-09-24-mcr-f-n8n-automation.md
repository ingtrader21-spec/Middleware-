# MCR-F post-acceptance automation contract plan

Scope: extend the existing contract-only campaign recycling boundary; do not add
runtime handlers, activate workflows, provision infrastructure, or contact providers.
User authorized native implementation and commit/push only after green validation.

1. Add failing contract tests for trigger/result/readback/replay operation sets,
   required security and headers, strict schemas, and fail-closed acceptance checks.
2. Add a versioned contract and OpenAPI document referencing the existing lifecycle,
   authority matrix, automation ledger and operation policy. Define durable tenant-bound
   idempotency, leases, result binding, retries, unknown-outcome reconciliation,
   dead-letter and operator replay semantics without duplicating runtime stores.
3. Add an offline conformance evaluator and validator. Exercise trusted persisted
   acceptance separately from untrusted workflow input; no network clients or adapters.
4. Run positive and negative no-effect staging-profile scenarios locally; record their
   exact scope and leave protected staging/runtime evidence pending and release NO_GO.
5. Run campaign and n8n validators, focused regression tests, lint and diff checks.
   Review the diff, commit only if green, push the specified branch and compare SHAs.

Review focus: forged acceptance, changed correlation on duplicate keys, cross-tenant
readback, unknown-outcome replay, terminal result replacement, and scopes that permit
provider bypass. Contract evidence must not be represented as deployed enforcement.
