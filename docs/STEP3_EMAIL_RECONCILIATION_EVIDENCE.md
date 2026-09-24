# Step 3 Email Reconciliation Evidence

Date: 2026-08-30

## Implemented

- New email messages start with canonical `accepted` and `queued` events.
- Idempotency keys prevent duplicate command creation for replayed requests.
- Reused idempotency keys with changed payloads return conflict.
- A replayed create request returns the original message and leaves exactly one message intent and one command operation in the in-memory stores.
- Command-ledger `reconciliation_required` state is surfaced as canonical message status `indeterminate`, with the operation error retained for read-back.
- The Temporal email unknown-outcome fixture performs exactly one provider execution attempt and immediately quarantines the command as `reconciliation_required`; it never retries the externally effective command.
- A separate durable reconciliation workflow then performs bounded authoritative provider read-back using the original tenant, operation identity, correlation context, and idempotency evidence.
- The deterministic evidence injects two transient read-back failures followed by a provider match. The reconciliation completes after three read-back attempts while the provider execution-attempt count remains exactly one.
- Reconciliation therefore cannot create a duplicate email send. A read-back failure or mismatch remains reconciliation-required and is not represented as delivery success.
- Provider events from Klyrow update message status and append canonical timeline events.
- Provider event IDs are deduplicated at the communications read-model layer. Exact signed callback replays do not append a second event; reuse with changed content is rejected by the durable inbox as an idempotency conflict.
- Cross-tenant reads are denied before read-back data is returned.
- Cancellation is rejected for terminal states.

## Evidence Boundary

The automated Temporal test uses deterministic provider activities and proves the required workflow semantics without making a live provider call:

```text
provider execution attempts = 1
unknown outcome state = reconciliation_required
provider reconciliation read-back attempts = 3
provider resubmissions during reconciliation = 0
final deterministic reconciliation result = completed / provider read-back matched
```

Live Klyrow credentials, network calls, email delivery, Postal submission, and production provider state remain disabled.

## Remaining Before Production

- Persist the Communications read model in durable storage.
- Replace the in-memory provider-event deduplication index with the same durable transaction as the future Communications read model.
- Bind `reconcile_operation` to the reviewed Klyrow authoritative message lookup using OAuth2 plus mTLS and tenant-scoped idempotency/correlation evidence.
- Prove the same no-resubmission behavior against the isolated Klyrow staging runtime.
- Keep live delivery disabled until cross-repository contract, secret, network, backup/restore, rollback, and activation gates pass.
