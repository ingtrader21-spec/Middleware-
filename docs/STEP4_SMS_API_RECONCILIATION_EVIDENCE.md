# Step 4 SMS API Reconciliation Evidence

Date: 2026-08-30

## Implemented

- Stable request idempotency produces one Communications message and one durable command intent.
- Reusing an idempotency key with changed content returns `409`.
- SMS cancellation dead-letters a command before dispatch and exact cancellation replay is a no-op.
- A command-ledger `reconciliation_required` state reads back as canonical `indeterminate`.
- Temporal possible-after-acceptance timeout evidence proves one execution attempt and no automatic resend.
- Signed Telnexa event IDs are deduplicated independently of the durable webhook inbox.
- Reusing an event ID with changed signed content returns `409`.
- Delivered is monotonic; a later provider `sent` state is retained as evidence without downgrading the message.
- Provider references and raw provider statuses are retained on the canonical read model/timeline.

## Production follow-up

The command ledger and webhook inbox are durable in production mode. The
Communications message/timeline projection and its secondary provider-event
deduplication index are still in memory and must be migrated transactionally
before live activation. Telnexa authoritative readback remains a required
cross-repository gate.
