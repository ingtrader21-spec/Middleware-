# VICIdial lifecycle projection to Odoo

## Data path

```text
Asterisk/VICidial
  -> read-only AMI observer
  -> signed /api/v1/vicidial/events ingress
  -> Middleware durable inbox + immutable event ledger + NATS outbox
  -> dedicated durable JetStream consumer
  -> tenant-bound signed Odoo call-event endpoint
  -> Odoo call state + Odoo Bus screen pop
```

The worker consumes only the explicit `codestra.vicidial.call.lifecycle.*`
event allowlist. It does not transport RTP/SRTP audio and has no AMI, ARI,
originate, campaign-write, callback, or production-dialing permission.

The shared VICidial ingress also retains the pre-existing SDK compatibility
event `codestra.events.call_disposition_updated`. That event remains accepted by
the normal route but is outside the lifecycle subject and cannot be consumed by
this projection worker.

## Immutable cross-repository source authority

`config/vicidial-odoo-projection-source-authority.v1.json` pins the complete
reviewed dependency tuple:

- Keycloak PR #86 protected merge
  `922d039b5143f3ac738e88998036355562a8dd5d`;
- Odoo PR #78 candidate head
  `9f38f87138f2914622b8ac1243c7969691ac5317`;
- VICIdial PR #17 candidate head
  `8007f9550a933c1cb17f21da6028dcfc41b47b0a`.

An enabled worker requires runtime read-back variables for all three exact SHAs
before it opens a NATS connection, mutates durable projection state, or contacts
Odoo. A later push to either external pull request does not float this worker to
new code: the source tuple remains locked until a separately reviewed authority
change updates it. Odoo and VICIdial must still reach protected merge before any
staging activation; the lock records reviewed source and does not itself approve
those merges or a deployment.

## Delivery discipline

Every event is first registered in a persistent SQLite state ledger mounted at
`VICIDIAL_ODOO_STATE_PATH`. Registration and state transitions use serialized
transactions, and terminal `delivered` or `failed` states cannot be downgraded.
The ledger file is forced to mode `0600`.

Before any Odoo POST begins, the worker durably transitions the event to
`reconciliation_required`. This is the write-attempt uncertainty boundary. If
the process exits before the POST, during transport, after Odoo commits, or
before local delivered evidence is persisted, the next JetStream delivery does
signed status read-back first and cannot blindly resubmit. A proven 404 moves
the event to `retryable`; only a later delivery may open another write attempt.

An exact success response is accepted only when Odoo returns matching event,
tenant, call, type, sequence, and `recorded=true` evidence. A timeout or
ambiguous HTTP response is followed by signed status read-back. Until Odoo
proves a 404, redelivery performs read-back only and never blindly repeats the
write.

Odoo HTTP 409 responses are also fail-closed. Only an identity-matching
`sequence_gap` response with `retryable=true`, `recorded=false`, and consistent
`expected_sequence`/`current_sequence` evidence may be retried. Stale sequence,
lifecycle transition, and event-identity conflicts are terminal. Unknown or
malformed conflict evidence remains outcome-unknown and is reconciled rather
than guessed.

The worker sends JetStream progress acknowledgements while an Odoo request or
read-back is active and starts every message in a fetched batch immediately, so
one slow event cannot let later deliveries expire behind it.

## Activation sequence

1. Use Keycloak protected merge
   `922d039b5143f3ac738e88998036355562a8dd5d` as the immutable lifecycle
   identity authority.
2. Merge Odoo PR #78 only from reviewed head
   `9f38f87138f2914622b8ac1243c7969691ac5317`, then record its protected merge
   SHA in a separately reviewed authority update before staging activation.
3. Merge VICIdial PR #17 only from reviewed head
   `8007f9550a933c1cb17f21da6028dcfc41b47b0a`, then record its protected merge
   SHA in the same activation authority.
4. Merge this Middleware worker only from its unchanged, approved, green exact
   head.
5. Deploy a protected staging candidate with the worker disabled.
6. Bind NATS and Odoo secrets outside Git and expose exact Keycloak, Odoo, and
   VICIdial source read-back variables matching the committed authority file.
7. Enable `VICIDIAL_ODOO_PROJECTION_ENABLED=true` with
   `VICIDIAL_ODOO_SYNTHETIC_ONLY=true` only for `TEST_SYN`.
8. Certify created -> ringing -> connected -> hangup -> completed, duplicate,
   out-of-order, crash-after-POST, restart, and signed read-back behavior.

Production remains a separate activation release requiring an exact activation
ID, a runtime profile that explicitly permits activation, exact protected merge
and immutable image read-back, `ODOO_WRITE`, the external-delivery umbrella,
rollback evidence, and `PRODUCTION_DIALING=DISABLED`.
