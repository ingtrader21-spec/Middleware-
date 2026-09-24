# VICIdial-to-Odoo projection activation authority

The durable projection worker is repository-complete but deliberately not
runtime-activatable while either cross-repository prerequisite remains an open
candidate.

## Source gate

`config/vicidial-odoo-projection-source-authority.v1.json` records reviewed
candidate identities for audit. `load_projection_source_locks()` returns a
runtime tuple only when **every** dependency row has all of the following:

- `state_at_lock: merged`;
- `base_ref: refs/heads/main`;
- one 40-character `merge_sha`;
- `source_sha` equal to that same merge SHA;
- the matching runtime read-back variable.

Odoo PR #78 and VICIdial PR #17 are still open candidates, so enabled startup
fails before NATS connection, durable-state creation, or Odoo network I/O. Their
candidate SHAs must not be relabeled as merge SHAs. A later reviewed lock update
must record the actual protected-main merge identities.

## Runtime-profile gate

`config/vicidial-odoo-projection-runtime-authority.v1.json` is the immutable
projection-specific endpoint authority. The current staging entry permits only:

- profile `codestra-middleware-staging-v1`;
- `APP_ENV=staging`;
- synthetic-only events;
- Odoo origin `https://odoo-staging.internal.codestra`;
- HMAC files whose normalized names start with
  `/run/secrets/middleware-staging-vicidial-odoo-`.

The production and production-compose entries are explicitly
`blocked-pending-protected-authority`; no production Odoo hostname or credential
path is inferred by this change.

## Non-authorization boundary

These source files and tests authorize no deployment, environment secret,
production Odoo write, NATS consumption, VICIdial mutation, callback, transfer,
SMS, email, call origination, or PSTN dialing. `PRODUCTION_DIALING` remains
`DISABLED`, external effects remain false, and expected calls placed remain zero.
