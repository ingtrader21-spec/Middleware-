# MCR-C runtime shell implementation

Preserve MCR-A at b3f44dd4b8ad8976f10394051d2f13cc17443155 and reuse the
existing engine and tables. Register the eight operations without activating
execution. Never infer candidates, addresses, consent, or sender authorization.

1. Add contract-backed request/response validation from the frozen local JSON
   schemas, including conditional constraints, formats and additionalProperties.
2. Register the canonical operations with exact scopes, tenant binding, required
   headers and canonical errors. Pin status and execute authorization closed.
3. Add tenant-bound opaque pagination over existing journey tables. Keep reads
   free of durable writes. Validate readback documents before disclosure.
4. Verify signatures before parsing normalized delivery events. Reuse configured
   producer credentials; reject tenant/source/identity mismatches.
5. Integrate mutation routes only when atomic idempotency, replay quarantine and
   the communications suppression bridge are available. Do not acknowledge a
   write that cannot enforce these boundaries.
6. Exercise API headers, scopes, schema validation, disabled execution, signature
   failures, pagination, generated operations and existing engine invariants.
7. Run canonical generation, focused pytest, MCR validation and diff checks.
   Record exact remaining dependency blockers; do not commit an incomplete task.

Review focus: body/header tenant mismatch; scope escalation; raw-body signature
binding; no provider access on any failure; cursors replayed across tenants.
