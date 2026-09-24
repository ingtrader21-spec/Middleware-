# Immutable event ledger

Every newly accepted canonical event is committed atomically to three
PostgreSQL records: the idempotent inbox, the append-only event ledger, and the
JetStream outbox intent. Failure to append any one of them rolls back all three.

`middleware_event_ledger` is sequenced independently per tenant. Each entry
stores the canonical event payload hash, the preceding entry hash, and a
domain-separated SHA-256 entry hash. A PostgreSQL transaction-scoped advisory
lock serializes concurrent appends for the same tenant while allowing unrelated
tenants to proceed independently.

The database rejects `UPDATE`, `DELETE`, and `TRUNCATE` against the event ledger.
The same append-only trigger protects command and reconciliation audit tables.
The application role should not own these tables and must not receive trigger or
DDL privileges in production.

Run the read-only verifier with a database credential that can select the
ledger:

```text
python scripts/verify_event_ledger.py
python scripts/verify_event_ledger.py --tenant-id <internal-tenant-id>
```

The verifier recomputes every canonical payload hash, checks gapless tenant
sequences and previous-hash links, then recomputes each entry hash. It emits
only counts, never event payloads. Any mismatch exits non-zero.
