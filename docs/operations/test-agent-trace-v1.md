# Canonical test-agent trace contract

This contract defines a redacted read model over existing authoritative
journals. It does not create another identity, action, reaction, event, audit,
or reconciliation store.

Source ownership remains:

- Odoo: employee, agent, campaign membership, lead, requested state, outbox,
  inbox, and business audit.
- Middleware: policy decisions, command/idempotency journals, integration
  events and deliveries, provisioning saga references, audit, and
  reconciliation.
- Provisioning: endpoint and credential lifecycle execution and its audit.
- Keycloak: authentication subject and account state.
- VICIdial/Asterisk: disabled test runtime mappings and observed state.
- n8n: one authenticated notification-only or report-only test execution.

Every trace is restricted to `TEST` or `STAGING`, campaign `CMP-400-COD`, and
business unit `BU-400-COD`. Evidence contains identifiers, hashes, state,
timestamps, and latency—not credentials or unrestricted destinations.

The extension allocator must scan every authoritative and historical source
before selecting the first free value from `7490` through `7494`. Defining the
candidate set does not reserve an extension.

No write-through run is authorized by this document. Staging population
requires separate conflict-scan evidence and approval. Production writes
remain prohibited.
