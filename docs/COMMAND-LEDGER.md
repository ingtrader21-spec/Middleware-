# Durable command ledger

Effectful middleware requests use the canonical command ledger. The generic
entry point is `POST /v1/commands`; scoped APIs, including the
[Odoo calling endpoints](ODOO-CALLING-ENDPOINTS.md), normalize their authorized
requests into the same command envelope and storage boundary. The API validates
the canonical envelope, authenticates the requesting subject, authorizes the
tenant, owning adapter, and capability, then commits two records in one
PostgreSQL transaction:

1. the command in `middleware_commands`; and
2. its `temporal-command` outbox intent.

The generic caller receives `202 Accepted` and a `Location` header for
`GET /v1/operations/{command_id}`. An exact replay returns the same operation
with `200 OK`; reuse of either the command ID or idempotency key with different
content returns `409 Conflict`. Scoped calling status uses the same-actor route
documented in the calling contract instead of granting generic operation access.

## State machine

```text
persisted -> queued -> dispatching -> accepted -> readback_pending -> completed
                         |               |               |
                         +---------------+---------------+
                                         |
                              reconciliation_required
```

`completed` is legal only after a provider read-back activity returns `matched`.
An ambiguous adapter error, failed read-back, or mismatch moves the command to
`reconciliation_required`; it is never reported as success. Every state change
is appended to `middleware_command_audit`, and each dispatch attempt is tracked
in `middleware_command_attempts`.

The outbox dispatcher uses a workflow ID derived from `(tenant_id, command_id)`
with duplicate workflow starts rejected or attached to the existing run. This
makes PostgreSQL redelivery safe without creating a second command execution.

## Activation boundary

`connectors/generated/command-registry.v1.json` maps each command prefix to
exactly one adapter, capability, and mandatory read-back policy.
`config/capabilities.v2.json` defaults every capability to `false`. The Temporal
worker's provider activities also fail closed until a reviewed adapter is
explicitly bound. Enabling a configuration flag alone therefore cannot activate
a provider write.

The calling API's expiring, single-call internal grant authorizes only its scoped
ledger submission. It does not bind a provider executor, activate an agent, or
change public-network dialing. A queued calling operation is returned as an
unknown call outcome, not as answered or successfully completed.
