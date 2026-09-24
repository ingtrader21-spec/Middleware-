# Canonical event and command contracts

The Integration Fabric has exactly one durable event envelope and one durable
command envelope:

- `contracts/platform/event-envelope.v1.schema.json`
- `contracts/platform/command-envelope.v1.schema.json`

The runtime loads these JSON Schemas and validates every accepted event and
command against them. Pydantic provides typed application objects, but it is not
an independent contract authority. CI compares its required fields to the
authoritative schemas.

`contracts/event-envelope.schema.json` remains only as a compatibility `$ref`.
It contains no second field definition. Lead intake and Odoo lead schemas extend
the canonical envelopes and constrain their `payload`; they do not create new
top-level envelopes.

Provider-native wire formats, including connector CloudEvents and the current
Beyvra identity event, are projections. An adapter must normalize them before
the middleware persists or publishes them. They are listed explicitly in
`contracts/platform/contract-catalog.v1.json` and must never be treated as
durable canonical records.

Contract changes require a new versioned canonical file. Replacing a deployed
version in place, accepting an unsupported version, or persisting a provider
projection directly is prohibited.
