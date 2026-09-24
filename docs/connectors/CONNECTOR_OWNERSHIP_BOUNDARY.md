# Connector Ownership Boundary

## Decision

`appolon1908-hue/SDK-repository` and `ingtrader21-spec/Middleware-` are not competing authorities and must not be consolidated into one runtime codebase.

- `SDK-repository` is the developer-facing SDK/distribution authority: reusable contracts, generated clients, webhook helpers, connector-kit APIs, n8n nodes, compatibility gates and distributable adapter packages.
- `Middleware-` is the privileged connector runtime/control authority: trusted adapter registration, machine/tenant/actor authorization, semantic idempotency, durable inbox/outbox state, secret resolution, provider command execution, read-back, unknown-outcome reconciliation, kill switches and production activation.

## Permanent rule

```text
SDK consumer / n8n / product
          |
          v
      Kong / Middleware
          |
          v
trusted Middleware connector runtime
          |
          v
product/provider-owned adapter or API
```

SDK code must never become an alternate provider write path. A connector package may describe/translate a provider contract, but privileged credentials and production side effects remain behind Middleware.

## VICIdial example

- reusable connector interfaces: `SDK-repository` / `@codestra/connector-kit`
- actual VICIdial/Asterisk implementation: `appolon1908-hue/Vicidialer-Codestra`
- cross-system command/control authority: `Middleware-`

Therefore the supported path is:

```text
VICIdial/Asterisk <-> Vicidialer-Codestra <-> Middleware <-> Odoo/n8n/Telnexa/Klyrow
```

Telnexa/Jasmin remains SMS-only and is not the VICIdial voice connector.

## Source overlap policy

Middleware's internal `middleware/connector_sdk/` is a runtime enforcement framework. It may share contract shapes or generated models with `SDK-repository`, but public/distributable SDK APIs should be generated from one versioned contract and checked for drift rather than hand-maintained independently.

A future consolidation should remove duplicated **contract definitions**, not merge the privileged Middleware runtime into the SDK repository.
