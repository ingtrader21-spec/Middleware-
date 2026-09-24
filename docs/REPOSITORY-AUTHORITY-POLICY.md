# Repository authority policy

## Permanent rule

When a Codestra component has its own GitHub repository, that repository is the principal source for the component. Middleware may own the integration contract, adapter, command mapping, derived compatibility fixture or read-back logic, but it must not become a second application/runtime source for that component.

The machine-readable registry is `config/repository-authorities.v1.json`.

## Middleware owns only the Middleware boundary

`ingtrader21-spec/Middleware-` owns:

- cross-system command/event contracts and durable integration state;
- authenticated Middleware APIs and workers;
- the tenant-scoped command ledger, inbox/outbox and audit boundary;
- Middleware-owned Temporal command execution;
- trusted adapters that translate Middleware commands into a provider's reviewed API;
- destination read-back, reconciliation, idempotency, retry/dead-letter and capability enforcement;
- the privileged Middleware Connector Runtime;
- compatibility contracts and combined cross-repository release evidence.

It does not own the implementation/runtime of Caddy, Kong, Keycloak, n8n, Odoo, Telnexa, Klyrow, Kyqra, VICIdial/Asterisk, provisioning, social/Postiz, SDK packages, or independent products when those have dedicated repositories.

## Principal repositories

Critical control-plane authorities are:

| Component | Principal repository |
|---|---|
| Middleware | `ingtrader21-spec/Middleware-` |
| Caddy | `appolon1908-hue/Caddy` |
| Kong | `appolon1908-hue/Kong` |
| Keycloak | `appolon1908-hue/Keycloak` |
| n8n | `appolon1908-hue/N8N` |
| Odoo | `appolon1908-hue/Odoo` |
| Telnexa SMS/Jasmin | `appolon1908-hue/telnexa` |
| Telnexa website | `appolon1908-hue/Telnexa-web` |
| Klyrow email platform | `appolon1908-hue/klyrow.com` |
| Klyrow website | `appolon1908-hue/klyrow-Website-` |
| Kyqra crawler | `appolon1908-hue/kyqra-crawler` |
| VICIdial/Asterisk connector | `appolon1908-hue/Vicidialer-Codestra` |
| Provisioning | `appolon1908-hue/codestra-provisioning-service` |
| SDKs / connector kit | `appolon1908-hue/SDK-repository` |
| Social/Postiz | `appolon1908-hue/social.codestra.co` |

The full reviewed registry also records independent product repositories so Middleware does not accidentally absorb their source.

## Shared API edge

The shared API-edge ownership chain is permanently:

```text
client -> Caddy -> Kong -> Middleware -> owned downstream runtime
```

`appolon1908-hue/Caddy` owns the canonical edge contract at `config/caddy-kong-contract.v1.json`, including the outer TLS/host/reverse-proxy handoff. `appolon1908-hue/Kong` owns the gateway route/security implementation. Middleware must not ask Caddy to bypass Kong for a path already represented in Kong source.

Caddy must not create trusted application identity headers. Kong performs token/scope policy and sets authenticated downstream identity; Middleware revalidates the identity/tenant authorization required for privileged commands.

Transitional legacy Caddy upstreams may exist only as migration compatibility for paths without accepted Kong parity. They are not alternate principals and must be removed after equivalent Kong routes pass write-disabled staging acceptance and rollback gates.

## `codestra-production-platform`

`appolon1908-hue/codestra-production-platform` is reference-only under the current model. It remains useful for:

- historical runtime inventories;
- previous deployment provenance;
- rollback and disaster-recovery evidence;
- prior Caddy/Kong/runtime configuration used during migration comparison;
- old multi-service release evidence.

It is not principal source for any component that now has its own repository and it is not a central release authority.

Historical files are retained; they are not deleted merely because ownership moved. A dedicated repository must import/reconcile useful historical source and record provenance before the old copy is treated as frozen reference.

## Derived files inside Middleware

Middleware may keep generated or derived integration files for other repositories only when all of these are true:

1. the owning repository is identified in the authority registry;
2. the file is a contract, adapter mapping, compatibility fixture, generated desired-state preview or integration test artifact—not a competing runtime implementation;
3. secrets are absent;
4. CI can reproduce or validate the derivation where practical;
5. deployment of the external component still occurs from its principal repository.

Examples: a Telnexa command schema and Telnexa adapter belong in Middleware; the Jasmin runtime belongs in `telnexa`. A VICIdial command mapping belongs in Middleware; the restricted Asterisk/VICIdial connector belongs in `Vicidialer-Codestra`. A generated Kong route expectation may be tested here; Kong route implementation/reconciliation belongs in `Kong`. Caddy edge source belongs only in `Caddy`.

## Release rule

Every repository ships independently from its own reviewed source and immutable artifact identity. Cross-repository features are coupled by contract versions and a combined evidence note, not by copying the applications into Middleware or by reviving a central platform repository.

No merge of this policy changes a live server or authorizes production activation.
