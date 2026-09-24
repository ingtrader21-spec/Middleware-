# CI, environments, and current handoff

Status snapshot: 2026-08-29

This is the concise operating reference for Middleware source, CI, environment promotion, and the next gated work in the CRM/telephony/messaging mission. It does not authorize deployment and does not replace repository-specific runtime evidence.

## Repository and release model

Middleware uses `main` as its release source branch. Staging and production are deployment environments, not Git branches. The same immutable Middleware artifact accepted in staging may be promoted only after the applicable approval and read-back gates.

Codestra uses a decentralized source model: **if a component has its own GitHub repository, that repository is its principal source**. Repositories couple through versioned contracts and evidence, not by copying their runtimes into Middleware.

The canonical machine-readable mapping is `config/repository-authorities.v1.json`; `scripts/validate_repository_authorities.py` fails CI when this rule is violated.

`appolon1908-hue/codestra-production-platform` is reference-only: historical runtime inventory, deployment provenance, rollback/recovery evidence and migration comparison. It is not central release authority and cannot be principal source for a component that has a dedicated repository.

For a cross-repository feature, Middleware owns the combined evidence note because it is the cross-system write boundary. That evidence role does not give Middleware authority to merge, deploy or activate another repository.

See:

- `docs/REPOSITORY-AUTHORITY-POLICY.md`
- `docs/STAGE0_GROUND_TRUTH_20260829.md`
- `docs/CROSS_REPOSITORY_RELEASE_EVIDENCE.md`
- `docs/releases/RELEASE_EVIDENCE_TEMPLATE.md`

## CI coverage

| Workflow | Responsibility |
|---|---|
| `Middleware CI` | Repository validators, locked tests, runtime image smoke, PostgreSQL/Redis, NATS, Temporal, synthetic no-effect acceptance and security gates |
| `Connector SDK v1 validation` | Middleware-consumed connector manifests, generated artifacts, contracts and regression tests |
| `Connector storage v1` | Alembic migrations, RLS/tenant isolation, concurrency, backup/restore and downgrade/upgrade |
| `Connector Runtime API validation` | Middleware Connector Runtime management API, PostgreSQL integration and migration replay |
| `Signed Middleware Release` | Build, scan, sign and verify the Middleware artifact only |

Recommended protected checks include repository validation, principal-repository authority validation, runtime image build/smoke, disposable PostgreSQL/Redis, NATS, Temporal critical workflows, synthetic no-effect E2E and all affected connector checks.

## Promotion model

For Middleware itself:

```text
workstream PR
  -> exact-head CI
  -> protected merge to main
  -> exact-main-SHA CI
  -> immutable signed Middleware artifact
  -> staging with external effects disabled
  -> runtime read-back + synthetic acceptance + restore/rollback proof
  -> explicit production approval
  -> promote the identical accepted artifact
```

For a feature spanning repositories:

```text
versioned contract
  -> implementation in each principal repository
  -> exact accepted SHA/artifact per repository
  -> cross-repository staging acceptance
  -> Middleware evidence note listing every immutable identity
  -> separately approved capability activation
```

## Caddy and gateway ownership

The dedicated repository `appolon1908-hue/Caddy` is now the principal source for shared Codestra Caddy edge configuration. The initial `api.codestra.co` baseline is imported there from the historical `codestra-production-platform:release/production-activation:operations/caddy/api.codestra.co.caddy` reference without claiming runtime convergence.

`appolon1908-hue/Kong` owns Kong services, route/plugin policy, Keycloak OIDC enforcement and gateway reconciliation. Kong does not own Caddy source merely because Caddy forwards to Kong.

Middleware `platform/caddy` material is compatibility/review evidence only and must not become a second Caddy runtime source. New shared-edge Caddy source belongs in `appolon1908-hue/Caddy`.

No live Caddy configuration has been changed. Runtime convergence requires read-only inventory, checksum comparison, staging Caddy → Kong/Middleware validation, rollback rehearsal, controlled reload and post-change read-back.

## Principal provider/product ownership

```text
Caddy                   = appolon1908-hue/Caddy
Kong                    = appolon1908-hue/Kong
Keycloak                = appolon1908-hue/Keycloak
N8N                     = appolon1908-hue/N8N
Odoo                    = appolon1908-hue/Odoo
Telnexa/Jasmin          = appolon1908-hue/telnexa (SMS only)
Telnexa website         = appolon1908-hue/Telnexa-web
Klyrow/Postal/Mautic    = appolon1908-hue/klyrow.com
Klyrow website          = appolon1908-hue/klyrow-Website-
Kyqra crawler           = appolon1908-hue/kyqra-crawler
VICIdial/Asterisk       = appolon1908-hue/Vicidialer-Codestra
Provisioning            = appolon1908-hue/codestra-provisioning-service
SDK / connector kit     = appolon1908-hue/SDK-repository
Social/Postiz           = appolon1908-hue/social.codestra.co
Middleware              = ingtrader21-spec/Middleware-
```

Independent products such as MoneyBee, Beyvra, Breero, LARIM-A and the public Codestra site also remain in their dedicated repositories; Middleware may integrate with them but may not absorb their application source.

## Middleware-only ownership

Middleware continues to own the cross-system command/event boundary, durable command ledger, inbox/outbox/audit state, Middleware Temporal command execution, trusted provider adapters, read-back/reconciliation, idempotency, capability enforcement and the privileged Middleware Connector Runtime.

A Telnexa adapter in Middleware is correct; a Jasmin runtime copy is not. A VICIdial command mapping in Middleware is correct; the Asterisk/VICIdial connector runtime belongs in `Vicidialer-Codestra`. Generated compatibility expectations are allowed; the external runtime remains in its principal repository.

## Current gated status

### Stage 0

Source authority is resolved and now enforced by CI. The dedicated Caddy repository corrects the earlier temporary assumption that Kong should own future Caddy source.

### Stage 1

Keycloak/Kong source contracts have green source validation, but the live exit gate still requires a real Client Credentials token to be issued, accepted on the reviewed Kong route, rejected when invalid, and revalidated by Middleware. Do not declare Stage 1 complete from Git configuration alone.

### Stage 2

Middleware has substantial Phase 4 source and provider adapter work. Remaining provider runtime binding must respect each provider's actual confirmation semantics. Telnexa SMS final delivery truth is asynchronous DLR; VICIdial and crawler operations have direct read-back surfaces. No provider activation should bypass the Stage 1 live identity gate.

### Stage 3+

Odoo business modules, n8n runtime binding, provider staging acceptance, gateway activation, full staging acceptance and production launch retain their real-runtime/read-back gates.

## Immediate next gate

Do not skip dependency order. The next runtime gate remains Stage 1 live identity acceptance. Repository ownership cleanup does not activate or deploy anything.

No production deployment, live Caddy reload, provider write, SMS/email delivery, production dialing, unrestricted crawling or production activation is authorized by this document.
