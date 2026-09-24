# Codestra CRM/Telephony/Messaging Stage 0 Ground Truth

Date: 2026-08-29

This document records repository-backed source authority for the CRM/telephony/messaging control plane. Source readiness is not deployment evidence.

## Permanent rule

When a Codestra component has its own GitHub repository, that repository is its principal source. Middleware may own the integration contract, trusted adapter, command mapping, derived compatibility fixture and read-back/reconciliation logic; it must not become a competing runtime source.

The enforceable registry is `config/repository-authorities.v1.json`.

`appolon1908-hue/codestra-production-platform` is historical runtime/deployment/reconciliation/rollback evidence only. It is a migration reference, not central release authority.

## Core architecture

```text
                         Keycloak
                            |
                            v
                           Kong
                            ^
                            |
                          Caddy
                            |
                            v
                       Middleware
           +----------------+----------------+
           |                |                |
           v                v                v
 Vicidialer-Codestra   Telnexa/Jasmin   Klyrow/Email
           |              SMS only           |
           v                                 v
   VICIdial/Asterisk                     Postal/Mautic
           |
           +-------------> Odoo <-------------+
                              ^
                              |
                             n8n
                      orchestration only
```

Principal source repositories:

```text
Middleware               appolon1908-hue/Middleware-
Caddy                    appolon1908-hue/Caddy
Kong                     appolon1908-hue/Kong
Keycloak                 appolon1908-hue/Keycloak
n8n                      appolon1908-hue/N8N
Odoo                     appolon1908-hue/Odoo
Telnexa SMS/Jasmin       appolon1908-hue/telnexa
Telnexa website          appolon1908-hue/Telnexa-web
Klyrow runtime           appolon1908-hue/klyrow.com
Klyrow website           appolon1908-hue/klyrow-Website-
Kyqra crawler            appolon1908-hue/kyqra-crawler
VICIdial/Asterisk        appolon1908-hue/Vicidialer-Codestra
Provisioning             appolon1908-hue/codestra-provisioning-service
SDK / connector kit      appolon1908-hue/SDK-repository
Social/Postiz            appolon1908-hue/social.codestra.co
```

## Keycloak

`appolon1908-hue/Keycloak` contains a substantive GitOps identity implementation: canonical Codestra issuer, separate confidential machine clients, service audiences/scopes, exact-source/merge validation, drift review and protected apply controls. The Keycloak/Kong OIDC integration work has green source validation.

Stage 1 is still a live-runtime gate: a real Client Credentials token must be issued, accepted by the reviewed Kong route, rejected when invalid and revalidated by Middleware. Git configuration alone does not satisfy the exit condition.

## N8N

`appolon1908-hue/N8N` is the governed workflow source. Its policy explicitly prohibits direct writes to Odoo, VICIdial, Jasmin/Telnexa, Klyrow/Postal, Kyqra and privileged infrastructure. Workflow source remains inactive/fail-closed until endpoint, credential and runtime bindings are verified.

Middleware may store the contract it exposes to n8n; n8n workflow implementation belongs in `N8N`.

## Telnexa

`appolon1908-hue/telnexa` is a substantive Jasmin SMS backend/runtime with SMPP/HTTP, signed MO/DLR/failure callbacks, billing/wallet/ledger logic, backups and CI. Telnexa is SMS-only in the Codestra cross-system model.

`appolon1908-hue/Telnexa-web` is the separate public website/service-onboarding frontend. It is not a second SMS runtime.

VICIdial/Asterisk voice does not belong in Telnexa.

## Klyrow

`appolon1908-hue/klyrow.com` is the email/customer-communications runtime around Postal/Mautic/FastAPI with tenant state, delivery operations, suppressions and guarded production sending.

`appolon1908-hue/klyrow-Website-` is the separate public marketing frontend and must not duplicate Postal/Mautic queues, tenant state or credentials.

## Provisioning

`appolon1908-hue/codestra-provisioning-service` is the principal identity/access provisioning runtime. It has protected service authentication, durable idempotent step execution, verification/reconciliation and release/security gates. Middleware integrates with it but does not absorb its runtime.

## VICIdial/Asterisk

`appolon1908-hue/Vicidialer-Codestra` is the principal VICIdial/Asterisk voice/contact-center connector source. It contains restricted adapter/API code, campaign/lead operations, container/source validation and fail-closed dialing/provisioning controls.

Permanent path:

```text
VICIdial/Asterisk <-> Vicidialer-Codestra <-> Middleware <-> Odoo/n8n/Telnexa/Klyrow
```

Not VICIdial directly writing across those systems.

## Kyqra and Scrapper

Canonical crawler source:

```text
appolon1908-hue/kyqra-crawler
```

`appolon1908-hue/kyqra` is retained as legacy reference and is deprecated for new crawler implementation.

`appolon1908-hue/scrapper` contains active business-scrapper/control-plane source work but its own reviewed PR evidence does not prove staging or production deployment. It must not become a second canonical Kyqra crawler runtime.

## SDK versus Middleware Connector Runtime

Both repositories remain valid with different authorities:

```text
appolon1908-hue/SDK-repository
  = distributable contracts, generated SDKs, webhook helpers,
    connector-kit APIs, n8n nodes and developer tooling

appolon1908-hue/Middleware-
  = privileged Connector Runtime, trusted adapter registration,
    secret resolution, durable state, provider execution,
    read-back/reconciliation and capability enforcement
```

Do not duplicate hand-maintained public contracts across the two; use versioning/drift gates and generation where practical.

## Caddy correction

The repository inventory identified a dedicated `appolon1908-hue/Caddy` repository. Therefore the earlier interim decision to place future shared Caddy source under Kong is superseded.

Current decision:

```text
SHARED_CADDY_PRINCIPAL=appolon1908-hue/Caddy
KONG_PRINCIPAL=appolon1908-hue/Kong
HISTORICAL_CADDY_REFERENCE=appolon1908-hue/codestra-production-platform
HISTORICAL_REFERENCE_PATH=operations/caddy/api.codestra.co.caddy
```

The historical Caddy baseline from `codestra-production-platform:release/production-activation` is imported into the Caddy repository with provenance recorded. No live Caddy host is changed by the import.

Kong owns Kong gateway routes/plugins/security and Caddy→Kong compatibility, not the Caddy runtime source.

## Independent product repositories

The same principal-repository rule applies to independent products. Examples recorded in the authority registry include MoneyBee, Beyvra, Breero, LARIM-A, Booked4Seasons and the public Codestra site. Middleware can expose/consume integration contracts for them without becoming their application source.

## What Middleware is allowed to retain

Middleware may retain:

- canonical cross-system command/event contracts;
- provider command mappings and trusted adapters;
- generated compatibility expectations;
- integration tests and fixtures;
- Middleware runtime/Connector Runtime source;
- combined cross-repository release evidence.

It may not treat those derived files as authority to deploy another repository's application/runtime.

## Stage 0 exit verdict

```text
PRINCIPAL_REPOSITORY_RULE=DEFINED
PRINCIPAL_REPOSITORY_RULE_CI_ENFORCED=YES
CODESTRA_PRODUCTION_PLATFORM=REFERENCE_ONLY
CADDY_DEDICATED_REPO_FOUND=YES
CADDY_PRINCIPAL=appolon1908-hue/Caddy
KONG_PRINCIPAL=appolon1908-hue/Kong
KEYCLOAK_PRINCIPAL=appolon1908-hue/Keycloak
N8N_PRINCIPAL=appolon1908-hue/N8N
ODOO_PRINCIPAL=appolon1908-hue/Odoo
TELNEXA_SMS_PRINCIPAL=appolon1908-hue/telnexa
KLYROW_PRINCIPAL=appolon1908-hue/klyrow.com
VICIDIAL_PRINCIPAL=appolon1908-hue/Vicidialer-Codestra
KYQRA_CRAWLER_PRINCIPAL=appolon1908-hue/kyqra-crawler
PROVISIONING_PRINCIPAL=appolon1908-hue/codestra-provisioning-service
SDK_PRINCIPAL=appolon1908-hue/SDK-repository
LIVE_RUNTIME_CHANGED=NO
PRODUCTION_ACTIVATED=NO
```

Stages 1–9 retain their live identity, read-back, staging, backup/restore, rollback and explicit production-approval gates. Repository cleanup does not waive those gates.
