# Server Runtime Reconciliation Map

## Frozen evidence

- `NEW_ARCHITECTURE_MAIN_SHA=844d13c7ba808653a7d982c63353bc67cdc9adef`
- `SERVER_CAPTURE_SHA=85b7898456abd4bdd0928b80ea925cafd8ad0f4c`
- `SERVER_SOURCE_SHA=7b9451b4db92982e5f0a4179d979ae94c043f943`
- Evidence branch: `import/server-runtime-20260828` (read-only; never merge directly)

This map is a classification and migration plan only. It ports no runtime code and authorizes no deployment. The 32 captured Middleware-related containers are mapped one-for-one below.

## Decision rules

The new transactional inbox/outbox, event ledger, command ledger, NATS transport, Temporal architecture, connector runtime, tenant validation, capabilities, idempotency, replay controls, canonical contracts, signed activation and security gates remain authoritative. A server behavior is retained only when it can be expressed through those boundaries.

## Coverage summary

- Captured containers: **32**
- Classified containers: **32**
- Unknown/unclassified containers: **0**
- `ALREADY_IMPLEMENTED`: **2**
- `DUPLICATE`: **7**
- `KEEP_AND_PORT`: **15**
- `REPLACE_WITH_NEW_ARCHITECTURE`: **7**
- `SERVER_ONLY_NEEDS_REVIEW`: **1**

## Component index

| Server component | Revision | New architecture equivalent | Action |
|---|---|---|---|
| `codestra-middleware-vicidial-adapter-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | `vicidial-restricted` connector | `KEEP_AND_PORT` |
| `codestra-middleware-telephony-provisioning-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | provisioning-service connector orchestrated by Middleware | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-pjsip-adapter-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | new Asterisk/PJSIP connector to be added | `KEEP_AND_PORT` |
| `codestra-middleware-webphone-session-issuer-1` | `80954a1ecb4eae49a57a9de245f78fd9a2f825a1` | isolated webphone session connector/API with Keycloak validation | `KEEP_AND_PORT` |
| `codestra-middleware-integration-api-1` | `35448ef85ae56db3651a72b61db8e242b7aacd2e` | `app.main`, `app.service`, `app.commands`, and connector-runtime API | `KEEP_AND_PORT` |
| `codestra-middleware-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | `app.main` intake API plus connector-runtime management API | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-odoo-result-worker-1` | `d30babd35b7b82aab312f16940f5b8d2f7797f1d` | Odoo connector plus canonical command/result events | `KEEP_AND_PORT` |
| `codestra-middleware-notification-worker-1` | `9118e5bc01f9ce4a52add8753c096d061cd84848` | canonical outbox worker and connector commands | `KEEP_AND_PORT` |
| `codestra-middleware-scheduler-1` | `9118e5bc01f9ce4a52add8753c096d061cd84848` | Temporal schedules/workflows and `core/workers-scheduler` | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-staging-middleware-staging-1` | `9118e5bc01f9ce4a52add8753c096d061cd84848` | same canonical API build with staging runtime profile | `DUPLICATE` |
| `codestra-middleware-staging-notification-worker-staging-1` | `9118e5bc01f9ce4a52add8753c096d061cd84848` | same canonical notification/outbox worker with staging profile | `DUPLICATE` |
| `codestra-middleware-staging-scheduler-staging-1` | `9118e5bc01f9ce4a52add8753c096d061cd84848` | same Temporal scheduler/workflow build with staging queue | `DUPLICATE` |
| `codestra-middleware-evidence-runner-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | synthetic staging acceptance and release-manifest validators | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-policy-engine-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | capability registry, operation policy and runtime-safety controls | `KEEP_AND_PORT` |
| `codestra-middleware-sync-worker-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | connector event ingestion plus Temporal workflows | `SERVER_ONLY_NEEDS_REVIEW` |
| `codestra-middleware-n8n-runtime-worker-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | generated n8n workflow packs plus command/event contracts | `KEEP_AND_PORT` |
| `codestra-middleware-social-n8n-delivery-worker-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | Postly connector manifest and n8n workflow pack | `KEEP_AND_PORT` |
| `codestra-middleware-reconciliation-worker-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | Temporal reconciliation workflows and command read-back | `KEEP_AND_PORT` |
| `codestra-middleware-extension-allocator-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | provisioning-service connector and tenant-onboarding command boundary | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-event-gateway-1` | `4a3ac0b57a61baf63310c55048a7897556faa9a972083b86761e91391ae2317b` | `app.main` signed intake and connector-runtime `webhook_ingress` | `KEEP_AND_PORT` |
| `codestra-middleware-external-webhook-worker-1` | `4a3ac0b57a61baf63310c55048a7897556faa9a972083b86761e91391ae2317b` | connector-runtime inbox processing plus Temporal/outbox workers | `KEEP_AND_PORT` |
| `codestra-middleware-breero-odoo-worker-1` | `51416422eaaa959c8c7223ad1434287597eb8007` | Breero connector feeding lead normalization and Odoo connector | `KEEP_AND_PORT` |
| `codestra-middleware-postly-polling-worker-1` | `b3ca9aa458fef843e3065aeff3397c656349f138` | Postly social connector event ingestion | `KEEP_AND_PORT` |
| `codestra-middleware-scraper-odoo-delivery-worker-1` | `bab6f4332fec77611f6a364fd3c9c7f9cc022051` | Kyqra/scraper connector, lead normalization, and Odoo connector | `KEEP_AND_PORT` |
| `codestra-middleware-staging-redis-1` | `UNKNOWN` | `platform/redis` runtime dependency | `ALREADY_IMPLEMENTED` |
| `codestra-middleware-staging-odoo-result-worker-staging-1` | `45c467899e0c7580538de72d543fb3de0b09cd75` | same canonical Odoo connector worker with staging profile | `DUPLICATE` |
| `codestra-middleware-staging-scraper-odoo-delivery-worker-1` | `4780bd72d1c574af4aed62d374ec50b208e8ea4c` | same scraper→normalization→Odoo connector pipeline with staging profile | `DUPLICATE` |
| `codestra-middleware-staging-social-delivery-worker-staging-1` | `unknown` | canonical Postly connector delivery worker | `DUPLICATE` |
| `codestra-middleware-staging-social-dead-letter-worker-staging-1` | `unknown` | canonical dead-letter/replay workflow | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-staging-social-reconciliation-worker-staging-1` | `unknown` | canonical reconciliation workflow plus Postly read-back | `DUPLICATE` |
| `codestra-middleware-staging-callback-staging-1` | `f1c07e0-reprofix2` | signed connector webhook ingress | `REPLACE_WITH_NEW_ARCHITECTURE` |
| `codestra-middleware-staging-postgres-1` | `UNKNOWN` | `platform/postgresql` and canonical migration sets | `ALREADY_IMPLEMENTED` |

## Complete component records

### 1. `codestra-middleware-vicidial-adapter-1`

- `SERVER_COMPONENT=codestra-middleware-vicidial-adapter-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.vicidial_adapter`
- `SERVER_DEPENDENCIES=VICIdial private endpoints; command ledger; telephony events; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=`vicidial-restricted` connector`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Preserve restricted telephony capabilities behind OAuth2+mTLS, explicit command prefixes and mandatory read-back.`
- `TEST_REQUIRED=VICIdial mock, mTLS, capability denial, idempotency, timeout and unknown-outcome tests`

### 2. `codestra-middleware-telephony-provisioning-1`

- `SERVER_COMPONENT=codestra-middleware-telephony-provisioning-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.telephony_provisioning`
- `SERVER_DEPENDENCIES=Provisioning service; VICIdial/PJSIP connectors; command ledger; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=provisioning-service connector orchestrated by Middleware`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=Provisioning lifecycle/state belongs to provisioning service; Middleware retains tenant/capability authorization and orchestration only.`
- `TEST_REQUIRED=Provisioning mock, duplicate desired state, partial failure, rollback and read-back tests`

### 3. `codestra-middleware-pjsip-adapter-1`

- `SERVER_COMPONENT=codestra-middleware-pjsip-adapter-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.pjsip_adapter`
- `SERVER_DEPENDENCIES=Asterisk/PJSIP provider; provisioning service; command ledger; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=new Asterisk/PJSIP connector to be added`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=PJSIP behavior is required but lacks a complete connector manifest in main; it must not remain an ad-hoc entrypoint.`
- `TEST_REQUIRED=Asterisk/PJSIP mock, mTLS, tenant, retry, read-back and forbidden-command tests`

### 4. `codestra-middleware-webphone-session-issuer-1`

- `SERVER_COMPONENT=codestra-middleware-webphone-session-issuer-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:48dbb4201b4cf8abee1600936a84da52a92969ab124fb44a0007059e75d57e85`
- `SERVER_REVISION=80954a1ecb4eae49a57a9de245f78fd9a2f825a1`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.webphone_session_issuer`
- `SERVER_DEPENDENCIES=Keycloak; provisioning service; telephony session backend; NETWORKS=codestra-identity_identity_service,codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=isolated webphone session connector/API with Keycloak validation`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Short-lived browser session issuance remains separate from telephony command authority and must not expose provider credentials.`
- `TEST_REQUIRED=JWT audience/azp, tenant, expiry, replay, credential non-disclosure and revocation tests`

### 5. `codestra-middleware-integration-api-1`

- `SERVER_COMPONENT=codestra-middleware-integration-api-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:09d4bd0f7b2376e0a06d3efae27a6642429389fa7e3277791ec0b36584e87175`
- `SERVER_REVISION=35448ef85ae56db3651a72b61db8e242b7aacd2e`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=/opt/venv/bin/python -m app.entrypoints.integration_api`
- `SERVER_DEPENDENCIES=PostgreSQL; Redis; Keycloak; n8n; Odoo; provisioning; internal integration gateway; NETWORKS=codestra-identity_identity_service,codestra-internal-integration,codestra-n8n-middleware-staging-control,codestra-odoo19-module-staging_isolated,codestra-provisioning-service_private,codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=`app.main`, `app.service`, `app.commands`, and connector-runtime API`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=This is the principal server API surface. Required endpoint semantics must be inventoried and selectively ported; direct provider writes must become commands/connectors.`
- `TEST_REQUIRED=Per-route contract matrix plus authorization, tenant, idempotency and no-direct-write tests`

### 6. `codestra-middleware-1`

- `SERVER_COMPONENT=codestra-middleware-1`
- `SERVER_IMAGE=codestra/middleware:health-contract-b3ca9aa`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.integration_api`
- `SERVER_DEPENDENCIES=PostgreSQL; Redis; Keycloak; provisioning service; Odoo boundary; NETWORKS=codestra-identity_identity_service,codestra-odoo19-module-staging_isolated,codestra-provisioning-service_private,codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=`app.main` intake API plus connector-runtime management API`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=The container duplicates the integration API and uses legacy route/write boundaries. Preserve only explicitly mapped endpoint behavior behind canonical auth, tenant, inbox/outbox and command controls.`
- `TEST_REQUIRED=API contract, JWT/OIDC, tenant isolation, idempotency, capability denial and legacy-route parity tests`

### 7. `codestra-middleware-odoo-result-worker-1`

- `SERVER_COMPONENT=codestra-middleware-odoo-result-worker-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:ab74b9eb56c9625597476ab6669b065b471314c912cb2d4677118de230e3d4e2`
- `SERVER_REVISION=d30babd35b7b82aab312f16940f5b8d2f7797f1d`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=/opt/venv/bin/python -m app.entrypoints.odoo_result_worker`
- `SERVER_DEPENDENCIES=PostgreSQL; Odoo connector; Keycloak service identity; NETWORKS=codestra-identity_identity_service,codestra-internal-integration,codestra_backend`
- `NEW_ARCH_EQUIVALENT=Odoo connector plus canonical command/result events`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Delivery results remain required, but Odoo writes must pass through the command/capability boundary and record read-back.`
- `TEST_REQUIRED=Odoo mock, tenant, duplicate, conflict, retry and read-back completion tests`

### 8. `codestra-middleware-notification-worker-1`

- `SERVER_COMPONENT=codestra-middleware-notification-worker-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:73fe86858d7a9303bbb151c77097aa43c0739e71c4781636e7db81dd4eadbf98`
- `SERVER_REVISION=9118e5bc01f9ce4a52add8753c096d061cd84848`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=/opt/venv/bin/python -m app.entrypoints.notification_worker`
- `SERVER_DEPENDENCIES=PostgreSQL outbox; Redis; communications connectors; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=canonical outbox worker and connector commands`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Notification scheduling/delivery is required, but every external effect must use an explicit connector and capability.`
- `TEST_REQUIRED=Email/SMS mocks, capability denial, retry, receipt and opt-out tests`

### 9. `codestra-middleware-scheduler-1`

- `SERVER_COMPONENT=codestra-middleware-scheduler-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:73fe86858d7a9303bbb151c77097aa43c0739e71c4781636e7db81dd4eadbf98`
- `SERVER_REVISION=9118e5bc01f9ce4a52add8753c096d061cd84848`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=/opt/venv/bin/python -m app.entrypoints.scheduler`
- `SERVER_DEPENDENCIES=Temporal; PostgreSQL; command ledger; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=Temporal schedules/workflows and `core/workers-scheduler``
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=Local polling semantics should be represented as durable Temporal schedules or database-backed leases, not an undocumented standalone scheduler.`
- `TEST_REQUIRED=Schedule idempotency, missed tick, overlapping lease, restart and delayed callback tests`

### 10. `codestra-middleware-staging-middleware-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-middleware-staging-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:73fe86858d7a9303bbb151c77097aa43c0739e71c4781636e7db81dd4eadbf98`
- `SERVER_REVISION=9118e5bc01f9ce4a52add8753c096d061cd84848`
- `SERVER_ENTRYPOINT=(none); COMMAND=/opt/venv/bin/python -m app.entrypoints.integration_api`
- `SERVER_DEPENDENCIES=Staging PostgreSQL/Redis/Keycloak/n8n; NETWORKS=codestra-identity-staging_service,codestra-identity_identity_service,codestra-middleware-staging_backend,codestra-n8n-middleware-staging-control,codestra-n8n-staging_edge`
- `NEW_ARCH_EQUIVALENT=same canonical API build with staging runtime profile`
- `ACTION=DUPLICATE`
- `RATIONALE=Staging is an environment of the canonical API, not a separate source history or implementation.`
- `TEST_REQUIRED=Same-image provenance, staging fail-closed profile and external-effects-disabled acceptance`

### 11. `codestra-middleware-staging-notification-worker-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-notification-worker-staging-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:73fe86858d7a9303bbb151c77097aa43c0739e71c4781636e7db81dd4eadbf98`
- `SERVER_REVISION=9118e5bc01f9ce4a52add8753c096d061cd84848`
- `SERVER_ENTRYPOINT=(none); COMMAND=/opt/venv/bin/python -m app.entrypoints.notification_worker`
- `SERVER_DEPENDENCIES=Staging PostgreSQL; Redis; mock connectors; NETWORKS=codestra-identity-staging_service,codestra-middleware-staging_backend,codestra-n8n-staging_edge`
- `NEW_ARCH_EQUIVALENT=same canonical notification/outbox worker with staging profile`
- `ACTION=DUPLICATE`
- `RATIONALE=Environment-specific deployment only; no separate source implementation should survive.`
- `TEST_REQUIRED=Same-image provenance and communications mocks with all live effects disabled`

### 12. `codestra-middleware-staging-scheduler-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-scheduler-staging-1`
- `SERVER_IMAGE=ghcr.io/codestra-srl/codestra-middleware@sha256:73fe86858d7a9303bbb151c77097aa43c0739e71c4781636e7db81dd4eadbf98`
- `SERVER_REVISION=9118e5bc01f9ce4a52add8753c096d061cd84848`
- `SERVER_ENTRYPOINT=(none); COMMAND=/opt/venv/bin/python -m app.entrypoints.scheduler`
- `SERVER_DEPENDENCIES=Staging Temporal; PostgreSQL; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=same Temporal scheduler/workflow build with staging queue`
- `ACTION=DUPLICATE`
- `RATIONALE=Environment-specific instance of the scheduler replacement.`
- `TEST_REQUIRED=Same-image provenance, isolated task queue and restart tests`

### 13. `codestra-middleware-evidence-runner-1`

- `SERVER_COMPONENT=codestra-middleware-evidence-runner-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.evidence_runner`
- `SERVER_DEPENDENCIES=Release manifest; staging API; observability; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=synthetic staging acceptance and release-manifest validators`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=Runtime evidence must come from reproducible acceptance/release tooling, not a permanently running mixed-revision utility container.`
- `TEST_REQUIRED=No-effect acceptance, source/digest attestation and evidence immutability tests`

### 14. `codestra-middleware-policy-engine-1`

- `SERVER_COMPONENT=codestra-middleware-policy-engine-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.policy_engine`
- `SERVER_DEPENDENCIES=Capability registry; Keycloak claims; command policy; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=capability registry, operation policy and runtime-safety controls`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Server policy decisions may contain required behavior, but the new signed capability and activation design remains authoritative.`
- `TEST_REQUIRED=Default deny, expiry, tenant mismatch, forbidden prefix and signed activation tests`

### 15. `codestra-middleware-sync-worker-1`

- `SERVER_COMPONENT=codestra-middleware-sync-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.sync_worker`
- `SERVER_DEPENDENCIES=PostgreSQL; provider connectors; event ledger; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=connector event ingestion plus Temporal workflows`
- `ACTION=SERVER_ONLY_NEEDS_REVIEW`
- `RATIONALE=The generic sync scope is not explicit enough to port safely. Each synchronized resource must be assigned to a connector/event contract first.`
- `TEST_REQUIRED=Resource-specific ownership, tenant, cursor, duplicate and convergence tests`

### 16. `codestra-middleware-n8n-runtime-worker-1`

- `SERVER_COMPONENT=codestra-middleware-n8n-runtime-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.n8n_runtime_worker`
- `SERVER_DEPENDENCIES=PostgreSQL; n8n; Keycloak service identity; command ledger; NETWORKS=codestra-n8n-middleware-staging-control,codestra_backend`
- `NEW_ARCH_EQUIVALENT=generated n8n workflow packs plus command/event contracts`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Retain orchestration handoff while making Middleware the authorization and durable-command boundary.`
- `TEST_REQUIRED=Signed handoff, scope, idempotency, result correlation and forbidden-direct-write tests`

### 17. `codestra-middleware-social-n8n-delivery-worker-1`

- `SERVER_COMPONENT=codestra-middleware-social-n8n-delivery-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.social_n8n_delivery_worker`
- `SERVER_DEPENDENCIES=PostgreSQL; n8n; Postiz/Postly connector; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=Postly connector manifest and n8n workflow pack`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Retain delivery orchestration but move provider calls behind the social connector; do not duplicate Postiz domain logic.`
- `TEST_REQUIRED=Social mock, duplicate, provider 429/500, callback and reconciliation tests`

### 18. `codestra-middleware-reconciliation-worker-1`

- `SERVER_COMPONENT=codestra-middleware-reconciliation-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.reconciliation_worker`
- `SERVER_DEPENDENCIES=Temporal; PostgreSQL command ledger; connector read-back; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=Temporal reconciliation workflows and command read-back`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Reconciliation is a core requirement and must compare durable intent with provider read-back before completion.`
- `TEST_REQUIRED=Unknown outcome, mismatch, retry, rollback, dead-letter approval and restart tests`

### 19. `codestra-middleware-extension-allocator-1`

- `SERVER_COMPONENT=codestra-middleware-extension-allocator-1`
- `SERVER_IMAGE=codestra/middleware@sha256:1a9e13a0c930d36076b5742e17f948dc85d9bc6ace90e58052756c8b1ad42700`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.extension_allocator`
- `SERVER_DEPENDENCIES=Provisioning service; command ledger; telephony connector; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=provisioning-service connector and tenant-onboarding command boundary`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=Resource allocation belongs to provisioning service; Middleware should authorize/orchestrate the command without owning allocation state.`
- `TEST_REQUIRED=Idempotent provisioning mock, tenant, desired-state, read-back and duplicate allocation tests`

### 20. `codestra-middleware-event-gateway-1`

- `SERVER_COMPONENT=codestra-middleware-event-gateway-1`
- `SERVER_IMAGE=codestra/middleware:webhook-cert-pg-20260816`
- `SERVER_REVISION=4a3ac0b57a61baf63310c55048a7897556faa9a972083b86761e91391ae2317b`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.event_gateway`
- `SERVER_DEPENDENCIES=PostgreSQL; Redis; edge ingress; provider signature secrets; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=`app.main` signed intake and connector-runtime `webhook_ingress``
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Provider ingress behavior remains required, but verification and acknowledgement must terminate in the canonical durable inbox/outbox.`
- `TEST_REQUIRED=Body limit, HMAC, timestamp, duplicate, conflict, tenant routing, restart and redelivery tests`

### 21. `codestra-middleware-external-webhook-worker-1`

- `SERVER_COMPONENT=codestra-middleware-external-webhook-worker-1`
- `SERVER_IMAGE=codestra/middleware:webhook-cert-pg-20260816`
- `SERVER_REVISION=4a3ac0b57a61baf63310c55048a7897556faa9a972083b86761e91391ae2317b`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.external_webhook_worker`
- `SERVER_DEPENDENCIES=PostgreSQL inbox/outbox; n8n control network; connector contracts; NETWORKS=codestra-n8n-middleware-staging-control,codestra_backend`
- `NEW_ARCH_EQUIVALENT=connector-runtime inbox processing plus Temporal/outbox workers`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Asynchronous webhook processing is valid only after durable acknowledgement; n8n delivery cannot be the source of write authority.`
- `TEST_REQUIRED=Inbox lease, retry, dead-letter, timeout, n8n mock and restart tests`

### 22. `codestra-middleware-breero-odoo-worker-1`

- `SERVER_COMPONENT=codestra-middleware-breero-odoo-worker-1`
- `SERVER_IMAGE=codestra/middleware:breero-51416422`
- `SERVER_REVISION=51416422eaaa959c8c7223ad1434287597eb8007`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.breero_odoo_worker`
- `SERVER_DEPENDENCIES=Breero connector; lead normalization; Odoo connector; PostgreSQL; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=Breero connector feeding lead normalization and Odoo connector`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Preserve mapping behavior as two explicit connector boundaries with canonical lead provenance and review policy.`
- `TEST_REQUIRED=Breero/Odoo mocks, mapping golden files, consent, suppression, duplicate and tenant tests`

### 23. `codestra-middleware-postly-polling-worker-1`

- `SERVER_COMPONENT=codestra-middleware-postly-polling-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:d3ac2b34d216064bc579feedca9cc2d4079ebe44943a6417ab31437c79df8dd8`
- `SERVER_REVISION=b3ca9aa458fef843e3065aeff3397c656349f138`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.postly_polling_worker`
- `SERVER_DEPENDENCIES=Postly connector; PostgreSQL cursor/inbox; edge/provider API; NETWORKS=codestra_backend,codestra_edge`
- `NEW_ARCH_EQUIVALENT=Postly social connector event ingestion`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Polling may be retained only as connector-owned event acquisition with durable cursors, rate limits and normalized events.`
- `TEST_REQUIRED=Cursor restart, rate limit, duplicate event, provider 429/500 and normalization tests`

### 24. `codestra-middleware-scraper-odoo-delivery-worker-1`

- `SERVER_COMPONENT=codestra-middleware-scraper-odoo-delivery-worker-1`
- `SERVER_IMAGE=codestra/middleware@sha256:55dfe9ddfa8bfa94a9202284cb5276311e009066784bbde5dc05d5e1c3776492`
- `SERVER_REVISION=bab6f4332fec77611f6a364fd3c9c7f9cc022051`
- `SERVER_ENTRYPOINT=/usr/local/bin/live-delivery-admission; COMMAND=python -m app.entrypoints.scraper_odoo_delivery_worker`
- `SERVER_DEPENDENCIES=Scraper/Kyqra connector; lead normalization; Odoo connector; NETWORKS=codestra_backend`
- `NEW_ARCH_EQUIVALENT=Kyqra/scraper connector, lead normalization, and Odoo connector`
- `ACTION=KEEP_AND_PORT`
- `RATIONALE=Scraper discoveries must enter review_pending and cannot write directly to Odoo.`
- `TEST_REQUIRED=Review-required, provenance, suppression, no-contact, duplicate and Odoo mock tests`

### 25. `codestra-middleware-staging-redis-1`

- `SERVER_COMPONENT=codestra-middleware-staging-redis-1`
- `SERVER_IMAGE=redis@sha256:bb186d083732f669da90be8b0f975a37812b15e913465bb14d845db72a4e3e08`
- `SERVER_REVISION=UNKNOWN`
- `SERVER_ENTRYPOINT=docker-entrypoint.sh; COMMAND=redis-server --appendonly yes --save 60 1 --maxmemory 384mb --maxmemory-policy noeviction --aclfile /run/secrets/redis-users.acl`
- `SERVER_DEPENDENCIES=Staging workers; Redis ACL secret; staging network; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=`platform/redis` runtime dependency`
- `ACTION=ALREADY_IMPLEMENTED`
- `RATIONALE=Redis remains an optional coordination/cache primitive; durable correctness cannot depend on it.`
- `TEST_REQUIRED=ACL, outage, restart, cache-loss and no-durability-dependency tests`

### 26. `codestra-middleware-staging-odoo-result-worker-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-odoo-result-worker-staging-1`
- `SERVER_IMAGE=codestra/middleware:r1-45c4678`
- `SERVER_REVISION=45c467899e0c7580538de72d543fb3de0b09cd75`
- `SERVER_ENTRYPOINT=(none); COMMAND=python -m app.entrypoints.odoo_result_worker`
- `SERVER_DEPENDENCIES=Staging PostgreSQL; Odoo staging/mock; Keycloak; NETWORKS=codestra-identity-staging_service,codestra-middleware-staging_backend,codestra-n8n-staging_edge`
- `NEW_ARCH_EQUIVALENT=same canonical Odoo connector worker with staging profile`
- `ACTION=DUPLICATE`
- `RATIONALE=The unique staging revision is release drift, not a distinct supported component.`
- `TEST_REQUIRED=Same-image provenance and Odoo mock/read-back tests`

### 27. `codestra-middleware-staging-scraper-odoo-delivery-worker-1`

- `SERVER_COMPONENT=codestra-middleware-staging-scraper-odoo-delivery-worker-1`
- `SERVER_IMAGE=codestra/middleware:scraper-protected-main-4780bd72`
- `SERVER_REVISION=4780bd72d1c574af4aed62d374ec50b208e8ea4c`
- `SERVER_ENTRYPOINT=(none); COMMAND=python -m app.entrypoints.scraper_odoo_delivery_worker`
- `SERVER_DEPENDENCIES=Staging PostgreSQL; scraper mock; Odoo mock; NETWORKS=codestra-middleware-staging_backend,codestra-n8n-staging_edge`
- `NEW_ARCH_EQUIVALENT=same scraper→normalization→Odoo connector pipeline with staging profile`
- `ACTION=DUPLICATE`
- `RATIONALE=The staging-only image history must collapse into the canonical connector worker build.`
- `TEST_REQUIRED=Same-image provenance, review_pending and Odoo mock tests`

### 28. `codestra-middleware-staging-social-delivery-worker-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-social-delivery-worker-staging-1`
- `SERVER_IMAGE=codestra/middleware:social-staging-12cd5fc`
- `SERVER_REVISION=unknown`
- `SERVER_ENTRYPOINT=(none); COMMAND=python -m app.entrypoints.social_delivery_worker`
- `SERVER_DEPENDENCIES=Staging PostgreSQL; Postly mock; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=canonical Postly connector delivery worker`
- `ACTION=DUPLICATE`
- `RATIONALE=Unknown image provenance is unacceptable; behavior must be covered by the canonical social connector.`
- `TEST_REQUIRED=Same-image provenance, social mock and no-effect staging tests`

### 29. `codestra-middleware-staging-social-dead-letter-worker-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-social-dead-letter-worker-staging-1`
- `SERVER_IMAGE=codestra/middleware:social-staging-12cd5fc`
- `SERVER_REVISION=unknown`
- `SERVER_ENTRYPOINT=(none); COMMAND=python -m app.entrypoints.social_dead_letter_worker`
- `SERVER_DEPENDENCIES=Temporal; PostgreSQL; Postly connector; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=canonical dead-letter/replay workflow`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=Use the operator-approved dead-letter replay workflow rather than a social-specific undocumented implementation.`
- `TEST_REQUIRED=Approval, audit, correction, replay idempotency and tenant tests`

### 30. `codestra-middleware-staging-social-reconciliation-worker-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-social-reconciliation-worker-staging-1`
- `SERVER_IMAGE=codestra/middleware:social-staging-12cd5fc`
- `SERVER_REVISION=unknown`
- `SERVER_ENTRYPOINT=(none); COMMAND=python -m app.entrypoints.social_reconciliation_worker`
- `SERVER_DEPENDENCIES=Temporal; PostgreSQL; Postly connector; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=canonical reconciliation workflow plus Postly read-back`
- `ACTION=DUPLICATE`
- `RATIONALE=Social reconciliation is a connector specialization of the shared workflow, not a separate source lineage.`
- `TEST_REQUIRED=Postly read-back mismatch, timeout, retry and restart tests`

### 31. `codestra-middleware-staging-callback-staging-1`

- `SERVER_COMPONENT=codestra-middleware-staging-callback-staging-1`
- `SERVER_IMAGE=codestra/middleware:current-hardened-20260723`
- `SERVER_REVISION=f1c07e0-reprofix2`
- `SERVER_ENTRYPOINT=(none); COMMAND=python3 /app/staging_callback_receiver.py`
- `SERVER_DEPENDENCIES=Staging ingress; connector inbox; n8n staging network; NETWORKS=codestra-n8n-staging_edge`
- `NEW_ARCH_EQUIVALENT=signed connector webhook ingress`
- `ACTION=REPLACE_WITH_NEW_ARCHITECTURE`
- `RATIONALE=The standalone script and unknown/noncanonical revision should be replaced by the shared signed durable ingress.`
- `TEST_REQUIRED=Callback HMAC, timestamp, body limit, duplicate, tenant and durable-ack tests`

### 32. `codestra-middleware-staging-postgres-1`

- `SERVER_COMPONENT=codestra-middleware-staging-postgres-1`
- `SERVER_IMAGE=postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`
- `SERVER_REVISION=UNKNOWN`
- `SERVER_ENTRYPOINT=docker-entrypoint.sh; COMMAND=postgres`
- `SERVER_DEPENDENCIES=Middleware schemas; connector-runtime schema; staging network; NETWORKS=codestra-middleware-staging_backend`
- `NEW_ARCH_EQUIVALENT=`platform/postgresql` and canonical migration sets`
- `ACTION=ALREADY_IMPLEMENTED`
- `RATIONALE=PostgreSQL remains the durable store; reconcile schemas/migrations rather than porting the container as application code.`
- `TEST_REQUIRED=Empty→head, previous→head, downgrade/upgrade, locking, checksum and restart tests`

## Cross-cutting server functionality inventory

| Functionality | Evidence components | Canonical destination | Decision |
|---|---|---|---|
| API/auth/request context | primary and integration APIs | `app.main`, security, tenant context, connector-runtime API | Selectively port documented behavior |
| Durable ingress | event gateway, callback receiver | canonical signed inbox/outbox and connector ingress | Replace standalone ingress paths |
| Durable execution | scheduler, notification, sync, reconciliation workers | Temporal, command ledger, outbox workers | Port behavior onto durable primitives |
| Odoo delivery | result, Breero and scraper workers | Odoo connector and lead normalization | Port; prohibit direct writes |
| n8n | runtime and social delivery workers | signed command/event handoff | Port; Middleware remains authority |
| Telephony | VICIdial, PJSIP, provisioning, webphone | explicit connectors plus provisioning boundary | Port with separated authorities |
| Social | Postly polling/delivery/dead-letter/reconciliation | Postly connector and shared workflows | Port connector-specific behavior only |
| Runtime evidence | evidence runner | synthetic acceptance/release manifest | Replace |
| Infrastructure | PostgreSQL and Redis | platform primitives | Reconcile configuration/migrations |

## Required follow-up inventories before code porting

1. Extract every legacy API route and produce method/path/auth/tenant/request/response/idempotency/capability/effect/owner records.
2. Extract server database objects and compare them with both canonical and connector-runtime migrations.
3. Assign generic sync/notification behavior to named connectors; no generic provider authority may survive.
4. Define Asterisk/PJSIP and Breero connector manifests; these are required but incomplete in main.
5. Reconcile the 26 captured Compose inputs in the later Compose-consolidation milestone.
6. Require every eventual build target to carry one approved source SHA in OCI source/revision/version labels.

## A1 exit gate

- `SERVER_FUNCTIONALITY_MAPPED=100%` for captured running containers.
- `UNKNOWN_COMPONENTS=0` at the container level.
- Generic sync semantics remain `SERVER_ONLY_NEEDS_REVIEW` and must be decomposed before implementation.
- No server code was ported by this milestone.
