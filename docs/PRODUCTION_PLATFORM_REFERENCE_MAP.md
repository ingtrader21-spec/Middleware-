# `codestra-production-platform` reference map

`appolon1908-hue/codestra-production-platform` is historical runtime/deployment/reconciliation/rollback evidence. It is not principal source for a component that has a dedicated repository.

Use historical material only to reconcile prior runtime behavior into the correct principal repository. Preserve provenance and do not blindly copy secrets, runtime state or stale deployment assumptions.

| Historical area | Use as reference for | Principal source now |
|---|---|---|
| `operations/caddy/` | prior shared Caddy edge configuration | `appolon1908-hue/Caddy` |
| `operations/kong-database/` and Kong reconciliation evidence | prior Kong database/runtime operations | `appolon1908-hue/Kong` |
| `operations/odoo-n8n/` | prior Odoo/n8n integration/runtime evidence | `appolon1908-hue/Odoo`, `appolon1908-hue/N8N`, plus Middleware contracts in `appolon1908-hue/Middleware-` |
| historical control-plane/Middleware packages | prior Middleware deployment/runtime behavior | `appolon1908-hue/Middleware-` |
| historical Keycloak/identity material | prior identity deployment/runtime evidence | `appolon1908-hue/Keycloak` |
| historical VICIdial/Asterisk material | prior telephony integration/runtime evidence | `appolon1908-hue/Vicidialer-Codestra` |
| historical SMS/Jasmin material | prior SMS runtime/integration evidence | `appolon1908-hue/telnexa` |
| historical email/Postal/Mautic material | prior email runtime/integration evidence | `appolon1908-hue/klyrow.com` |
| historical crawler material | prior crawler integration/runtime evidence | `appolon1908-hue/kyqra-crawler` |
| historical provisioning material | prior provisioning runtime/integration evidence | `appolon1908-hue/codestra-provisioning-service` |
| `operations/backup/`, `operations/recovery/`, `operations/restore/`, `operations/readiness/`, `operations/canary/`, `operations/production-operator/`, `operations/runbooks/` | historical operational evidence for the runtime they describe | preserve as evidence; changes to a service's current runtime/runbook belong with that service unless the content is truly shared infrastructure |
| `operations/shared-postgresql/`, `operations/database-rbac/` | historical shared-database evidence | do not assign to an application repo blindly; first identify the database owner and then place current policy with that owner |
| `operations/monitoring/` | historical monitoring evidence | retain as reference until an explicit current monitoring owner is established; do not use it to override service-owned observability config |

## Migration method

For any historical file that still contains useful current behavior:

1. identify the component it actually controls;
2. confirm that component's principal repository in `config/repository-authorities.v1.json`;
3. compare historical source to the principal repository and current runtime read-only;
4. port only reviewed, non-secret behavior into the principal repository;
5. add tests and provenance there;
6. validate in staging;
7. rehearse rollback where the change is operational;
8. leave the old platform copy intact as historical evidence or mark it frozen/deprecated.

Never solve drift by making `codestra-production-platform` principal again.
