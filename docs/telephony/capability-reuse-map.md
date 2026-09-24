# Capability Reuse Map

| Required capability | Reused authority | Increment |
|---|---|---|
| Odoo request and approval | `codestra.provisioning.request` | Map new saga states; no duplicate model |
| Provisioning steps/compensation | `codestra.provisioning.step` and provisioning-service engine | Add production PostgreSQL authority and gates |
| Identity projection | `codestra.identity.link` | Add registration/provider drift states |
| Pool boundary | `codestra.extension.pool` | Configure the approved business-unit/role ranges |
| Assignment | `codestra.extension.assignment` | Preserve history while enforcing one active assignment |
| Reservation | `codestra.identifier.reservation` plus middleware reservation | Middleware becomes transactional allocation authority |
| Secrets | `codestra.credential.reference` plus protected secret store | Never persist secret values in Odoo/n8n |
| Audit | `codestra.provisioning.audit` plus middleware `audit_event` | Correlated, sanitized cross-system evidence |
| VICIdial/PJSIP mutation | Existing provisioning-service mTLS/HMAC Server B adapter | Separate gated runtimes; no direct Odoo/n8n DB writes |
| Browser phone session | Existing provisioning-service SIP browser session | Remove staging constants and prove production identity/device binding |
| Reconciliation | Existing middleware worker/checkpoints | Add telephony drift classes and source read-backs |
| Notification | Existing middleware notification worker | Add provider receipts, consent and allowlists |

Forbidden duplicate Odoo model names were not introduced.

EXISTING_MODEL_REUSE_GATE=PASS
