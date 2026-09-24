# BREERO middleware boundary

Issue: #207. Cross-repository contract: BREERO PR #28 at commit
`f4a89644363dd629b6ad6b22b919f66258353411`.

BREERO submits four typed CRM events to
`POST /api/v1/integrations/breero/events`. Odoo credentials remain exclusively
on middleware. The endpoint does not accept model names, Odoo methods, or
arbitrary routing destinations.

The deterministic routes are:

| Event | Route key | Odoo responsibility |
|---|---|---|
| `breero.service_request.created` | `BREERO_CUSTOMER_REQUESTS` | customer-request CRM pipeline |
| `breero.contact_request.created` | `BREERO_SUPPORT_BUSINESS` | support/business pipeline |
| `breero.provider_interest.created` | `BREERO_PROVIDER_RECRUITMENT` | provider-recruitment pipeline |
| `breero.lead_dispute.created` | `BREERO_LEAD_DISPUTES` | dispute pipeline |

`BREERO_INGRESS_ENABLED=false` and `BREERO_ODOO_DELIVERY_ENABLED=false` are the
deployment defaults. Identity examples are disabled and contain no secrets.
Secrets must be distinct between staging and production, root-owned, mounted
read-only, and absent from environment variables and Compose rendering.
The private listener and identity registry bind BREERO's private VLAN source
`10.40.0.3`; the public address must not be accepted as proxy-supplied identity
evidence.

Activation requires private routing, CA distribution, independent review,
exact-SHA CI, migration backup/restore, authenticated denial tests, four
staging canaries, idempotency/conflict proof, Odoo outage recovery, dead-letter
visibility, and reconciliation with no event loss. Public routing is forbidden.
