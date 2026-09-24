# Odoo SMS integration

Odoo submits native CRM SMS through `POST /v1/communications/messages` using
the dedicated Keycloak machine client `odoo-sms`. Its command scope is
`odoo.sms.command.write`, restricted to the registered `sms.*` namespace targeting
`telnexa-sms`. Status requests require `odoo.sms.status.read`. The verified token
tenant must match `X-Tenant-ID`; original bearer verification remains mandatory.
This registry entry does not create a Keycloak client or grant live delivery.
The HTTP boundary permits this identity only to POST the canonical messages
endpoint and GET its by-idempotency readback. Generic commands, operation
controls, message lists and unrelated channel resources return 403.

The Odoo outbox retains one immutable identity per native SMS. Its request carries
`Idempotency-Key: odoo-sms:<sms-uuid>`, `X-Correlation-ID: <sms-uuid>` and metadata
`odooSmsUuid`. Sender and billing account are operator-configured server values,
not user-supplied provider credentials. Existing verified-sender, consent,
suppression, capability and Telnexa adapter controls apply unchanged.

`GET /v1/communications/messages/by-idempotency` accepts the same Idempotency-Key
and returns the tenant-scoped canonical message or 404. The route precedes the
UUID route. PostgreSQL readback queries the durable idempotency/message join on
every request so different API processes and event workers can be observed.
It does not invoke a provider, submit a command or authorize a resubmission.
It works while SMS delivery is disabled. A missing projection after an uncertain
submission requires reconciliation; it is not evidence that no SMS was sent.

Deploy this API and the companion `codestra_sms_middleware` Odoo addon together
through their reviewed release processes. Provision the tenant-bound Keycloak
service account with audience `middleware-api`, short-lived tokens and both
scopes, then configure the private HTTPS route/CA, approved sender/billing mapping,
and Telnexa credentials in their respective services. Do not reuse a human token
or the existing Odoo callback client. The legacy SMS API on Server 65 is a
different application and cannot substitute for these canonical endpoints.

The initial verification uses fake transports only: one command despite repeated
readbacks, cross-tenant/scope rejection, denied email writes, durable-store lookup,
delivery-disabled readback, and the existing Telnexa no-second-POST suite.
Production SMS activation and carrier delivery require separate runtime evidence.
