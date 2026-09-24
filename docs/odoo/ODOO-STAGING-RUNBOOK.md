# Staging runbook

Use only `TEST_SYN_` records and the dedicated staging tenant. Confirm the reviewed addon mount, healthy Odoo registry, private network DNS, CA validation, and short-lived client-credentials JWT before enabling reads. Run authenticated live/readiness/capabilities probes, then read canaries. Next create one synthetic Odoo outbox event and prove claim/lease/durable middleware intake/ACK with result delivery disabled.

Only after that gate may operators enable `ODOO_RESULT_DELIVERY_ENABLED` and `ODOO_STAGING_WRITES_ENABLED`. `ODOO_PRODUCTION_WRITES_ENABLED` and `LIVE_WRITES_ENABLED` stay false. Validate one allowlisted synthetic result and compare exact before/after records. Disable staging writes immediately after certification.

The approved staging identity is `codestra-middleware-staging`. Its secret is a
root-owned, read-only file mount and Keycloak issues five-minute RS256 JWTs for
audience `codestra-odoo-integration`. The client is limited to the `COD` business
unit and `COD-TEST-OUT` synthetic campaign. Do not copy the secret into an env
file or request a broader scope for canary work.

The 2026-08-08 canary used `TEST_SYN_ODOO_RUNTIME_CANARY_20260808`. Odoo created
one transactional outbox row; the middleware worker claimed, hash-validated,
durably persisted, audited, and acknowledged it. A durable middleware result was
then delivered to Odoo, and an identical replay retained exactly one Odoo result
inbox row. The Odoo outbox ended `delivered/COMPLETED`. Temporary write-gate
overrides existed only on one-shot containers; persisted staging, production,
and live write gates remained closed.
