# Approved-order n8n workflows

These seven inactive exports implement the middleware-owned order contract. Every
workflow calls only the middleware command/result/error/reconciliation APIs;
none contains Odoo, VICIdial, Postiz, database, Redis, or arbitrary external
URLs. Import remains disabled until synthetic validation enables the two test
flags for `CODESTRA-INTEGRATION-TEST-` records.

The registry is the allowlist. User-provided text never selects an n8n
workflow. Middleware owns approval, canonical status, idempotency, retries,
dead letters, audit records, and kill switches.
