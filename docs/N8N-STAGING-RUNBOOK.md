# n8n staging runbook

1. Verify exact middleware SHA/image digest and migration head.
2. Confirm every production/write/outreach flag remains false.
3. Confirm staging n8n is 2.30.8 in queue mode with two workers at concurrency
   five, PostgreSQL persistence, and authenticated private Redis 7.4.5.
4. Import `deploy/n8n/runtime/TEST_SYN_RUNTIME_V1.json`, bind its Crypto node to
   the encrypted `Codestra Runtime HMAC` credential, and register only the
   explicit `TEST_SYN_TENANT` mapping. Disable it after certification.
5. Apply migration, deploy the exact image to staging only, and verify health.
6. Run dispatch, signed callback, ten-request duplicate, replay, restart, and
   concurrency tests at 1/5/10/25.
7. For an Odoo-bound canary, enable `TEST_SYN_ODOO_RESULT_DELIVERY_ENABLED`
   only on the API and result worker and configure every exact binding:
   tenant, workflow/version, event type/ID, correlation ID, organization,
   business unit, campaign, and originating Odoo outbox ID. Keep
   `ODOO_RESULT_DELIVERY_ENABLED`, `ODOO_WRITE_ENABLED`, and
   `LIVE_WRITES_ENABLED` false. The worker emits only the fixed synthetic
   result-inbox payload; n8n cannot supply a model, record ID, or field name.
8. Confirm one logical Odoo inbox result, a 200 idempotent replay, retained
   delivery during a bounded Odoo outage, and successful delivery after worker
   restart.
9. Disable the workflow and registry row, stop/remove the synthetic result
   worker, and confirm all unrestricted write flags remain false.
10. Observe n8n/Redis metrics and retain the PostgreSQL/audit identifiers.

Workflow inventory at discovery: 236 total, 0 active, 236 inactive. Without a
signed governance inventory, inactive workflows remain `UNKNOWN` except
explicitly approved synthetic fixtures; nothing is deleted or activated.
