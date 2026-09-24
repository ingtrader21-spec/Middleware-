# Source and staging rollback

1. Keep the workflow inactive.
2. Disable the `n8n.leads.ingest` binding.
3. When separately authorized, remove only the imported staging workflow corresponding to this source artifact.
4. Preserve Middleware events, results, quarantine entries, reconciliation evidence, and audit records.
5. Remove no production lead data and create no compensating CRM mutation.
6. Revoke the staging callback credential when required without exposing its value.
7. Do not alter unrelated workflows, credentials, bindings, or n8n instance configuration.

Source rollback is a normal revert of the dedicated workflow-source commit. It does not change Middleware migrations, Odoo modules, recording services, Asterisk, VICIdial, or Server B.
