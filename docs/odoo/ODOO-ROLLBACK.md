# Rollback

1. Set `ODOO_STAGING_WRITES_ENABLED=false` and `ODOO_RESULT_DELIVERY_ENABLED=false`.
2. Stop the result worker, then the sync worker; preserve their databases and queues.
3. Restore the prior middleware image digest.
4. Restore the Odoo staging addon mount from `/root/codestra-ai-platform-source-20260801T210000Z/codestra-odoo-addons` to `/root/odoo19-upgrade` and recreate only the staging Odoo service.
5. Verify Odoo health and leave pending Odoo/middleware outbox rows untouched.
6. Repair the cause, restore the reviewed source/image, and resume from durable pending/retry state.

Never delete integration events or results to make rollback appear successful.
