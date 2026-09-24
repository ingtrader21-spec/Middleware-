# PostgreSQL and Redis credential-rotation plan

This plan is intentionally separate from the private-mTLS source change. No credential is rotated here.

1. Inventory every PostgreSQL and Redis consumer and secret location without printing values.
2. Create protected backups of the affected environment files and database role metadata.
3. Schedule a dedicated maintenance window with database, middleware, Odoo, n8n, and operations owners.
4. Generate new independent credentials through the approved secret-management process.
5. Update server-side credentials and all consumers as one coordinated change, using overlap credentials where supported.
6. Restart only the explicitly approved dependent services and verify authentication, health, queues, and error rates.
7. Revoke the old credentials after every consumer is confirmed healthy.
8. Record secret versions and evidence without recording secret values.
9. Roll back using the protected prior secret versions if any consumer fails validation.
