# Lead Automation V1 rollback

This remediation is source-only and leaves production deployment and activation blocked.

For an authorized future rollback, first disable the Odoo apply, result processing, n8n lead binding, action-specific and global lead-automation switches. Stop only the lead dispatcher and reconciliation worker after in-flight calls have reached a bounded outcome. Do not delete or rewrite events, canonical request hashes, idempotency keys, attempts, acknowledgements, quarantine records, reconciliation results, or audit evidence.

Restore the previously approved application and contract artifacts together; request and acknowledgement schemas must not be rolled back independently of their client. Migration `0028_lead_automation_platform_v1` may be downgraded only in a non-production validation environment, or later under separate owner-approved production authority after a verified backup and confirmation of zero business rows. Re-upgrade and run schema/manifest, migration, replay, security and reconciliation gates before considering reactivation.

HMAC-V2 version, exact scope, method, and canonical-path binding form one atomic contract for both the n8n result callback and Middleware-to-Odoo apply delivery. A rollback must restore signers, verifiers, vectors, and documentation together while all lead-automation delivery gates remain disabled. HMAC-V1 acceptance must not be enabled as a rollback mechanism.

Rollback does not authorize direct database writes, Odoo/n8n bypasses, communication sends, deployment, merge, lead processing, telephony, media, or Server B access.
