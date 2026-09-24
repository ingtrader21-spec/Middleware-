# Phase 2 rollback

No staging deployment or network mutation occurred during this run. The rehearsed repository rollback is:

1. keep `SOCIAL_PUBLISH_ENABLED=false`;
2. set social integration, SQL repository, worker, Postiz delivery, n8n events, and Odoo sync/write flags false;
3. stop the staging social worker if introduced;
4. preserve PostgreSQL posts, jobs, attempts, webhook receipts, events, and audit evidence;
5. revert the Phase 2 code commit;
6. downgrade `0034_social_staging` to `0033_social_publishing` only in a disposable or approved staging database;
7. revoke staging-only credentials and restore firewall/routes only if those were changed.

Migration upgrade/downgrade/re-upgrade passed against disposable PostgreSQL. No production route, firewall, secret, provider, or Odoo state requires restoration.
