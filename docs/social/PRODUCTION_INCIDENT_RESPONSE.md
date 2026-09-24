# Production social incident response

- **Duplicate post:** disable canary and dispatch, preserve evidence, reconcile both provider and Codestra IDs, and remove content only with account-owner approval.
- **Wrong account/network or accidental content:** disable the account allowlist, stop pending jobs, notify the content/account owner, and use the owning provider's approved correction workflow.
- **Provider outage/auth expiry/account disconnect:** block dispatch, alert, repair the same provider/account, and never fail over automatically.
- **Queue backlog/worker crash:** keep PostgreSQL authoritative, restore the worker, recover leases, and re-signal only known-safe jobs.
- **Webhook failure:** keep signature enforcement, reconcile by polling where supported, and do not accept unsigned callbacks.
- **n8n outage:** retain committed IntegrationEvents and retry delivery without repeating the provider operation.
- **Unknown result:** hold the job, alert an operator, and reconcile by provider request/reference and post status. Never blind retry.
- **Credential leak:** disable canary, revoke/rotate the affected credential, inspect audit and provider activity, and preserve evidence.

Odoo production writes remain off during every incident path.
