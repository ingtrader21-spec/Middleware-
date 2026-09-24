# Social production canary alerts

Immediately disable `SOCIAL_PRODUCTION_CANARY_ENABLED`, `SOCIAL_PUBLISH_ENABLED`, and `POSTIZ_PUBLISH_ENABLED` for a critical social alert. Stop dispatch only if needed; preserve PostgreSQL jobs, attempts, audit, and provider ownership.

For an unknown result, do not retry, fail over, or recreate the post. Hold the job and reconcile by the stored provider, account, request reference, and content fingerprint. For duplicate or wrong-account risk, suspend the account allowlist and inspect both Codestra and provider state before any cancellation or deletion.

For Redis loss, restore Redis and re-signal from PostgreSQL. For PostgreSQL loss, block all commands and restore the authoritative database before restarting dispatch. An n8n outage must not alter the committed provider result; retain IntegrationEvent delivery for retry. Odoo writes remain off.

Record timestamps, aggregate metric values, Codestra post/job/event UUIDs, provider ownership, and correlation IDs. Never copy content, credentials, tokens, or customer identifiers into alert annotations.
