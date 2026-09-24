# Phase 4 acceptance

## Source-certified controls

- production canary, account/tenant/campaign allowlists, backup/rollback/webhook/monitoring gates, and defaults-off validation;
- one-account provider-ownership enforcement and worker-time revalidation;
- side-effect-free dry-run with durable audit evidence;
- no automatic failover or dual publishing;
- production metrics, alert rules, rollback, and incident runbooks;
- PostgreSQL migration and automated policy/security regression tests.

## Blocking conditions

Phase 2 lacks authenticated staging certification, Phase 3 is incomplete, and no `PRODUCTION_APPROVED_CANARY` account, human-approved content, production backup restore evidence, protected provider credential, signed webhook round-trip, or approved n8n production path was available. No live production canary is authorized.

The correct status is `PARTIAL_BLOCKED_APPROVED_PRODUCTION_SOCIAL_ACCOUNT`, subject also to the remaining staging, credential, backup, webhook, and n8n gates. Production social posts and Odoo writes remain zero.
