# Phase N2 social n8n runtime

Phase N2 connects normalized social events to the existing governed n8n runtime. It does not enable provider publishing or Odoo writes.

## Data flow

Postly is polled read-only at a minimum 60-second interval. `social_poll_checkpoints` and `social_poll_observations` are PostgreSQL-authoritative. An observation, normalized `integration_event`, optional `integration_delivery`, and checkpoint advancement commit in one transaction. The observation uniqueness key is provider, account, provider object, normalized event type, and provider version.

The social delivery worker leases `integration_delivery` records and creates one linked `n8n_runtime_execution`. The existing runtime worker signs the canonical request. The router calls the Middleware authorization endpoint before handling; Middleware verifies HMAC, timestamp, body hash, execution binding, nonce replay, and event deduplication in PostgreSQL. The signed result callback updates both the governed execution and linked delivery.

## Feature flags

All source defaults are off. Infrastructure activation requires `SOCIAL_N8N_EVENTS_ENABLED`, `SOCIAL_N8N_DELIVERY_WORKER_ENABLED`, `N8N_RUNTIME_ENABLED`, and `POSTLY_POLLING_ENABLED`. `SOCIAL_PUBLISH_ENABLED`, `POSTIZ_PUBLISH_ENABLED`, and `SOCIAL_ODOO_WRITE_ENABLED` remain false.

## Postly secret

The approved host secret is mounted read-only as `/run/secrets/postiz_api_key`. Rotation replaces the host file atomically with owner-only permissions, then restarts only the Middleware API and Postly polling worker. Secret values must never be placed in environment variables, Git, workflow JSON, or logs.

## Recovery

Polling failures do not advance the successful checkpoint. Re-observation is safe because the observation key is durable. A worker crash after delivery staging leaves a durable runtime execution; a crash before staging leaves a recoverable lease. HTTP 408, 429, 502, 503, 504, and network failures use the governed bounded retry policy. Authentication, schema, signature, and binding failures fail closed.

## Workflow deployment

Import `CdstSocialHandlersV1.json` and `CdstSocialEventRouterV1.json` inactive. Validate credentials and graphs. Activate safe handlers first and the router last. Comment and message handlers stay inactive until Postly exposes certified read support. Odoo projection is dry-run only.
