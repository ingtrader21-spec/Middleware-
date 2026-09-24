# Marketing Integration Runtime Contract

## Purpose
Middleware is the durable transport and provider-integration boundary for the Codestra marketing platform.

## Canonical inbound events
- marketing.lead.received.v1
- marketing.provider.webhook.received.v1
- social.engagement.received.v1
- communication.delivery.updated.v1

## Canonical outbound commands
- crm.lead.upsert.v1
- communication.message.requested.v1
- social.post.dispatch.requested.v1
- marketing.provider.operation.requested.v1

## Required envelope
Every command/event carries event_id, event_type, schema_version, occurred_at, tenant_id, correlation_id, causation_id, idempotency_key, source, and payload.

## Safety
LIVE_ADVERTISING_WRITES=false
LIVE_SOCIAL_PUBLISHING=false
LIVE_EXTERNAL_DELIVERY=false

Provider webhooks must be authenticated/verified before normalization. Commands must be idempotent. Durable outbox/inbox handling and bounded retry are required. No business approval decision belongs in middleware.
