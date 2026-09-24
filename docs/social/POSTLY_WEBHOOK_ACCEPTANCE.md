# Postly webhook acceptance

The ingress requires timestamped HMAC verification before JSON parsing and normalization. Invalid, missing, expired, future, or body-mismatched signatures fail closed. Known events are mapped to canonical social events and only allowlisted fields persist.

`SqlSocialRepository.persist_webhook()` enforces `(provider, provider_event_id)` uniqueness and creates the normalized provider event plus existing middleware IntegrationEvent record in the same transaction. n8n delivery is created only when its staging flag is enabled. Real webhook round-trip remains blocked by Postly server access.
