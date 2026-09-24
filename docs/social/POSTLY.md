# Postly/Postiz

`PostlyProviderAdapter` wraps the existing Postiz public API client. Configure only through runtime secrets (`POSTIZ_API_KEY_FILE`) and private base URL. `POSTIZ_DELIVERY_ENABLED`, `SOCIAL_INTEGRATION_ENABLED`, and `SOCIAL_PUBLISH_ENABLED` remain false until a separately approved staging phase.

Provider webhook requests require timestamped HMAC verification. Phase 1 uses mocks only and publishes zero real posts.
