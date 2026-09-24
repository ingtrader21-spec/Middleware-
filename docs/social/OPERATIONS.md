# Operations

Default configuration:

```dotenv
SOCIAL_INTEGRATION_ENABLED=false
SOCIAL_PUBLISH_ENABLED=false
SOCIAL_PROVIDER=disabled
SOCIAL_PROVIDER_MODE=single
SOCIAL_PROVIDER_MIGRATION_MODE=disabled
POSTIZ_DELIVERY_ENABLED=false
POSTIZ_API_KEY_FILE=
POSTLY_WEBHOOK_SECRET=
HOOTSUITE_ENABLED=false
HOOTSUITE_CLIENT_ID_FILE=
HOOTSUITE_CLIENT_SECRET_FILE=
HOOTSUITE_REDIRECT_URI=
SOCIAL_N8N_EVENTS_ENABLED=false
SOCIAL_ODOO_SYNC_ENABLED=false
SOCIAL_ODOO_WRITE_ENABLED=false
SOCIAL_ANALYTICS_SYNC_ENABLED=false
```

Health reports configuration and enabled/reachable state without probing disabled providers or exposing credentials. Monitor publish totals/duration, provider errors/rate limits, webhook rejection, queue depth, retries and dead letters using provider/network/result only—never account IDs or PII.
