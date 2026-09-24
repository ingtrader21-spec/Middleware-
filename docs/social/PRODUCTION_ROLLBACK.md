# Production social rollback

Before a live canary, rehearse this sequence:

1. Set `SOCIAL_PRODUCTION_CANARY_ENABLED=false`, `SOCIAL_PUBLISH_ENABLED=false`, and `POSTIZ_PUBLISH_ENABLED=false`.
2. Verify new publish requests are denied.
3. Stop social dispatch if containment requires it; preserve queued and in-flight PostgreSQL rows.
4. Inspect already-scheduled provider-owned jobs individually. Cancel only through the owning provider after reconciling uncertain results.
5. Disable social n8n delivery if it causes downstream side effects; retain IntegrationEvents.
6. Restore the prior exact image/configuration and revoke a compromised canary credential if applicable.
7. Never delete social posts, jobs, attempts, webhook receipts, audit, or provider ownership to perform rollback.

Only a source/configuration rehearsal was possible. No production worker or canary was enabled or disabled during this mission.
