# Production canary

Source defaults keep production mode and canary publishing off. A future operator must explicitly set narrow staging-reviewed overrides, including one account UUID and, where used, tenant and campaign UUIDs. The selected `SocialPost.provider` and account provider must match.

Call `POST /api/v1/social/posts/{post_id}/publish?dry_run=true` with `Idempotency-Key`, `X-Codestra-Permissions: social.publish`, and `X-Social-Content-Approved: true`. A passing response records `PRODUCTION_DRY_RUN_VALIDATED` but creates no publish job and performs no provider call.

The first live request may proceed only after staging certification, approved account inventory, protected credentials, verified backups/restoration, rollback rehearsal, signed webhook round-trip, production n8n delivery acceptance, and human-approved content. It must target one account, one provider, and one network. Schedule first where the deployed provider contract has been validated.
