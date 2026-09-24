# Provider migration

## Postly to Hootsuite

Import Hootsuite account mappings as new `SocialAccount` rows, validate capabilities, then change only the default for newly created posts. Historical and scheduled Postly posts retain `provider=postly` and their Postly external references. They continue through Postly or are explicitly cancelled and recreated through an approved operator workflow.

## Hootsuite to Postly

Apply the symmetric process: create Postly mappings, validate, and change the default only for new posts. Hootsuite history and scheduled jobs remain Hootsuite-owned.

The API and Codestra post UUIDs never change. Credentials remain isolated. `SOCIAL_PROVIDER_MIGRATION_MODE` defaults to `disabled`; future `shadow`, `canary`, or `dual-read` modes must never imply dual publishing. Duplicate publish calls require an explicit new operation and idempotency key. Rollback restores the previous default; it never rewrites historical provider ownership.
