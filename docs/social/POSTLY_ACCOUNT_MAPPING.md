# Postly staging account mapping

Account discovery must call the deployed Postly/Postiz integrations endpoint through `PostlyProviderAdapter.list_accounts()`. Each result maps to a Codestra `social_accounts.id` UUID and retains its provider account ID only as an external reference.

Every discovered account requires an explicit classification: `STAGING_SAFE`, `PRODUCTION`, or `UNKNOWN`. Only `STAGING_SAFE` may be considered for controlled tests. The sanitized Postly inventory reported zero configured accounts, so controlled publishing is blocked and no OAuth token or account metadata was copied.
