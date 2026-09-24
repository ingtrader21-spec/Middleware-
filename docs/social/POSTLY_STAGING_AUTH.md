# Postly staging authentication

The deployed runtime authenticates its public API with organization API keys or
organization OAuth tokens. It has no scoped service-token model: public API access is
treated as organization superadmin. The existing organization has zero connected
accounts, and its API key is installed only in the Middleware staging secret directory
as `postiz_api_key`, mode `0400`, UID/GID 10001.

Real validation returned `200` for the installed credential and `401` for invalid and
missing credentials. Middleware health and authenticated discovery pass. Native
outward webhook delivery remains unsigned and therefore does not satisfy Middleware
ingress verification.

Staging must use a dedicated `postly-social-01` identity. Store API and webhook secrets in root-owned runtime files such as `/run/secrets/...`; never commit values or place them in repository `.env` files. Prefer private mTLS plus the provider-supported API key, with timestamp/nonce/HMAC protection where Codestra controls both endpoints.

No public post or provider mutation was made. Write canaries remain blocked until a
positively classified staging-safe account and signed outbound event mechanism exist.
