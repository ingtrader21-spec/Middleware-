# Security

Social APIs retain middleware bearer authentication and add permission foundations: `social.read`, `social.write`, `social.publish`, `social.schedule`, `social.cancel`, `social.delete`, `social.accounts.read`, `social.accounts.manage`, `social.analytics.read`, and `social.admin`.

Provider keys use secret files. Webhooks use provider HMAC/timestamp checks; controlled machine requests can use `X-Codestra-Timestamp`, `X-Codestra-Nonce`, and `X-Codestra-Signature`. Audit metadata stores an idempotency-key hash, not the key. Errors expose only normalized codes and safe summaries.
