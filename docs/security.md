# Security controls

Requests require `Idempotency-Key`, `X-Client-Instance-ID`, `X-Timestamp`, and an HMAC-SHA256 `X-Signature`. Signatures cover `timestamp + '.' + raw_body` and expire after the configured window. Policy rejects every campaign except `TEST_SYN`. Secrets are read from environment only and are never logged.
