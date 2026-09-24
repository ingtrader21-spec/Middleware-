# Acceptance

- No published ports or console service.
- Images include immutable tag and digest.
- Bucket bootstrap uses `--with-lock`, enables versioning and governance retention.
- Staging encryption is SSE-S3.
- Production bootstrap fails without an external KMS provider.
- Root credentials are absent from application configuration.
- All deletion and delivery switches remain disabled.
