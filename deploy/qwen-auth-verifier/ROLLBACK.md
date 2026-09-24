# Qwen authentication verifier rollback

This candidate is inactive and does not authorize deployment.

For a separately authorized deployment rollback:

1. Remove only the `@qwen_auth_verify` handle added to the private mTLS virtual host.
2. Validate the restored Caddy configuration before reload.
3. Stop and remove only the `qwen-auth-verifier` container.
4. Preserve the replay volume, audit evidence, image digest, SBOM, and scanner reports.
5. Remove no certificate or HMAC secret until the security owner authorizes revocation.
6. Confirm the existing VICIdial matcher remains byte-for-byte unchanged and all write gates remain disabled.

Rollback must not activate another middleware route or fall back to bearer-only authentication.
