# PR #68 staging candidate workflow control

This change introduces the protected-main identity needed to build and later sign an immutable PR #68 staging candidate. It does not merge PR #68 or authorize staging, canary, database, Server B, or production operations.

The `build` operation verifies the live PR head, checks out that exact SHA, publishes only a SHA-derived candidate tag, records the manifest digest, and emits digest-bound CycloneDX, Trivy, Grype, and provenance evidence. It has no OIDC permission.

The `sign` operation is separately protected by the `security-owner-staging-candidate` environment. It requires exact run-scoped evidence and a completed Security Owner decision bound to the candidate digest, source SHA, evidence hash, staging-only scope, and finite validity window. Only this job receives `id-token: write`.

The exact certificate identity is:

`https://github.com/Codestra-SRL/codestra-middleware/.github/workflows/staging-candidate-build-sign.yml@refs/heads/main`

Production deployment, activation, canary execution, customer data, and Server B access remain blocked.
