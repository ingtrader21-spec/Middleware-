# Middleware integration API runbook

Owner: `codestra-platform`

Confirm `/health/live`, `/health/ready`, `/health/dependencies`, and `/version`. Use the returned correlation ID to inspect the Codestra observability facade. Never copy credentials, connection strings, internal hostnames, or raw tenant payloads into an incident record.

Production changes require a validated provisioning request, independent approval, immutable image digest, SBOM, verified provenance, and a separately authorized deployment operator. The platform API records intent and evidence; it does not directly mutate Caddy, Kong, Keycloak, OpenBao, or telemetry backends.

Rollback uses the provisioning request's reviewed rollback action and the preceding digest-pinned
release. Stop apply workers first, preserve audit evidence, and never roll back by changing a mutable
tag or bypassing the migration compatibility gate.

## Identity and readiness

Every `/platform/v1` route verifies the original RS256 Keycloak bearer using
`KEYCLOAK_ISSUER`, `KEYCLOAK_AUDIENCE`, `KEYCLOAK_JWKS_URL`, and the explicit
`KEYCLOAK_AUTHORIZED_PARTIES` allowlist. These values must come from reviewed
environment configuration; missing configuration returns 503. The shared
Middleware secret and `X-Codestra-Principal` / `X-Codestra-Role` headers grant no
platform authority. Immutable token `sub` identifies the requester and reviewer.

Catalog mutations require `platform_admin` and `platform.services.write`;
reads require `platform.services.read` or `platform.provisioning.read` as
appropriate. Provisioning requests require `platform.provisioning.request`
and an admin/operator role. Validation and approval require their respective
`platform.provisioning.validate` / `platform.provisioning.approve` scopes and
an admin/reviewer role. Apply and rollback require an admin plus their explicit
`platform.provisioning.apply` / `platform.provisioning.rollback` scope. Scope
names are recorded in `permissions.yaml`; no role automatically supplies scopes.
No identity/client, credential, or role binding is created by a source merge.

The integration API always requires PostgreSQL, Redis, and configured reachable
Keycloak signing keys for readiness, even when a legacy optional-database flag is
false. Each dependency failure gives 503 while `/health/live` remains a process
liveness check. Probe output contains statuses, not addresses or credentials.
Run `python scripts/validate_codestra_manifest.py` to validate all seven contract
files before review. A successful manifest or unit test is not live certification.
