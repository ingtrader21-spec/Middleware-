# 07 — Identity

## One identity source

`Settings.identity` → `IdentitySettings(issuer, audience, jwks_url, authorized_parties, jwks_timeout_seconds,
explicit, max_token_lifetime_seconds=300, algorithms=("RS256",))`. `issuer`/`jwks_url` always carry a value
(the environment's canonical authority when nothing was configured); `explicit` is true only when
`KEYCLOAK_ISSUER`, `KEYCLOAK_AUDIENCE` and `KEYCLOAK_JWKS_URL` were all set.

## Two verifiers, one source, one policy

| Verifier | Used by | Claims | Failure semantics |
| --- | --- | --- | --- |
| `app.security.KeycloakJwtVerifier` (async, cached JWKS, readiness) | control plane (`RuntimeContainer.tokens`), signed webhook ingress, calling contract | RS256; `exp`, `iat`, `iss`, `sub`, `aud`, `azp`, `jti`, `scope` required; `azp` = expected client; scope present; lifetime ≤ 300 s; wildcard tenant rejected | `AuthenticationError` 401 (missing/invalid token), `AuthorizationError` 403 (valid token, wrong azp/scope/tenant) |
| `app.core.jwt_auth.KeycloakValidator` (sync) | integration routes; built with `identity_validator_kwargs(settings.identity, …)` / `from_identity` | RS256; `exp`, `iat`, `iss`, `aud`; `azp` ∈ authorized parties; roles/scopes/environment/business-unit/campaign requirements | `JWTAuthError`; `app/api/v1/integrations.py::_jwt_error_status` maps permission denials to 403, identity failures to 401; implicit identity → "not configured" (401/503 as before) |

Per-integration identities (n8n service issuer, callback JWT, sales scraper JWT, registry service) keep their
own explicitly configured issuer/audience/JWKS — they are different trust relationships, not copies of the
Middleware identity.

## Environment pinning

- `_authenticate_n8n`, `_authenticate_odoo` (integrations): `required_environment=settings.environment`.
- `POST /api/v1/automation/policy-check`: now `settings.environment` (was `"production"` — the Mission-1 gap
  analysis item; staging n8n tokens were rejected in staging).
- `n8n_transport` results ingress: still `production` + `BU-400-COD` + `CMP-400-COD` (the controlled
  broad-event activation contract; unchanged on purpose).

## Readiness probing of the authority

`identity_probe_required(settings)`: staging/production always; development/test only when explicit. A local
process never treats the production Keycloak as its dependency; the CI `app.main:app` startup step (implicit
identity) reports `identity_jwks: not_configured` and stays ready; the certified failure-mode matrix uses an
explicit synthetic identity and therefore probes it (JWKS outage → 503).

Tests: `tests/test_core_config_authority.py::test_identity_is_derived_but_marked_implicit_until_configured`,
`::test_integration_validators_refuse_an_implicit_identity`, `::test_wildcard_tenant_and_missing_authority_are_rejected_by_the_verifier`,
`tests/test_security.py` (claims/lifetime/azp), `tests/test_odoo_campaign_adapter_routes.py`
(explicit identity required, dedicated reader clients, 401/403 split), `tests/test_integration_api_entrypoint_routes.py`
(38: expired/tampered/wrong issuer/wrong audience/wrong environment/wrong scope/cross-tenant),
`tests/test_campaign_policy_auth.py`, `tests/test_webphone.py`,
`tests/test_architecture_governance.py::test_jwks_clients_are_created_only_by_the_identity_verifiers`,
`::test_canonical_identity_is_consumed_through_identity_settings`, `::test_security_module_keeps_machine_token_policy`.
