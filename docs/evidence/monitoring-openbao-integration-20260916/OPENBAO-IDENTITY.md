# Keycloak -> OpenBao workload identity (2026-09-16)

## Flow

Service (`azp` = Keycloak clientId) -> `client_credentials` with `scope=openbao.workload` -> Keycloak issues an access token with `aud` containing `openbao`, `codestra_environment` (rendered per environment), `jti`, `exp-iat <= 300` -> OpenBao `jwt-codestra` mount (`plugins/codestra-jwt-replay`, `jti` replay cache) -> CEL role `<identity>-<environment>` -> policy `workload-<identity>-<environment>` -> 300 s renewable token.

## Keycloak side (`Keycloak` `3daa1fa4`, PR #119)

- Optional client scope `openbao.workload`: mappers `audience-openbao` (access token only) and `claim-codestra-environment` with placeholder `${CODESTRA_ENVIRONMENT}` rendered by the staging reconciler to `staging`; never a realm default, never on a browser client, never on `monitoring-readonly`.
- Nine new confidential clients: `prometheus-openbao`, `grafana-runtime`, `alloy-collector`, `otel-gateway`, `loki-runtime`, `tempo-runtime`, `redis-exporter`, `postgres-exporter`, `superset-analytics` (service accounts only, no flows, `fullScopeAllowed=false`, 300 s, default `basic`, optional `openbao.workload`). `grafana-runtime` alone also carries the `middleware-api` audience with read-only scopes.
- Existing managed clients bound by optional-scope link: `alertmanager`, `kong-gateway`, `middleware-api`, `middleware-worker`, `n8n-automation`, `odoo-integration`, `vicidial-adapter`.
- Validator `openbao_workload_identity_desired_state.py --check --require-cross-check` against the OpenBao head: `OPENBAO_AUTHORITY_CROSS_CHECK=PASS`, authority sha256 `0dd53c17b1668bb0488c579cb5d128d64c185ee8923d9b2a9712485609d214bd`.
- Unresolved (Keycloak clientId != OpenBao identity; owned by the application repositories): `beyvra-api`, `beyvra-funding`, `beyvra-market-data`, `beyvra-trading-executor`, `breero-api`, `larimia-api`, `moneybee-api`, `crawler-adapter`, `klyrow-email-adapter`, `telnexa-sms-adapter`.

## OpenBao side (`Codestra-OpenBao` `28f009c6`, PR #78)

- Per-environment issuer: `mountConfigurationByEnvironment` — production `https://auth.codestra.co/realms/codestra`, staging/development/test `https://auth-staging.codestra.co/realms/codestra`; every CEL program binds its environment's issuer (`tests/security/test_monitoring_identities.py::test_every_role_binds_its_own_environment_issuer`, `::test_only_the_production_mount_trusts_the_production_issuer`).
- Rejections proven by the CEL programs: foreign issuer, wrong audience, wrong `azp`, wrong `codestra_environment`, missing `sub`/`jti`, expired, lifetime > 300 s, tampered (RS256 only); staging tokens cannot read `codestra/production/*` (policy deny) and cannot satisfy a production role (claim mismatch).

## monitoring-readonly

`client_id: monitoring-readonly`, optional scopes exactly `health.read` and `metrics.read`, audience `middleware-api`, no `openbao.workload`, no secret-reading or provider-write scope (`tests/test_openbao_workload_identity.py::test_monitoring_readonly_never_gets_a_secret_reading_scope`). Prometheus uses it for `codestra-middleware-metrics` with `scopes: [metrics.read]`.

## Runtime status

No token was minted and no live Keycloak or OpenBao was touched. `OPENBAO_IDENTITY_GO=NO` until the staging reconciler (`reconcile_openbao_workload_identity_staging.py --mode apply`) and OpenBao `scripts/verify.sh` produce positive and negative read evidence with staging tokens.
