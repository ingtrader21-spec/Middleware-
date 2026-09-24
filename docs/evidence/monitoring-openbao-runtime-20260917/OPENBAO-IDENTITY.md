# OpenBao identity (2026-09-17)

## Endpoint and listeners

- Public name: `https://bao.codestra.media` (Caddy edge, TLS on 443). Reachable from the public internet in this session: HTTP 403 on `/` (edge policy), which is the expected posture for an unauthenticated browser.
- Native listeners 8200 (API) and 8201 (cluster) must not be reachable on the public name. `scripts/certify_staging_identity.py --check private-listeners` asserts a successful TLS handshake on 443 and refused/timed-out TCP on 8200/8201 (recorded as booleans only).
- Nothing in this package or in any repository exposes: root token, unseal/recovery material, provider credentials, private keys, database passwords or raw OpenBao tokens. `scripts/reject_repository_secrets.sh` passes on the OpenBao branch (`SCAN_OK`); see SECRET-LEAK-SCAN.md.

## Keycloak → OpenBao audience/role contract (OpenBao-specific; `middleware-api` audience untouched)

| Item | Value |
| --- | --- |
| Issuer (staging) | `https://auth-staging.codestra.co/realms/codestra` |
| Issuer (production) | `https://auth.codestra.co/realms/codestra` (never trusted by a non-production mount) |
| Grant | `client_credentials` + `scope=openbao.workload` |
| Audience | `openbao` (optional client scope `openbao.workload`, access-token mapper only) |
| Required claims | `iss sub aud azp iat exp jti codestra_environment`; `exp - iat <= 300` |
| Mount / login | `auth/jwt-codestra/cel/login` `{role, jwt}` — role `<clientId>-<environment>` |
| Policy | exactly `workload-<clientId>-<environment>`; TTL 300 s, max TTL 300 s, renewable |
| Environment binding | CEL requires `claims.codestra_environment == '<environment>'`; the staging Keycloak instance renders the placeholder to `staging`, so it cannot mint a production claim |
| Replay | `codestra-jwt-replay` plugin rejects re-used `jti` |

Roles: 78 generated (26 identities × staging/production, plus development/test for the 13 legacy identities). Monitoring-plane identities admitted: `prometheus-openbao`, `grafana-runtime`, `alertmanager`, `alloy-collector`, `otel-gateway`, `loki-runtime`, `tempo-runtime`, `redis-exporter`, `postgres-exporter`, `superset-analytics`.

## Staging identity certifier — `scripts/certify_staging_identity.py` (OpenBao @ `b8e2144f9257`)

Required checks (all must pass, none may be skipped, for `STAGING_OPENBAO_IDENTITY_GO=YES`):

| Check | Proves | Expected |
| --- | --- | --- |
| authority-role | identity is one reviewed staging role; probe path under its exact prefixes; generated role binds `openbao` audience, staging issuer and environment | pass |
| private-listeners | TLS on 443; 8200/8201 unreachable | pass |
| health-unauthenticated | `GET /v1/sys/health` answers without credentials; initialized; **sealed state is recorded, never changed** | pass |
| admin-mutation-unauthorized | `PUT sys/seal`, policy write, `sys/audit`, policy list without a token | all non-2xx |
| keycloak-token | claims `iss/aud/azp/codestra_environment/jti`, lifetime ≤ 300 s (jti/sub recorded as sha256 prefixes) | pass |
| login-own-role | exactly `workload-<identity>-staging`, TTL ≤ 300 s | pass |
| own-path-read | own prefix authorised (200 or 404, never 403; value never recorded) | pass |
| cross-environment-denied | same path under `codestra/production/` | 403 |
| cross-service-denied | a disjoint staging identity's prefix | 403 |
| admin-with-workload-token | `sys/policies`, `sys/audit`, `sys/seal` with the workload token | 403 |
| wrong-audience-rejected | token minted without `scope=openbao.workload` carries no `openbao` audience and cannot log in | ≥ 400 |
| wrong-role-rejected | own token as another identity's role | ≥ 400 |
| tampered-signature-rejected | modified signature | ≥ 400 |
| tampered-issuer-rejected | `iss` rewritten to the production issuer (a genuine production token cannot be minted from staging by design) | ≥ 400 |
| token-revocation | `auth/token/revoke-self`, then own-path read | 204 then 403 |

Optional: `expired-jwt-rejected` (`OPENBAO_IDENTITY_WAIT_FOR_EXPIRY=true`, waits ≤ 335 s), `monitoring-readonly-never-bound` (`MONITORING_READONLY_CLIENT_SECRET_FILE`; Keycloak refuses the scope or the token lacks the audience, and no `monitoring-readonly-staging` role exists).

Fail-closed properties (unit-proven, `tests/security/test_staging_identity_certifier.py`, 13 tests): staging only; https only; secret files absolute and non-symlink (0600 outside Windows); no request is sent when inputs are unsafe; a sealed OpenBao stops the run before any Keycloak token is minted and never triggers `sys/unseal`; an open admin surface, readable production path, readable other-service prefix, accepted wrong audience or reachable native listener each fail the run; evidence containing a credential, JWT or secret-shaped string is refused (exit 3).

**Runtime execution: not performed.** No staging client secret or host access was available to this session and staging is `NO_GO_PREPARATION_INCOMPLETE` per the OpenBao operations authority; `OPENBAO_IDENTITY_GO` therefore stays at source readiness (see FINAL-GATE.md).
