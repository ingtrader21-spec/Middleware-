# OpenBao policies (2026-09-17)

Source authority: `Codestra-OpenBao/config/workload-secret-authority.v1.json` (canonical sha256 `0dd53c17b1668bb0488c579cb5d128d64c185ee8923d9b2a9712485609d214bd`, generated from `config/policies/workload-identities.v1.json`; vendored byte-for-byte in Keycloak with a sha256 pin).

## Namespace and prefixes

- Namespace: `codestra/<environment>/<service>/...` on the KV v2 mount `codestra`; environments `development|test|staging|production`.
- Each policy grants `read` on its own exact prefixes only (78 policies in `openbao/policies/<environment>/<identity>.hcl`, index `config/policies/generated-policy-index.v1.json`). Examples: `prometheus-openbao` → `codestra/<env>/observability/openbao/metrics-client/` and `codestra/<env>/observability/prometheus/scrape-credentials/`; `grafana-runtime` → `observability/grafana/`; `superset-analytics` → `analytics/superset/`.
- **No wildcard global secret-reader role exists**; `validate_workload_secret_authority.py` rejects `*` in prefixes and any non-production environment trusting the production issuer (`PLAINTEXT_SECRET_INJECTION=DISALLOWED`, `PROVIDER_BUSINESS_EFFECTS_ENABLED=NO`, `SECRET_VALUES_IN_CATALOG=NONE`).

## Negative tests (explicit)

| Case | Source test | Runtime certifier check |
| --- | --- | --- |
| staging → production path | `tests/security/test_monitoring_identities.py` (prefix disjointness), CEL environment claim | cross-environment-denied (403) |
| service A → service B path | same | cross-service-denied (403) |
| foreign issuer | `EXPECTED_ISSUERS`, mount bound issuer per environment | tampered-issuer-rejected |
| wrong audience / wrong azp | generated role `bound_audiences=[openbao]`, CEL `claims.azp` | wrong-audience-rejected, wrong-role-rejected |
| expired / tampered / replayed jti | CEL lifetime bound, plugin `codestra-jwt-replay` (integration_test_jti_plugin.sh) | tampered-signature-rejected, expired-jwt-rejected (optional) |
| monitoring-readonly | Keycloak never-bound list; no OpenBao role | monitoring-readonly-never-bound (optional) |
| admin surface | policies grant no `sys/*` | admin-mutation-unauthorized, admin-with-workload-token |

Validation on the branch: `validate_workload_secret_authority.py` PASS, `validate_secret_references.py` `SECRET_REFERENCE_CONTRACT=PASS references=50 identities=11`, unit/policy/integration/recovery/runtime suites OK (security suite: 13 Windows-only errors — backslash paths in the release manifest and non-Win32 shell scripts — identical on the base; CI is authoritative).
