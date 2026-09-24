# FINAL GATE — monitoring + Middleware + OpenBao runtime integration (2026-09-17)

## Verdicts

| Verdict | Value | Basis |
| --- | --- | --- |
| SOURCE_INTEGRATION_GO | **YES** | 16 repositories aligned on isolated branches; all PRs open and mergeable; validators and unit suites pass locally on the exact SHAs (host-only exceptions listed); Keycloak rebased onto its advanced base; runtime wiring tooling (collector, target inventory, identity certifier, TEST_SYN runner, failure-mode suite, rotation matrix) committed and fake-tested |
| OPENBAO_IDENTITY_GO | **NO** (source ready) | contract, roles, policies, Keycloak desired state and the staging certifier are complete and offline-proven, but no live login/denial/revocation run was executed against `bao.codestra.media` |
| LOCAL_RUNTIME_GO | **NO** | Docker/WSL unavailable on this host; no local runtime of the stack was brought up; Windows-only test exclusions apply |
| STAGING_OPENBAO_GO | **NO** | staging OpenBao is `NO_GO_PREPARATION_INCOMPLETE`; init/unseal ceremony outstanding; no health/audit/rotation runtime evidence |
| STAGING_MONITORING_GO | **NO** | no staging deployment of Middleware 0067, Prometheus activation, Alloy/OTel, Loki, Tempo, Grafana; no collector run or reconciliation readback |
| TEST_SYN_GO | **NO** | runner ready and fake-proven; not executed end-to-end |
| PRODUCTION_GO | **NO** | not authorised by this mission; nothing production-facing changed (`production_changed=false`) |

## Section 30 certification matrix

| Component | Source SHA | Runtime | Identity | Secrets | Metrics | Logs | Traces | Alerts | Reconciliation | Dashboard | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Middleware | `30498a30381a` | NOT_DEPLOYED | SOURCE_READY (monitoring_collector role, monitoring-readonly, alertmanager client) | REFERENCES_ONLY (no values; contract pinned) | SOURCE_WIRED (/metrics private, oauth2 monitoring-readonly, 8095) | SOURCE_WIRED (Alloy stage.json + structured metadata) | SOURCE_WIRED (correlation.id contract) | SOURCE_WIRED (Alertmanager ingestion, idempotent) | COLLECTOR_READY (service_state fold) | PROVISIONED_SOURCE (middleware-operations) | BLOCKED_PENDING_EXACT_SHA_CI |
| OpenBao | `b8e2144f9257` | NOT_CERTIFIED (staging NO_GO_PREPARATION_INCOMPLETE) | SOURCE_READY (78 roles; certifier ready) | AUTHORITY (50 refs / 11 identities) | SOURCE_WIRED (sys/metrics pending, mTLS+bearer file) | SOURCE_WIRED (audit → Alloy → Loki, HMAC kept) | N/A | RULES_PINNED (24 + 10) | COLLECTOR_READY (health reader) | PROVISIONED_SOURCE (codestra-openbao, 24 panels) | BLOCKED_PENDING_EXACT_SHA_CI |
| Keycloak | `886ce5e64e12` | NOT_RECONCILED (staging reconciler ready) | ISSUER (per-environment; openbao.workload scope) | N/A (client secrets rendered by OpenBao agent) | SOURCE_WIRED (keycloak:9000 target) | SOURCE_WIRED | N/A | RULES_PINNED | N/A | N/A | BLOCKED_PENDING_EXACT_SHA_CI |
| Prometheus | `1e1089a26860` | NOT_DEPLOYED (staging activation pending) | SOURCE_READY (prometheus-openbao) | REFERENCES_ONLY (file-backed credentials) | SOURCE_WIRED (44-target inventory) | N/A | N/A | RULES_PINNED (18 rules) | COLLECTOR_READY (config/targets/rules digest) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Alertmanager | `d5da15851cfc` | NOT_DEPLOYED | SOURCE_READY (alertmanager) | REFERENCES_ONLY | SOURCE_WIRED (alertmanager:9093 target) | N/A | N/A | ROUTING_PINNED (11 cases) | COLLECTOR_READY (config.original digest) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Alloy/OTel | `f1be1cd3c70d / bf48a9c1c410` | NOT_DEPLOYED | SOURCE_READY (alloy-collector, otel-gateway) | REFERENCES_ONLY | SOURCE_WIRED (otel-collector:8888) | SOURCE_WIRED (redaction before write) | SOURCE_WIRED (gateway mTLS → Tempo) | RULES_PINNED (pipeline alerts) | COLLECTOR_READY (components/health) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Loki | `639f171047ff` | NOT_DEPLOYED | SOURCE_READY (loki-runtime) | REFERENCES_ONLY | SOURCE_WIRED (loki-1:3100 pending) | SOURCE_WIRED (bounded labels) | N/A | RULES_PINNED (openbao-audit rules) | COLLECTOR_READY (/config, labels) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Tempo | `911218affcd3` | NOT_DEPLOYED | SOURCE_READY (tempo-runtime) | REFERENCES_ONLY | SOURCE_WIRED (tempo:3200 pending) | N/A | SOURCE_WIRED (propagation contract; TEST_SYN runner) | RULES_PINNED | COLLECTOR_READY (/status/config) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Grafana | `9c119fe8eca0` | NOT_DEPLOYED | SOURCE_READY (grafana-runtime; middleware-api read scopes) | REFERENCES_ONLY ($__file token) | SOURCE_WIRED (grafana:3000 pending) | N/A | N/A | N/A | COLLECTOR_READY (datasources/dashboards digest) | PROVISIONED_SOURCE (53 dashboards, 5 datasources) | BLOCKED_PENDING_EXACT_SHA_CI |
| Node Exporter | `d054cafe67be` | NOT_DEPLOYED | N/A (no credentials) | N/A | SOURCE_WIRED (×3 hosts) | N/A | N/A | RULES_PINNED | COLLECTOR_READY (sentinel) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| cAdvisor | `f19d0c4e6575` | NOT_DEPLOYED | N/A | N/A | SOURCE_WIRED (×3 hosts) | N/A | N/A | RULES_PINNED | COLLECTOR_READY (sentinel) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Redis Exporter | `fc8ed43d3e14` | NOT_DEPLOYED | SOURCE_READY (redis-exporter) | REFERENCES_ONLY | SOURCE_WIRED | N/A | N/A | RULES_PINNED | COLLECTOR_READY (redis_up) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Postgres Exporter | `992c18266167` | NOT_DEPLOYED | SOURCE_READY (postgres-exporter) | REFERENCES_ONLY | SOURCE_WIRED | N/A | N/A | RULES_PINNED | COLLECTOR_READY (pg_up) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Blackbox | `61450f8030cb` | NOT_DEPLOYED (OpenBao probe pending) | N/A | N/A | SOURCE_WIRED (GET/HEAD/DNS/TCP/TLS only) | N/A | N/A | RULES_PINNED | COLLECTOR_READY (probe_success via Prometheus) | PROVISIONED_SOURCE | BLOCKED_PENDING_EXACT_SHA_CI |
| Superset | `ec9591c094f3` | NOT_DEPLOYED | SOURCE_READY (superset-analytics) | REFERENCES_ONLY | N/A (health probe only) | N/A | N/A | N/A | N/A (boundary validator) | N/A | BLOCKED_PENDING_EXACT_SHA_CI |

Legend: `SOURCE_WIRED` = configuration committed and validated; `COLLECTOR_READY` = a read-only reader exists in `app/monitoring/collector.py` and is unit-proven; `PROVISIONED_SOURCE` = provisioning committed; `REFERENCES_ONLY` = secret references without values; `NOT_DEPLOYED` = no staging runtime evidence.

## Exact-SHA CI rule

GitHub Actions remain locked at the account level ("The job was not started because your account is locked due to a billing issue.", last confirmed 2026-09-17T10:48Z (Middleware run 35212408013 on eeefec60; OpenBao b8e2144f and Prometheus 1e1089a2 startup_failure at 10:38Z/10:42Z)). Per the mission rule, for every repository:

- the blocked exact SHA is recorded (REPOSITORY-SHAS.md; Middleware's final exact SHA is the head that includes this evidence commit, recorded below);
- nothing was merged; no admin bypass, no disabled required check, no weakened branch protection; no CI success was claimed or simulated;
- local validation results are recorded as local only and are **not** transferable to any later commit — a commit after this package invalidates it.

Final status for every repository: **BLOCKED_PENDING_EXACT_SHA_CI**.

## Remaining blockers (ordered)

1. Lift the GitHub Actions billing lock → CI on the exact SHAs → independent review → merge (Middleware #279 after #278).
2. OpenBao staging initialisation/unseal ceremony and `runtimeApplyAuthorized` for staging; then `certify_staging_identity.py` and the rotation matrix.
3. Keycloak staging reconciliation (`reconcile_openbao_workload_identity_staging.py --mode apply`).
4. Staging deployment in the mission order (OpenBao → Keycloak → Middleware → Prometheus → Alertmanager → Alloy/OTel → Loki → Tempo → exporters → Blackbox → Grafana → Superset), Prometheus activation PR, collector run, TEST_SYN run, failure injection — each producing the runtime columns above.

Middleware exact SHA to be CI-tested: the branch head that seals this package — its parent (this package's first commit) is `d6557512f5114885ca130f3e28eaffb4b784a47b`; the sealing commit only fills in this sentence and the README pointer, so the head recorded on PR #279 (`git rev-parse origin/codex/monitoring-openbao-integration-20260916`) is the exact SHA.
