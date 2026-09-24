# Final gate — monitoring / OpenBao integration (2026-09-16)

## Verdicts

| Verdict | Value | Basis |
| --- | --- | --- |
| `SOURCE_INTEGRATION_GO` | **YES** | every mission-relevant source validator and unit/contract test passes at the recorded heads in all 16 repositories; identical contract digests vendored; no secret finding; the only failures are documented host-environment artefacts (Windows CRLF checksum readers, `openssl`/symlink/`os.geteuid`, missing deployment image variables) that reproduce identically on the base branches |
| `OPENBAO_IDENTITY_GO` | **NO** | the identity model is complete and cross-checked in source (Keycloak <-> OpenBao authority PASS), but no staging token was minted and no positive/negative OpenBao read was executed |
| `LOCAL_RUNTIME_GO` | **NO** | the Docker Linux engine on the certifying host cannot start (no WSL distribution); no isolated stack, PostgreSQL, Redis, OpenBao dev server or collector runtime could be started |
| `STAGING_MONITORING_GO` | **NO** | no staging Middleware/Keycloak/OpenBao/Prometheus/Loki/Tempo/Alertmanager/Grafana access from this session; TEST-SYN.md not executed |
| `STAGING_OPENBAO_GO` | **NO** | Section 27 runtime rows not performed |
| `PRODUCTION_GO` | **NO** | never authorized by this mission; every `runtimeApplyAuthorized`, `productionActivation`, `activation.*` gate stays false |

## Static certification — commands and exit codes

Executed on the certifying host (Windows 10, Python 3.12) at the heads in REPOSITORY-MATRIX.md. `rc=0` unless noted.

| Repository | Checks |
| --- | --- |
| Codestra-OpenBao | `validate_repository.py`, `validate_codestra_enterprise_profile.py`, `validate_codestra_openbao.py`, `validate_codestra_openbao_oidc.py`, `validate_codestra_review_boundaries.py`, `validate_workload_secret_authority.py`, `validate_secret_references.py`, `validate_orbit_adoption.py`; JSON validation (33 files); unittest `tests/policy`, `tests/unit` (+10), `tests/integration`, `tests/recovery`, `tests/runtime` OK; `tests/security` (+8) OK except 4 pre-existing Windows-only (openssl, backslash paths); top-level `tests` 13 pre-existing `WinError 193`; `reject_repository_secrets.sh` clean; `git diff --check` clean. `validate_hcl.sh` and compose render need Docker (CI). |
| Keycloak | `openbao_workload_identity_desired_state.py --check --require-cross-check` PASS; `tests/test_openbao_workload_identity.py` 20/20; every `validate.sh` step PASS individually (backup-contract step needs `age`/`pg_restore`; `observability_desired_state.py --check` shows the same Windows path-separator staleness as `origin/main`); pytest failure set identical to the base branch (5 Windows-only). |
| Middleware- | `tests/test_platform_catalog_monitoring.py` 19, `tests/test_secret_reference_contract.py` 13, `tests/test_monitoring_component_states.py` 3, `tests/test_secret_file_fail_closed.py` 5, `tests/test_platform_verified_authority.py` 66, `tests/test_integrated_monitoring.py` 30/31 (1 pre-existing Windows symlink); full suite 3069 passed, failures = prior certified baseline + `test_vicidial_mtls_client.py` (openssl subprocess, identical on the base worktree today); `audit_release_endpoints`, `validate_repository_governance`, staging observability, automation conformance, identity webhook contracts, authority assets/convergence, `validate_secret_reference_contract --require-cross-check`, `generate_api_contracts --check`, integrated-monitoring OpenAPI check all PASS; ruff clean, mypy clean on new modules; migration digest pinned from index blobs and verified against HEAD (`b476993b…`). |
| Codestra-Prometheus | `validate.py` PASS; pytest 20/20; `promtool 3.14.0 check rules` SUCCESS (10 files); `check config --syntax-only` SUCCESS. |
| Codestra-Alertmanager | `validate_codestra_alertmanager.py` PASS; `amtool 0.34.0 check-config` SUCCESS; Stage 6 routing PASS; security PASS; manifest verified against index blobs. |
| Codestra-Telemetry | `validate_codestra_telemetry.py` PASS (+negative controls); `validate_collector_image_readiness.py` PASS; pytest 53/53; `otelcol-contrib 0.159.0 validate` exit 0 for both profiles. |
| Codestra-Alloy | three Alloy validators + enterprise profile + intake + readiness PASS; pytest 6/6; native `alloy` check CI-only. |
| Codestra-Loki | `validate_codestra_loki_platform.py --require-cross-check` PASS; enterprise profile and sensitive-values PASS; tests 6/6 (readiness CRLF mismatch Windows-only). |
| Codestra-Tempo | all five validators PASS (enterprise profile repaired); `--require-cross-check --telemetry-repo` PASS; tests 9/9. |
| Redis/Postgres/Blackbox/Node/cAdvisor | `validate_monitoring_platform.py` PASS each; unittest OK each; existing enterprise/corporate validators PASS (readiness CRLF and image-variable validators host-only; cAdvisor proxy-test finding pre-existing on `development`). |
| Codestra-Grafana- | `validate_codestra_observability.py` PASS (53 dashboards regenerated; negative controls rejected). |
| Superset | boundary validator PASS (+negative control); tests 4/4; seven existing validators PASS (`validate_runtime_identity.py` needs release image variables). |

## Blockers

| Blocker | Reproduction | Needed |
| --- | --- | --- |
| GitHub Actions cannot start any job for the repository owner (billing lock; every run on the new branches is `startup_failure`, last checked 2026-09-17T02:52Z) | `gh run list -R appolon1908-hue/<repo> --branch codex/monitoring-openbao-integration-20260916` | resolve the account lock, then re-trigger (push or close/reopen) so exact-SHA CI produces the Linux evidence this package cannot substitute for; no PR may merge before it is green |
| Local runtime | `docker info` -> HTTP 500; `wsl -l -v` -> no distribution | install WSL 2 / Docker Linux engine, then the isolated stacks (`Codestra-OpenBao scripts/integration_test.sh`, Middleware disposable-DB suites, compose candidates) |
| Staging access | none of the staging endpoints, secret-file references, TEST_SYN seeds or restart authority were available | staging DNS, OpenBao agent bootstrap for the collectors, Keycloak protected reconciler credentials, log/dashboard access |
| Application trace hops | Caddy, Kong, Middleware, Odoo and N8N instrumentation is declared `planned` in the Tempo contract | per-repository OTel instrumentation PRs |
| Business-application OpenBao identities | 10 OpenBao identities have no Keycloak client of the same id | owning repositories register clients or rename identities |
| Stacked pull requests | Keycloak #119 and the Middleware PR are stacked on the unmerged #118 / #278 branches | merge the cross-repo-authority set first, then retarget |

All live-write switches remain false; no deploy, reload, token, secret write or provider effect was performed.

## Monitoring certification matrix (Section 28)

Source = static validation at the recorded head; Identity = Keycloak client/role declared; OpenBao = secret references declared and cross-checked; Runtime/Metrics/Logs/Traces/Alerts/Dashboard = live evidence (none obtained in this mission).

| Component | Source | Identity | OpenBao | Runtime | Metrics | Logs | Traces | Alerts | Dashboard | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Middleware | PASS | `middleware-api`, `monitoring-readonly` scrape | 6 refs (`middleware-api`) | NOT_PROVEN | NOT_PROVEN (job defined) | NOT_PROVEN | NOT_PROVEN (planned) | NOT_PROVEN (rules defined) | Middleware Operational Control Plane | SOURCE_READY |
| OpenBao | PASS | JWT mount, 78 roles | authority | NOT_PROVEN | NOT_PROVEN (job pending) | NOT_PROVEN (audit tail) | N/A | NOT_PROVEN (24 + 10 rules) | OpenBao Secrets Authority | SOURCE_READY |
| Prometheus | PASS | `prometheus-openbao` | 4 refs | NOT_PROVEN | self-scrape defined | N/A | N/A | defined | existing | SOURCE_READY |
| Alertmanager | PASS | `alertmanager` | 2 refs | NOT_PROVEN | target active | N/A | N/A | Stage 6 matrix PASS (no delivery) | existing incident triage | SOURCE_READY |
| Grafana | PASS | `grafana-runtime` | 6 refs | NOT_PROVEN | target pending | N/A | N/A | N/A | 53 dashboards | SOURCE_READY |
| Loki | PASS | `loki-runtime` | 2 refs | NOT_PROVEN | target pending | ruler rules pinned | N/A | ruler rules | via Grafana | SOURCE_READY |
| Tempo | PASS | `tempo-runtime` | 4 refs | NOT_PROVEN | target pending | N/A | receiver TLS + contract | via Prometheus | via Grafana | SOURCE_READY |
| Alloy/OTel | PASS | `alloy-collector`, `otel-gateway` | 2 + 4 refs | NOT_PROVEN | targets defined | agent + gateway redaction | agent loopback -> gateway | export-failure rules | via Grafana | SOURCE_READY |
| Node Exporter | PASS | none (credential-free) | none | NOT_PROVEN | target active | N/A | N/A | `CodestraExporterDown` | server health | SOURCE_READY |
| cAdvisor | PASS | none (credential-free) | none | NOT_PROVEN | target active | N/A | N/A | `CodestraExporterDown` | server health | SOURCE_READY |
| Redis Exporter | PASS | `redis-exporter` | 2 refs | NOT_PROVEN | target active | N/A | N/A | `CodestraExporterDown` | Redis health | SOURCE_READY |
| Postgres Exporter | PASS | `postgres-exporter` | 2 refs | NOT_PROVEN | target active | N/A | N/A | `CodestraExporterDown` | PostgreSQL health | SOURCE_READY |
| Blackbox | PASS | none (credential-free) | none | NOT_PROVEN | probe targets defined | N/A | N/A | safe-probe rules | via Grafana | SOURCE_READY |
| Superset | PASS | `superset-analytics` | 8 refs | NOT_PROVEN | health probe defined | N/A | N/A | safe-probe rule | N/A (analytics) | SOURCE_READY |
