# Staging certification (2026-09-17)

## Required deployment order and status

| # | Step | Status | Evidence / blocker |
| --- | --- | --- | --- |
| 1 | OpenBao staging (init/unseal ceremony, audit device, mounts, roles, policies) | NOT PERFORMED | operations authority: staging `NO_GO_PREPARATION_INCOMPLETE`; init/unseal prohibited outside the ceremony; no host/SSH access (permission denied) |
| 2 | Keycloak staging reconciliation (`openbao.workload` scope, 9 clients, 7 links) | NOT PERFORMED (plan/apply tooling ready) | no admin client secret file available |
| 3 | Middleware staging release with `0067` | NOT PERFORMED | CI blocked (billing lock); no deploy authority in session |
| 4 | Prometheus staging activation (`pending → active`, activation PR citing image digest + evidence checksum) | NOT RAISED | contract requires runtime evidence checksum first |
| 5 | Alertmanager staging bundle | NOT PERFORMED | — |
| 6 | Alloy/OTel, Loki, Tempo | NOT PERFORMED | — |
| 7 | Exporters, Blackbox | NOT PERFORMED | — |
| 8 | Grafana datasources/dashboards | NOT PERFORMED | — |
| 9 | Superset boundary | source only | — |
| 10 | Collector run → reconciliation → catalog observed state | NOT PERFORMED | tool ready (`scripts/monitoring_collector.py`) |
| 11 | OpenBao identity certification + rotation | NOT PERFORMED | tool ready (`scripts/certify_staging_identity.py`, rotation matrix) |
| 12 | TEST_SYN E2E | NOT PERFORMED | tool ready (`scripts/certify_test_syn.py`) |
| 13 | Failure-mode injection | NOT PERFORMED | source proofs only |

Public reachability observed from this session (no credentials used): `https://auth-staging.codestra.co` → 302 (Keycloak alive), `https://bao.codestra.media` → 403 at the edge (expected posture). Docker/WSL unavailable on the host; SSH to staging denied.

## What is staging-proven

Nothing at runtime. Everything in the mission's definition of done that requires staging (OpenBao health monitored live, Middleware monitoring state runtime-observed, TEST_SYN trace/log/metric/alert correlation, rotation, failure injection) remains open; the tooling to produce each proof is committed, unit-proven with fakes, and fail-closed.

## Local certification performed (host: Windows 10, `core.autocrlf=true`)

- Middleware `30498a30381a`: targeted suites 127 passed (collector 18, TEST_SYN 13, failure modes 9, component states 3, integrated monitoring 33, catalog monitoring 19, staging acceptance, history lock) + full suite 3100 passed / 252 skipped; 78 host-only failures reproduced on the base (openssl-dependent VICIdial mTLS, `WinError 1314` symlink privilege, POSIX 0600 mode checks, `/`-rooted workspace paths, CRLF digests). `ruff check` clean on the changed files.
- OpenBao `b8e2144f9257`: validators PASS; unit 15, policy 13, integration 2, recovery 19, runtime 2 OK; security 80 (13 Windows-only errors as on base); `reject_repository_secrets.sh` SCAN_OK.
- Prometheus `1e1089a26860`: `validate.py` PASS (incl. inventory), `promtool check config --syntax-only` PASS, pytest 27 passed, unittest 15 OK.
- Keycloak `886ce5e64e12`: `openbao_workload_identity_desired_state.py --check --require-cross-check` PASS, 20 tests OK.
- All other repositories: unchanged since their source-stage certification (validators PASS recorded in the 2026-09-16 package).
