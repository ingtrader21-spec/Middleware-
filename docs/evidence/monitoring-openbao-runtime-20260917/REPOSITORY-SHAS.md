# Repository SHAs (2026-09-17)

Every repository was changed only on its isolated worktree/branch; dirty trees in the primary checkouts were preserved untouched. Base branches were not modified.

| Repository | Branch | Exact SHA (branch head) | Base | PR | Changed in this stage | Final status |
| --- | --- | --- | --- | --- | --- | --- |
| Middleware- | `codex/monitoring-openbao-integration-20260916` | `30498a30381a602952eefff269e826265e27c810` | `codex/cross-repo-authority-20260916` | [#279](https://github.com/appolon1908-hue/Middleware-/pull/279) | yes (collector, TEST_SYN runner, failure modes, service-state fold; evidence commit follows) | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-OpenBao | `remediation/monitoring-openbao-integration-20260916` | `b8e2144f92575e13e2688baa1e536c249be2dc84` | `development` | [#78](https://github.com/appolon1908-hue/Codestra-OpenBao/pull/78) | yes (staging identity certifier, rotation matrix) | BLOCKED_PENDING_EXACT_SHA_CI |
| Keycloak | `codex/monitoring-openbao-integration-20260916` | `886ce5e64e1219c22f25686e2ba4d9c469421619` | `codex/cross-repo-authority-20260916` | [#119](https://github.com/appolon1908-hue/Keycloak/pull/119) | rebased onto 96bdda7 (source alignment) | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Prometheus | `codex/monitoring-openbao-integration-20260916` | `1e1089a26860e04f4b08cab946bec205a1d12d2f` | `main` | [#70](https://github.com/appolon1908-hue/Codestra-Prometheus/pull/70) | yes (per-target inventory + runtime merge) | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Alertmanager | `codex/monitoring-openbao-integration-20260916` | `d5da15851cfc02c1b5ff43aec858c51ab8868d3d` | `main` | [#29](https://github.com/appolon1908-hue/Codestra-Alertmanager/pull/29) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Telemetry | `codex/monitoring-openbao-integration-20260916` | `bf48a9c1c41093c7f46b1df4d44d49406179ba8f` | `development` | [#57](https://github.com/appolon1908-hue/Codestra-Telemetry/pull/57) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Alloy | `codex/monitoring-openbao-integration-20260916` | `f1be1cd3c70dbb84c8404a7cf0f4894bd04d9a8b` | `development` | [#39](https://github.com/appolon1908-hue/Codestra-Alloy/pull/39) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Loki | `codex/monitoring-openbao-integration-20260916` | `639f171047fff676298ee34be696ba30c2d6585c` | `development` | [#40](https://github.com/appolon1908-hue/Codestra-Loki/pull/40) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Tempo | `codex/monitoring-openbao-integration-20260916` | `911218affcd35d7c9b9fa2ac602f235fdd039b63` | `development` | [#33](https://github.com/appolon1908-hue/Codestra-Tempo/pull/33) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Grafana- | `codex/monitoring-openbao-integration-20260916` | `9c119fe8eca06a5da97e45a06a013f2d838872bc` | `main` | [#32](https://github.com/appolon1908-hue/Codestra-Grafana-/pull/32) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Node-Exporter | `codex/monitoring-openbao-integration-20260916` | `d054cafe67be13701beb86f2e63374758629cbbd` | `development` | [#38](https://github.com/appolon1908-hue/Codestra-Node-Exporter/pull/38) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-cAdvisor | `codex/monitoring-openbao-integration-20260916` | `f19d0c4e657586d92a312629106a2d1885a477f2` | `development` | [#41](https://github.com/appolon1908-hue/Codestra-cAdvisor/pull/41) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Redis-Exporter | `codex/monitoring-openbao-integration-20260916` | `fc8ed43d3e14a82964d0dbd02c05c89552116c65` | `development` | [#40](https://github.com/appolon1908-hue/Codestra-Redis-Exporter/pull/40) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Postgres-Exporter | `codex/monitoring-openbao-integration-20260916` | `992c182661676f3fbe182dd6081e75e1316fad13` | `development` | [#20](https://github.com/appolon1908-hue/Codestra-Postgres-Exporter/pull/20) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Codestra-Blackbox-Exporter | `codex/monitoring-openbao-integration-20260916` | `61450f8030cb11b686182e3f0ed8919f68af7024` | `development` | [#36](https://github.com/appolon1908-hue/Codestra-Blackbox-Exporter/pull/36) | no | BLOCKED_PENDING_EXACT_SHA_CI |
| Superset | `codex/monitoring-openbao-integration-20260916` | `ec9591c094f31b553570ffcef57963cf5d0bcb75` | `development` | [#51](https://github.com/appolon1908-hue/Superset/pull/51) | no | BLOCKED_PENDING_EXACT_SHA_CI |

Middleware: `30498a30381a602952eefff269e826265e27c810` is the code SHA at which local certification ran; the evidence commit that adds this package follows it and touches only `docs/evidence/**`. **The exact SHA that must pass CI is the final branch head after the evidence commit** (recorded in FINAL-GATE.md); local results are not transferable to any other SHA.

## GitHub Actions state

Every push in this stage produced `startup_failure` / zero-step `failure` runs; the check-run annotation reads verbatim: "The job was not started because your account is locked due to a billing issue." — last confirmed 2026-09-17T10:48Z (Middleware run 35212408013 on eeefec60; OpenBao b8e2144f and Prometheus 1e1089a2 startup_failure at 10:38Z/10:42Z). `gh run rerun` is refused for the same reason. No admin bypass was used, no required check was disabled, no branch protection was weakened, and no PR was merged.

## Base-branch verification

- Middleware PR #279 is stacked on PR #278 (`codex/cross-repo-authority-20260916` @ `bd6adaf0`), unchanged.
- Keycloak base `codex/cross-repo-authority-20260916` advanced to `96bdda7`; the branch was rebased (`--force-with-lease`) and validators re-run (`openbao_workload_identity_desired_state.py --check --require-cross-check` PASS, 20 tests OK).
- All other bases are as recorded in the source-stage package (`docs/evidence/monitoring-openbao-integration-20260916/REPOSITORY-MATRIX.md`).
