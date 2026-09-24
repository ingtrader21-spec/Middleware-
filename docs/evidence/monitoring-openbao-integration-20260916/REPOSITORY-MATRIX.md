# Repository matrix — exact branches and SHAs (2026-09-16)

Every repository below was worked in an isolated worktree on one integration branch; dirty checkouts on `main`/feature branches were left untouched. "Head" is the commit every check in this package was executed on.

| Repository | Branch | Head | Base | Pull request | Target |
| --- | --- | --- | --- | --- | --- |
| Codestra-OpenBao | `remediation/monitoring-openbao-integration-20260916` | `28f009c6852e` | `15d8ded836f4` | https://github.com/appolon1908-hue/Codestra-OpenBao/pull/78 | `development` |
| Keycloak | `codex/monitoring-openbao-integration-20260916` | `3daa1fa4aa67` | `bd4ca21601bc` | https://github.com/appolon1908-hue/Keycloak/pull/119 | `codex/cross-repo-authority-20260916 (stacked on #118)` |
| Middleware- | `codex/monitoring-openbao-integration-20260916` | `281bb7a6f153` (certified; the evidence commits on top change only `docs/evidence/` and `tests/test_secret_file_fail_closed.py`) | `bd6adaf` (codex/cross-repo-authority-20260916) | https://github.com/appolon1908-hue/Middleware-/pull/279 | `codex/cross-repo-authority-20260916 (stacked on #278)` |
| Codestra-Prometheus | `codex/monitoring-openbao-integration-20260916` | `7c1e70685453` | `0600406f9eab` | https://github.com/appolon1908-hue/Codestra-Prometheus/pull/70 | `main` |
| Codestra-Alertmanager | `codex/monitoring-openbao-integration-20260916` | `d5da15851cfc` | `abfd0f551e9a` | https://github.com/appolon1908-hue/Codestra-Alertmanager/pull/29 | `main` |
| Codestra-Telemetry | `codex/monitoring-openbao-integration-20260916` | `bf48a9c1c410` | `477207d0e858` | https://github.com/appolon1908-hue/Codestra-Telemetry/pull/57 | `development` |
| Codestra-Alloy | `codex/monitoring-openbao-integration-20260916` | `f1be1cd3c70d` | `98b428ec33d6` | https://github.com/appolon1908-hue/Codestra-Alloy/pull/39 | `development` |
| Codestra-Loki | `codex/monitoring-openbao-integration-20260916` | `639f171047ff` | `1b29eb41b49e` | https://github.com/appolon1908-hue/Codestra-Loki/pull/40 | `development` |
| Codestra-Tempo | `codex/monitoring-openbao-integration-20260916` | `911218affcd3` | `c58865be3b95` | https://github.com/appolon1908-hue/Codestra-Tempo/pull/33 | `development` |
| Codestra-Redis-Exporter | `codex/monitoring-openbao-integration-20260916` | `fc8ed43d3e14` | `4a702b0198ab` | https://github.com/appolon1908-hue/Codestra-Redis-Exporter/pull/40 | `development` |
| Codestra-Postgres-Exporter | `codex/monitoring-openbao-integration-20260916` | `992c18266167` | `c904f68ed9ba` | https://github.com/appolon1908-hue/Codestra-Postgres-Exporter/pull/20 | `development` |
| Codestra-Blackbox-Exporter | `codex/monitoring-openbao-integration-20260916` | `61450f8030cb` | `738742330c61` | https://github.com/appolon1908-hue/Codestra-Blackbox-Exporter/pull/36 | `development` |
| Codestra-Node-Exporter | `codex/monitoring-openbao-integration-20260916` | `d054cafe67be` | `04098ce410e2` | https://github.com/appolon1908-hue/Codestra-Node-Exporter/pull/38 | `development` |
| Codestra-cAdvisor | `codex/monitoring-openbao-integration-20260916` | `f19d0c4e6575` | `07237a002cfd` | https://github.com/appolon1908-hue/Codestra-cAdvisor/pull/41 | `development` |
| Codestra-Grafana- | `codex/monitoring-openbao-integration-20260916` | `9c119fe8eca0` | `2033fb01d021` | https://github.com/appolon1908-hue/Codestra-Grafana-/pull/32 | `main` |
| Superset | `codex/monitoring-openbao-integration-20260916` | `ec9591c094f3` | `3cefe457c668` | https://github.com/appolon1908-hue/Superset/pull/51 | `development` |

Canonical contract digests vendored across repositories:

- Secret-reference schema (OpenBao authority `contracts/secret-reference.v1.schema.json`), canonical sha256 `8762a999da747a9450d73dc876718a3f70a3fb47fd1e065689cdf2357849a665` — vendored byte-for-byte in Middleware, Alertmanager, Telemetry, Alloy, Loki, Tempo, Redis/Postgres exporters, Grafana, Superset.
- OpenBao workload authority `config/workload-secret-authority.v1.json`, canonical sha256 `0dd53c17b1668bb0488c579cb5d128d64c185ee8923d9b2a9712485609d214bd` — vendored and pinned in Keycloak (`config/desired-state/openbao-workload-identity/`), cross-check `OPENBAO_AUTHORITY_CROSS_CHECK=PASS`.
- OpenBao audit ruler rules `monitoring/alerts/openbao-audit-loki-rules.yml` — pinned copy in Loki (`LOKI_OPENBAO_AUDIT_RULES_CROSS_CHECK=PASS`).

Repositories inspected but not changed: Infustruction-repo (design authority `INTEGRATED-MONITORING-DESIGN.md`), codestra-production-platform, codestra-production-runtime-authority (placement/network), Caddy, Kong, Odoo, N8N (their trace-propagation hops are declared as `planned` in Tempo's contract; instrumentation is owned there).
