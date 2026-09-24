# 03 — Hosted CI on the repaired exact head `0d61de4`

Source: `gh pr checks 301 --repo ingtrader21-spec/Middleware-` after all runs completed (captured 2026-09-21 ~12:47Z). 29 pass, 3 skipping (matrix / main-push-only jobs), 0 fail.

| Check | Result | Duration |
| --- | --- | --- |
| Test exact repository SHA (Required exact-SHA CI, run 35600936736) | pass | 7m59s |
| Publish exact-SHA final status | pass | 3s |
| codestra/required-ci | pass | — |
| Validate middleware source head (Middleware CI, run 35600936823) | pass | 3m14s |
| Validate middleware merge result | pass | 2m45s |
| validate (Middleware CI umbrella) | pass | 3s |
| validate (middleware) | pass | 4m40s |
| validate (agent-desktop) | pass | 3m31s |
| validate (websocket-gateway) | pass | 1m25s |
| docker-runtime-build | pass | 45s |
| docker-test-build | pass | 3m41s |
| connector-runtime-build | pass | 24s |
| container-security | pass | 1m59s |
| source-security | pass | 9s |
| Disposable PostgreSQL Redis integration | pass | 2m55s |
| Disposable NATS JetStream integration | pass | 37s |
| Temporal critical workflow integration | pass | 32s |
| Synthetic no-effect acceptance E2E | pass | 55s |
| production-integration-lock | pass | 7s |
| signed-runtime-contract (Production route contract) | pass | 30s |
| orchestrator-contract | pass | 1m13s |
| trusted-orchestrator-evidence | pass | 1m13s |
| connector-sdk-v1-validation | pass | 30s |
| Ruff baseline (report only) | pass | 13s |
| mypy core baseline (report only) | pass | 1m15s |
| mypy Connector Runtime baseline (report only) | pass | 39s |
| Analyze (python) — CodeQL | pass | 1m12s |
| Analyze (actions) — CodeQL | pass | 37s |
| CodeQL | pass | 2s |
| Validate middleware main push | skipping | — |
| Calling contract (matrix) | skipping | — |
| order-orchestration | skipping | — |

The two Middleware CI validations and the exact-SHA test that failed on `0185fc84` (01) pass on `0d61de4` with no other change than the closure entry (02). The Windows-only symlink test noted in 02 passes here on Linux.
