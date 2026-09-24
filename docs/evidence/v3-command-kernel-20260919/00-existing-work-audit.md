# 00 — Existing V3 work audit

Base: `22d023a9c65b0789a0f7ee6c28548753521a9eff` (MAIN_AFTER_RUNTIME_MODERNIZATION). Historical branch `mission/middleware-v3-platform-20260918` @ `f2b9cf8` = SEMANTIC_REFERENCE only (no commit replayed).

## Historical branch (f2b9cf8) — classification

| File | Class | Disposition on main |
|---|---|---|
| app/platform/command.py, store.py, ledger.py, contracts.py, capabilities.py, catalog.py, secrets.py, config_authority.py | DROP (second kernel / second tables / duplicates of app.commands, app.secret_reference, #283 catalog, router-registry error envelope) | not carried |
| migrations/0012_platform_kernel.sql (+ RUNTIME_SCHEMA_VERSION=12, history pins) | DROP | runtime SQL stays at 11; schema proof in 15-database.md |
| app/platform/policy.py + config/platform-policy.v1.json | SUPERSEDED | app/core/policy_engine.evaluate_command (one module, own version line) |
| app/platform/safety.py + config/platform-safety.v1.json | REWORK | SafetyGate over Settings effect gates/umbrella + capability registry + adapter readiness + bounds |
| app/platform/adapter.py, resilience.py, metrics.py | KEEP (reworked onto CommandEnvelope / mission metric names) | app/platform/{adapter,resilience,metrics}.py |
| app/platform/openbao.py | SEMANTIC_REFERENCE | not carried in this PR (OpenBao resolution stays with the worker/adapter runtime; #283 SecretReference is the model) |
| app/platform/adapters/{fixtures,legacy_bridge,n8n}.py | REWORK | app/platform/adapters/{fixtures,providers,n8n}.py |
| app/platform/{kernel,bus,worker,runtime,api}.py | REWORK | orchestrator over CommandService; ExecutionBus over PostgresOutboxStore + OutboxWorker; six routes |
| tests/test_platform_*, tests/integration/test_platform_kernel_postgres.py | TEST_ONLY (regenerated) | new suites |
| docs/evidence/middleware-v3-platform-20260918/* (42) | SUPERSEDED | this pack |
| first 38 commits (#278/#280 prep) | SUPERSEDED (already on main) | — |

## This branch's unmerged work (audited before finalization)

| Change | Class | Note |
|---|---|---|
| app/platform/** (17 modules) | KEEP | one kernel, no second store/state machine/policy/registry |
| app/commands.py edits (ADAPTER_COMMAND_DESTINATION, resolve/extended, destination/evidence/trace on submit, attempt fencing, reconcile/latest_attempt/load_envelope/backlog, memory intents, destination-aware mutations) | KEEP | additive; existing suites green |
| app/core/policy_engine.py evaluate_command | KEEP | same module as `evaluate` |
| app/core/runtime.py (shared http clients, PlatformRuntime, worker role) / app/core/providers.py | KEEP | PER_REQUEST_* = 0 |
| app/router_registry.py / app/application.py | KEEP | kernel router in CANONICAL_ROUTERS, handler-authenticated |
| app/api/v1/{contacts,opportunities,tickets,crm_common}.py | KEEP | writes are kernel wrappers |
| app/api/v1/{tenants,session_context,n8n_target,telephony,webphone,readiness_challenge,agent_realtime}.py | KEEP | borrow container clients |
| app/api/v1/quarantine.py `{record_id:uuid}` | KEEP | shadow fixed, regression test |
| deploy/production/compose.canary.yaml + deploy/production/server/codestra-middleware-deploy | KEEP | canary on integration_api:8095 / python3.14 |
| workers/run_outbox.py, app/entrypoints/reconciliation_worker.py, Dockerfile.runtime scheduler/reconciler stages | KEEP | processes on the one container |
| config/control-plane-callers.v1.json (+3 callers), config/platform-safety.v1.json, config/route-authority-report.v1.json, config/route-authority-overrides.v1.json | KEEP | |
| config/route-authority.v1.json | RESTORED byte-identical to main (an earlier commit had overwritten it; fixed in c88900f) | |
| contracts/*, config/api-completion-matrix.yaml, deploy/public-api-route-contract.* | REGENERATED (LF) | only the six kernel operations differ from main (+ YAML anchor renumbering) |
| contracts/observability/integrated-monitoring.openapi.json | UNCHANGED | host pydantic 2.10 renders one line differently from the CI image's 2.12.5; the committed file is the image's rendering |
