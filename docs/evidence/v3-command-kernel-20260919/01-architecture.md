# 01 — Architecture

See `docs/architecture/middleware-v3-command-kernel.md` (design, classification, lifecycle, schema proof).

Exactly one of each authority on the final tree:

| Authority | Owner | Count |
|---|---|---|
| Configuration | app/core/config.py `Settings` | 1 |
| RuntimeContainer | app/core/runtime.py | 1 (+ `role="worker"` for worker/scheduler/reconciler) |
| Application factory | app/application.py `create_app` | 1 |
| Router registry | app/router_registry.py | 1 |
| Bootstrap / health | app/core/bootstrap.py, app/core/health.py | 1 each |
| Policy Engine | app/core/policy_engine.py (`evaluate`, `evaluate_command`) | 1 |
| Capability registry | app/commands.py `CommandPolicyRegistry` (+ runtime TEST_SYN / N8N families) | 1 |
| Safety authority | app/platform/safety.py `SafetyGate` | 1 |
| Command kernel | app/platform/kernel.py over app/commands.py `CommandService` | 1 |
| Idempotency authority | middleware_commands UNIQUE(tenant_id, idempotency_key) + payload digest | 1 |
| Operation ledger | middleware_commands / _command_attempts / _command_audit / _operation_mutations | 1 |
| Adapter registry | app/platform/registry.py | 1 |
| Execution bus | app/platform/bus.py over middleware_outbox + app/worker.OutboxWorker | 1 |
| Reconciliation | app/platform/reconciler.py (adapter-executed) — Temporal reconcile activity reuses the same ledger transitions for Temporal-executed families | 1 authority, 2 hosts |
| Service catalog / SecretReference | PR #283, unchanged | 1 |

Canonical service `middleware-integration-api`, port 8095, CANONICAL_8080=0 (see 17-container-runtime.md).
