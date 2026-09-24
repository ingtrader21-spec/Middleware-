# 02 — Kernel pipeline

`POST /platform/v1/commands` (app/platform/api.py → app/platform/kernel.py → app/commands.py):

1. parse (provider-blind `KernelCommandRequest`, extra fields forbidden, payload ≤ 262144 bytes)
2. JWT (RS256 only), issuer, audience, azp = registered control-plane caller, scope `platform.command` (app/security.KeycloakJwtVerifier + app/platform/principal.authenticate)
3. principal from verified claims only (subject, client, tenants, roles, scopes); body tenant must be granted; `requested_by` must equal `sub`; X-Correlation-ID / Idempotency-Key must equal the body
4. registry resolution: exactly one policy owns the command family; target/capability bound from it
5. adapter ownership (registry) → destination `adapter-command`, else `temporal-command`
6. Policy Engine `evaluate_command` → deny 403 policy_denied (audited)
7. Safety Gate → deny 403 safety_denied / 429 kernel_saturated (audited)
8. one transaction: idempotency reservation, middleware_commands (persisted), middleware_command_audit (decision evidence), middleware_outbox intent (+ `_trace` for propagation)
9. COMMIT → 202 + Location (200 duplicate=true on exact replay; 409 on conflict)

Controllers never call providers, never pick credentials, never own state. Execution: app/platform/bus.AdapterDispatch as the `adapter-command` handler of app/worker.OutboxWorker (lease → quarantine-before-provider → heartbeat → adapter execute → accepted → readback → completed only on MATCHED; UNKNOWN/ambiguous → reconciliation_required; TRANSIENT → bounded known-safe retry; REJECTED → failed). Finalizations are fenced to their attempt number.
