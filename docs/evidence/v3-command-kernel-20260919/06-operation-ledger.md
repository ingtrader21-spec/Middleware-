# 06 — Operation ledger

Tables (runtime SQL 11, unchanged): middleware_commands (state, provider_operation_id, resource_version, cancellation/reconciliation metadata), middleware_command_attempts (attempt_number, state, provider id, result_payload = readback evidence), middleware_command_audit (append-only, previous/new state, actor, reason, metadata = decision evidence, replay linkage `replay_mode`/`replay_of`, readback digest), middleware_operation_mutations (cancel/reconcile/retry with request_sha256, immutable trigger), middleware_control_audit (denials, reconciliation claims).

Never persisted: JWT / Authorization, provider passwords, OpenBao values, private keys, client secrets (redact_metadata on every metadata write; adapters' `redact()` on provider evidence; 21-case matrix asserts nothing is persisted on denial).

Timeline (`GET …/timeline`): event_id (monotonic, verified), operation_id, event_type (operation.accepted / transition / mutation.<action> / reconciliation / replay), previous/new public state, actor, reason, correlation_id, causation_id (preceding event), attempt, redacted safe_metadata, created_at.
