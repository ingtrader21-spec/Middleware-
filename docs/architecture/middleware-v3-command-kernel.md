# Middleware V3 — the command kernel (converged architecture)

Status: implementation mission `mission/middleware-v3-command-kernel-20260919`.
Base: `MAIN_AFTER_RUNTIME_MODERNIZATION` (the squash of PR #287 on `0ed9d10`).
`PROVIDER_EFFECTS=0`, `PRODUCTION_GO=NO` throughout.

V3 is an *architecture* version, not a URL version. It turns the existing
Middleware kernel — `app/commands.py` over the `middleware_*` ledger — into
the single command/policy/safety/audit/idempotency/operation-status/
reconciliation authority of the platform, and adds the adapter fabric that
executes commands. Nothing in V3 is a second middleware: every competing
authority found in the historical V3 branch (`mission/middleware-v3-platform-
20260918` @ `f2b9cf8`) was folded into the existing owner or deleted.

## 1. What already existed on main (reused, not rebuilt)

| Authority | Owner on main | V3 change |
|---|---|---|
| Configuration | `app/core/config.py` (`Settings`) | none — kernel reads `settings` only |
| RuntimeContainer | `app/core/runtime.py` | gains the shared `httpx.AsyncClient` and the `PlatformRuntime` (kernel, policy gate, safety gate, adapter registry, execution bus, metrics) |
| Application factory | `app/application.py` (`create_app`) | mounts the kernel router through the registry on every profile |
| Router registry | `app/router_registry.py` | `platform_kernel_router` added to `CANONICAL_ROUTERS` |
| Policy Engine | `app/core/policy_engine.py` (`evaluate`) | gains `evaluate_command` — the command-authorization decision of the same engine, same version line |
| Capability registry | `app/commands.py` `CommandPolicyRegistry` over `config/capabilities.v2.json` + `connectors/generated/command-registry.v1.json` | gains `resolve()`; adapter ownership is validated against it by the adapter registry |
| Command ledger / attempts / audit / mutations | `middleware_commands`, `middleware_command_attempts`, `middleware_command_audit`, `middleware_operation_mutations` (runtime SQL 0002/0004/0011) | reused as-is; audit `metadata` carries the policy/safety decision evidence |
| Durable outbox / attempt events / reconciliation audit | `middleware_outbox`, `middleware_outbox_attempt_events`, `middleware_reconciliation_audit` (0001/0006) with `lease_owner`/`lease_until`, `FOR UPDATE SKIP LOCKED`, `resource_version` | reused as the ExecutionBus's durable truth; new destination `adapter-command` |
| Inbox / event ledger | `middleware_inbox`, `middleware_event_ledger` | unchanged (Phase 35 already holds) |
| Control audit | `middleware_control_audit` (0005, immutable) | policy/safety denials and replay decisions are audited here |
| Service Catalog | PR #283 (`app/api/v1/platform.py`, ORM) | unchanged |
| SecretReference | PR #283 `app/secret_reference.py` + `contracts/secrets/secret-reference.v1.schema.json` | unchanged; adapters receive references, never values |
| Odoo CRM surfaces | PR #286 `app/api/v1/{contacts,opportunities,tickets}.py` | writes become kernel wrappers (`crm.*` commands); reads stay read-only bridge calls |
| Kyqra ingress | PR #269 `/api/v1/kyqra/results|progress` | unchanged (INTERNAL_EVENT_INGRESS) |
| N8N transport | `app/adapters/n8n/transport.py` (`attest_target`, `reserve_delivery`, `submit_reserved`) | wrapped by the N8N executor adapter |
| Health/readiness | `app/core/health.py` + `RuntimeContainer.readiness` | adapter registry validity and enabled-adapter readiness are components |

Runtime SQL schema stays at version **11**. No `platform_*` table is created:
the existing tables already carry idempotency (`UNIQUE(tenant_id,
idempotency_key)` + `payload_sha256`), leases and fencing (`lease_owner`,
`lease_until`, `resource_version`, `attempt_number`), request hashes
(`payload_sha256`, `request_sha256`), decision references (audit `metadata`)
and timeline metadata (`middleware_command_audit` + the 0011 indexes). The
schema proof is in §7.

## 2. Classification of the historical V3 branch (`f2b9cf8` vs main)

| Historical file | Classification | Where it went |
|---|---|---|
| `app/platform/command.py` (second `Command`/`CommandState`) | DELETE_AS_DUPLICATE | `app/commands.py` `CommandEnvelope`, `CommandState`, `ALLOWED_COMMAND_TRANSITIONS` |
| `app/platform/store.py` (`PostgresPlatformStore`, `platform_*`) | DELETE_AS_DUPLICATE | `PostgresCommandStore` + `PostgresOutboxStore` |
| `migrations/0012_platform_kernel.sql` | DELETE_AS_DUPLICATE | no migration needed (§7) |
| `app/platform/ledger.py` | DELETE_AS_DUPLICATE | `middleware_command_audit` (`OperationEvent`) |
| `app/platform/policy.py` + `config/platform-policy.v1.json` | REFACTOR → `app/core/policy_engine.evaluate_command` | one policy engine, one version line |
| `app/platform/capabilities.py` + `config/platform-capabilities.v1.json` | DELETE_AS_DUPLICATE | `CommandPolicyRegistry` (+ `resolve`) |
| `app/platform/catalog.py` + `config/platform-service-catalog.v1.json` | ALREADY_ON_MAIN (#283) | — |
| `app/platform/secrets.py` | ALREADY_ON_MAIN (#283 `app/secret_reference.py`) | — |
| `app/platform/config_authority.py` | REFACTOR | folded into `GET /platform/v1/kernel/describe` |
| `app/platform/contracts.py` | DELETE_AS_DUPLICATE | `router_registry.install_domain_error_handler` envelope + `app/operations.py` response models |
| `app/platform/safety.py` + `config/platform-safety.v1.json` | REFACTOR → `app/platform/safety.py` `SafetyGate` | consumes `Settings.umbrella_controls`/`external_effects`, the capability registry, adapter readiness, provider kill switches and quotas |
| `app/platform/adapter.py` | REUSE (extended) | Phase 22 protocol: `adapter_id`, `validate_config`, `capabilities`, `readiness`, `execute`, `status`, `readback`, `reconcile`, `cancel`, `normalize_result`, `classify_error`, `redact` |
| `app/platform/resilience.py` | REUSE | retry classes, breaker, bulkhead, `ReplayMode` |
| `app/platform/metrics.py` | REUSE (renamed series) | Phase 36 metric names |
| `app/platform/bus.py` + `worker.py` | REFACTOR → `app/platform/bus.py` | `ExecutionBus` over `PostgresOutboxStore` + `OutboxWorker` (`adapter-command` handler) |
| `app/platform/kernel.py` | REFACTOR | orchestrator over `CommandService` (no second store) |
| `app/platform/api.py` | REGENERATE | six kernel routes over the kernel + `app/operations.py` readers |
| `app/platform/runtime.py` | REFACTOR | `PlatformRuntime` wiring on the RuntimeContainer |
| `app/platform/openbao.py` | REUSE | workload-identity OpenBao client (resolution only in worker/adapter runtime) |
| `app/platform/adapters/{fixtures,legacy_bridge,n8n}.py` | REFACTOR | adapters over `CommandEnvelope`; `test-syn` fixture; Odoo/Klyrow/Telnexa/N8N/VICIdial/Kyqra/Postly bridges over the existing transports |
| `tests/test_platform_*` | REGENERATE | kernel, API, conformance, idempotency-concurrency, chaos, tenant isolation |
| `docs/adr/0001-execution-bus.md` | REUSE (updated) | — |
| `docs/evidence/middleware-v3-platform-20260918/*` | DELETE (superseded) | this document + the PR evidence |
| everything in the first 38 commits (#278/#280 prep) | ALREADY_ON_MAIN | — |

## 3. Command lifecycle

```
client ──POST /platform/v1/commands──▶ integration API (8095)
   1 parse            9 registry resolution (prefix → target/capability/readback)
   2 size/schema     10 adapter ownership (registry)
   3 JWT             11 Policy Engine  (evaluate_command)  ─ deny → 403 policy_denied  (audited)
   4 issuer          12 Safety Gate                        ─ deny → 403 safety_denied   (audited)
   5 audience        13 idempotency reservation (UNIQUE tenant_id+idempotency_key, payload digest)
   6 azp/client      14 middleware_commands (persisted)
   7 tenant          15 middleware_command_audit (decision evidence in metadata)
   8 actor           16 middleware_outbox intent (destination adapter-command | temporal-command)
                     17 COMMIT
                     18 202 Accepted + Location: /platform/v1/operations/{id}
```

Exact replay (same key, same canonical payload, same client) returns the
existing operation with `duplicate=true` and creates nothing. Same key with a
different payload is `409 command_conflict`.

Execution never happens in the request. The ExecutionBus claims the outbox
row with a lease (`FOR UPDATE SKIP LOCKED`), quarantines it as
reconciliation-required *before* any provider code runs (existing
`OutboxWorker` semantics), records the attempt (`queued → dispatching`), runs
the adapter inside its bulkhead/breaker/timeout, records the provider
acknowledgement (`accepted`, `provider_operation_id`), then reads back:

* readback `MATCHED` → `readback_pending → completed`
* readback `MISMATCH` → `failed`
* readback `UNAVAILABLE`, transport timeout after send, provider 5xx after
  submission, ambiguous result → `reconciliation_required`
* deterministic rejection before any effect → `failed` (retryable per class)
* stale lease / stale attempt fencing → the finalization is rejected

`completed` is reachable only through a `MATCHED` readback.

## 4. Public state mapping

`persisted→RECEIVED, queued→QUEUED, dispatching→SUBMITTED, accepted→ACCEPTED,
readback_pending→UNKNOWN, completed→COMPLETED, failed→FAILED,
reconciliation_required→RECONCILIATION_REQUIRED, dead_lettered→DEAD_LETTERED,
cancelled→CANCELLED` (unchanged `API_OPERATION_STATES`).

## 5. The six kernel routes (integration profile, Kong upstream `middleware-integration-api:8095`)

The submit body is provider-blind: `target` (connector id) and `capability` may be omitted; the command registry binds both to the command family and a supplied value must agree with it.

| Route | Scope | Notes |
|---|---|---|
| `POST /platform/v1/commands` | `platform.command` | 202 / 200 duplicate / 409 conflict / 403 policy, safety, capability |
| `GET /platform/v1/operations/{id}` | `platform.command.read` | tenant-scoped; foreign tenant → 404 |
| `GET /platform/v1/operations/{id}/timeline` | `platform.command.read` | append-only audit, monotonic `event_id` |
| `POST /platform/v1/operations/{id}/cancel` | `platform.command` | `expected_version` + `reason`; semantics of `mutate_operation` |
| `POST /platform/v1/operations/{id}/replay` | `platform.command.replay` + role `platform-operator` | `mode=REPROCESS` (no new effect) or `REEXECUTE` (new idempotency key, fresh policy + safety, adapter must support it) |
| `GET /platform/v1/kernel/describe` | `platform.command.read` | versions, digests, registries, effect defaults; no secrets |

`GET /metrics` stays private (`monitoring-readonly`, `metrics.read`).

The legacy domain surfaces are preserved: the #286 CRM writes became kernel wrappers (`crm.<entity>.<action>.v1` → `odoo-19`, 202 + Location); reads are unchanged. Every operation of the integration profile is classified in `config/route-authority-report.v1.json` (generated by `scripts/generate_route_authority_report.py`, guarded by `tests/test_route_authority_report.py`): `DIRECT_EFFECT_BYPASSES=0`; five reviewed worker-executed durable-outbox ingress/projection paths are pinned as `APPROVED_DURABLE_OUTBOX_EXCEPTION` and three synchronous provisioning-service calls (webphone session issuance) remain explicit `DIRECT_INTERNAL_SERVICE` exceptions. `KERNEL_CONVERGENCE_PENDING=0`; neither exception class is a direct external-provider bypass.

## 6. Adapter fabric

`app/platform/adapter.py` defines the one adapter protocol; unsupported
operations return `UNSUPPORTED` explicitly. `app/platform/registry.py` is the
one adapter registry: it refuses duplicate ids, requires every registered
adapter to own at least one command prefix of the command registry, requires
exactly one owner per prefix, requires readback support wherever the registry
says `readback_required`, and fails readiness when an enabled capability has
no ready adapter. Adapters receive an `AdapterContext` (correlation, trace,
timeout, secret references, shared HTTP client) and never read the process
environment, open pools or clients, or decide authorization.

## 7. Schema proof (why there is no migration 12)

| Required invariant | Existing carrier |
|---|---|
| one command record per (tenant, idempotency key) | `middleware_commands UNIQUE(tenant_id, idempotency_key)` |
| replay detection by canonical payload | `payload_sha256` (+ authenticated client) |
| one outbox intent per command submission | `middleware_outbox UNIQUE(tenant_id, destination, idempotency_key)`; `command_id` column |
| lease + fencing | `middleware_outbox.lease_owner/lease_until` (claim `FOR UPDATE SKIP LOCKED`; complete/fail require the owner); `middleware_command_attempts.attempt_number` (finalization fenced to the newest attempt) |
| optimistic concurrency for operator mutations | `middleware_commands.resource_version` + `middleware_operation_mutations(request_sha256)` |
| decision evidence | `middleware_command_audit.metadata` (policy + safety decision ids, versions, reason codes) |
| denial audit | `middleware_control_audit` (immutable) |
| timeline ordering | `middleware_command_audit(id)` + 0011 indexes |
| readback evidence | `middleware_command_attempts.result_payload` + audit `readback_evidence_sha256` |

## 8. Processes

`middleware-api` (accept/read), `middleware-worker` (`workers.run_outbox`,
executes leased commands through the adapter registry), `middleware-scheduler`
(`workers.run_scheduler`, time-based enqueue only), `middleware-reconciler`
(`workers.run_reconciler`, unknown outcomes/drift). All build the same
`RuntimeContainer` from the same image; none is a second command authority.
