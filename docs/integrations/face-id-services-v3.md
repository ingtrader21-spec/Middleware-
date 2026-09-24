# FACE-ID service integration with Middleware V3

GitHub API identity readback on 2026-09-24 confirms the service repositories
under `ingtrader21-spec`: `FACE-ID` (1384373026), `Codestra-Face-Liveness`
(1386426580), `Codestra-Camera-Gateway` (1386427236), and
`Codestra-PostgreSQL` (1386427368). The authority and system registries pin
these IDs; their active repository lifecycle does not authorize runtime effects.

These source contracts reconcile FACE-ID and introduce Face-Liveness,
Camera-Gateway and PostgreSQL as independent services. This checkout contained
no previous FACE-ID route or adapter to migrate. Service implementation and live
endpoint compatibility remain unverified; no runtime activation is authorized.

Caddy/Kong → Middleware integration API :8095 → durable command ledger/outbox
→ worker → private service API is the only command path. Middleware owns
orchestration, policy, audit and command state. Each service owns its internal
data and algorithms. PostgreSQL is an API control service for named backup
policies, not a database connection, arbitrary SQL bridge or shared-write path.
No enrollment, biometric storage, media streaming or database restore API is
introduced by this change.

| Service | Command | Reference-only payload | Capability |
|---|---|---|---|
| face-id | face-id.verify.v1 | subject_ref, capture_ref, liveness_ref | FACE_ID_VERIFY |
| face-liveness | face-liveness.verify.v1 | capture_ref, challenge_ref | FACE_LIVENESS_VERIFY |
| camera-gateway | camera-gateway.capture.v1 | camera_ref, consent_ref | CAMERA_CAPTURE |
| postgresql | postgresql.backup.v1 | database_ref, backup_policy_ref | POSTGRESQL_BACKUP |

References are opaque tenant-scoped handles. The owning service resolves them
and verifies access, consent, validity and policy; Middleware never fetches
media or stores embeddings. Unknown commands, extra fields, URLs and raw data
are rejected before the command ledger. A completed verification means the
service finished processing, not that a person passed identity verification.
Business results remain at the owning service; clients must not interpret the
Middleware operation state as an authorization or identity decision.

## Public caller contract

Reuse POST /platform/v1/commands (platform.command), GET
/platform/v1/operations/{id} and /timeline (platform.command.read).
The existing JWT validator verifies signature, issuer, audience, expiry and
registered azp/client; the kernel enforces tenant, actor, target and allowed
command prefixes. No new caller is enabled. An approved caller registration
must explicitly allow the corresponding service prefix and target. Replay
requires platform.command.replay plus platform-operator. Cross-tenant reads
remain 404. No direct service gateway routes are generated.

## Private service contract and activation boundary

`contracts/platform/identity-services-adapter.v1.openapi.json` specifies the
service-owned endpoints, not routes mounted on Middleware. GET /health/ready
and GET /internal/v1/commands/{command_id} use connector.<service>.read;
POST /internal/v1/commands uses connector.<service>.command. The receiver
validates a short-lived service JWT using configured JWKS/issuer, exact service
ID audience, exp/nbf, the dedicated connector-<service> client run by the Middleware worker
or reconciler (read scope only for reconciler), scope and tenant binding. Never forward public
caller tokens. Require private network policy and mTLS at the service ingress.
No /internal or /metrics path may be exposed through public Caddy/Kong.

IdentityServiceAdapter is explicitly injected through the existing
build_platform_runtime(adapters=...) seam with a verified HTTPS origin and
worker-owned token supplier. It uses the RuntimeContainer shared HTTP client
(with private trust/mTLS configured by that runtime), never creates clients or
pools, never follows redirects, and does not resolve secrets in the API.
Manifests and catalog entries are desired state only, not live registration.
Existing production default_adapters remains empty. All four capabilities
remain false. Activation requires endpoint conformance, governed caller and
workload identity provisioning, mTLS evidence and the existing release gates.

## Durability and ambiguous outcomes

The existing command ledger reserves tenant + idempotency key and canonical
payload hash; atomic outbox admission and leased/fenced workers execute effects.
The service MUST atomically deduplicate tenant + idempotency key, bind it to
command ID/type/payload digest, return the existing handle for exact repeats,
and return 409 before effects for conflicts. 400/401/403/409/422 guarantee no
effect. All other uncertain replies, malformed acknowledgements, redirects,
429/5xx and timeouts after send are UNKNOWN and require reconciliation.

Readback by canonical command ID recovers a lost acknowledgement. MATCHED
requires completed state and matching tenant, command type/ID, idempotency key,
payload digest and operation handle. Pending/accepted are unavailable, never
completed. 404 is not proof that retransmission is safe. Reconciliation uses
the same readback. Existing worker attempt bounds, dead-letter state and audit
remain authoritative; services do not own Middleware replay. REPROCESS reads
back without effects; REEXECUTE is unsupported (safe_reexecution=false).
Provider cancellation is explicitly unsupported.

Existing kernel metrics record command, attempt, readback, reconciliation and
safety outcomes; correlation and W3C trace context propagate to the service.
Do not label telemetry with raw references, identities, JWTs or payloads.
Only an opaque operation ID and digest evidence enter adapter results.
Catalog metrics paths are private monitoring metadata, not ingress routes.
