# FACE-ID next five integration missions

Canonical authority remains **Caddy -> Kong -> Middleware V3 :8095 -> private
service API**. This change is source-only: no deployment, Keycloak mutation,
production effect, door unlock, SQL execution, or remote restore. No raw media,
embeddings, camera credentials, streams, or biometric templates enter Middleware.
The [service catalog](../../contracts/platform/identity-services.catalog.v1.json)
pins inspected source revisions and distinguishes implemented routes from proposed
private contracts. Source inspection is not live readiness or compatibility proof.

## 1. Access evaluation and decision readback

Submit `face-id.access.evaluate.v1` through `POST /platform/v1/commands` with
`tenant_id` in the canonical envelope and this payload:

```json
{"subject_ref":"subject-1","zone_ref":"zone-1","occurred_at":"2026-09-24T12:00:00Z","visitor_pass_ref":"pass-1"}
```

`visitor_pass_ref` may be omitted. Subject and zone are required opaque references;
`occurred_at` must be an RFC 3339 timestamp with offset. Capability is
`FACE_ID_ACCESS_EVALUATE`; both `platform.command` and `face-id.access.evaluate`
scopes are required, together with registered caller prefix/target authority.
The tenant and actor must match verified Keycloak claims.

The private `GET /internal/v1/commands/{command_id}` contract returns the bound
command state and, when completed, a closed decision result: decision reference,
allow/deny/indeterminate, optional policy reference, evaluation timestamp, and
`door_effect=false`. A completed command means evaluation completed; it does not
mean access allowed. No door provider, unlock command, or actuator is introduced.
The public operation and timeline endpoints expose status and evidence digest;
they do not export service business data or imply an access grant.

## 2. Presence events

Commands `face-id.presence.enter.v1` and `face-id.presence.exit.v1` use capability
`FACE_ID_PRESENCE_EVENT`, scope `face-id.presence.write`, and exactly four payload
fields: `event_ref`, `camera_ref`, `zone_ref`, `subject_ref`. Direction is encoded
in the command name. No arbitrary metadata or raw data is accepted.

The canonical idempotency key MUST be `presence:<event_ref>`; uniqueness is
scoped by tenant. The ledger atomically binds caller, type and payload digest,
reserves one outbox intent, and returns the original operation on an exact retry.
Changing direction, subject, camera or zone under that key is a conflict.
Services must also atomically deduplicate tenant + event_ref. The service resolves
references within the authenticated tenant and must reject foreign references.
The service owns occupancy ordering and records event time; this projection does
not accept caller timestamps or retroactively rewrite presence history.

## 3. Governed PTZ

`camera-gateway.ptz.move.v1` requires `camera_ref`, normalized absolute `pan` and `tilt` in [-1, 1], `zoom` in [0, 1],
and integer `duration_ms` in [100, 2000].
`camera-gateway.ptz.stop.v1` accepts only `camera_ref`. Both require `CAMERA_PTZ`
and scope `camera-gateway.ptz.control`. Per-camera PTZ support and authorization
must be checked by the receiver before motion; unsupported devices reject before
any effect. No device URL, password, ONVIF XML or arbitrary camera action is accepted.

Production capabilities are false, provider kill switches remain true, gates
permit staging only, and default runtime adapters remain empty. Before any
future activation the receiver must demonstrate a local watchdog that stops on
duration expiry, lost connection/worker/lease, or kill switch. The watchdog is
independent of Middleware availability and stops existing motion even if new
commands are disabled. Explicit stop is an idempotent command; cancel is not a
stop command. Never rely on a queued stop as the sole failsafe.

Both move and stop reach completed only after readback confirms `motion_state:
stopped` for the same camera. Timeout, missing stop proof, uncertain acknowledgement,
429/5xx, or redirects remain unknown/unavailable and require reconciliation.
No blind retransmission or safe reexecution of an ambiguous move is allowed.

## 4. Backup and recovery evidence

The catalog and private OpenAPI define four fixed GET-only projections below
`/internal/v1/observability/<name>/{database_ref}`:

| Name | Evidence checks |
|---|---|
| backup-catalog | catalog availability, encryption, verified offsite copy |
| restore-rehearsal | isolated target, verified restore, application validation |
| tls-security | required TLS, valid certificate, verified least privilege |
| replication-recovery | replication health, recovery rehearsal, RPO and RTO |

Responses contain tenant/database references, observation time, bounded evidence
references, status and nullable boolean checks. `ready` requires every check true
and at least one evidence reference; missing evidence is unknown, never healthy.
A matched readback proves a valid tenant-bound observation, not operational
readiness. Consumers must assess status and age against deployment-specific SLOs.
Backup evidence references identify catalog records; they never expose file paths,
DSNs, keys, dump bytes, SQL, or restore credentials.

`IdentityServiceAdapter.read_observability` only selects these paths and obtains
`connector.postgresql.read` workload credentials. It rejects unknown paths,
foreign response tenants/databases and extra response fields. There is no public
proxy and no POST projection. PostgreSQL now implements native backup/rehearsal catalog and security/recovery
reads. The tenant-bound, sanitized projections remain proposed. Operator-run backup and isolated restore scripts in
the service repository do not authorize a remote production restore.

## 5. Multi-user and workload authorization

Keycloak alone issues identities/scopes. The
[authorization matrix](../../contracts/platform/face-id-authorization.v1.json)
declares clients; it creates none and contains no passwords. Public audience is
`middleware-api`, exact issuer is the existing Codestra realm, and existing
RS256/JWKS, expiry, client and tenant checks apply. Client IDs identify permission
profiles; a role string or forwarded user header grants no authority by itself.

| Client | Middleware authority |
|---|---|
| face-id-operator | verify, access evaluation, bounded PTZ; operation reads |
| face-id-reviewer | operation/timeline reads; no command writes |
| face-id-enrollment | operation/timeline reads; raw enrollment remains service-owned |
| face-id-security-admin | operation/timeline reads; no Keycloak, SQL or restore mutations |
| face-id-service | presence enter/exit; operation reads |

All read scopes remain tenant-bound; these profiles do not introduce field-level
redaction between users in the same tenant. Existing operation views contain no
raw payload or business result. Enrollment, review-queue mutation and security
administration need separately governed reference-only contracts before admission.
No generic service prefix is granted to these clients. Registered authority and
token scopes must both permit the action; operation replay retains its existing
platform-operator role requirement and these clients are not granted replay scope.

Worker tokens use exact service audiences `face-id`, `face-liveness`,
`camera-gateway`, or `postgresql`, client `connector-<service>`, tenant binding and
`connector.<service>.command` or `.read`. Readback/reconciliation uses read scope.
Never forward the caller bearer token to a service. Each receiver must validate
signature, issuer, audience, azp, bounded lifetime, scope and tenant, with mTLS
and private network restrictions. Existing service-local auth is not proof of
conformance to that receiver contract.

## Reconciliation of implemented service routes

Inspected branch: `mission/face-id-middleware-integration-20260924`, 2026-09-24.

| Service | Pinned revision | Readiness |
|---|---|---|
| FACE-ID | da213fdbdc301f6892bb276e9b715b4875d17d5a | GET /health/ready |
| Face-Liveness | e664aa4fe1153d59dd7a468b768e7bd0d10b92f8 | GET /health/ready |
| Camera-Gateway | 0dfa3c0c31c213a5d9518d0cbdc24eb11513455d | GET /health/ready |
| PostgreSQL | 172b65f47820d5623e327bc35c3aa4a75098e624 | GET /health/ready |

FACE-ID missions 21–25 appeared during implementation and were re-inspected:

- 21: POST `/v1/access/evaluate` is decision-only. It uses `zone_id` and optional
  `visitor_pass_id`, corresponding to our `zone_ref` and `visitor_pass_ref`.
- 22: POST `/v1/presence/events`, GET `/v1/presence/current` and `/history` exist.
  The service uses `camera_id`, `zone_id` and a `direction` field. Its event_ref
  uniqueness is service-global, so it is not yet tenant-contract compatible.
- 23: unknown-cluster CRUD and event membership routes exist. Clusters explicitly
  assert no identity and grant no access.
- 24: camera-zone CRUD exists; metadata mapping is separate from camera PTZ.
- 25: review queues and items support CRUD/assignment. `assignee_ref` is an opaque
  Keycloak-side reference and does not authorize the request.

Full methods, parameterized paths, field correspondence and compatibility gaps
are machine-readable in the catalog. These native routes are not mounted on
Middleware and are not silently substituted for `/internal/v1/commands`. They lack
canonical tenant isolation, workload identity and command-ID readback. Activation
requires service-owned implementation and conformance evidence. Camera-Gateway now implements GET
`/v1/cameras/{camera_id}/ptz` and private POST
`/v1/internal/cameras/{camera_id}/ptz/commands`. The catalog maps our move to
`action=absolute`, command ID to `command_ref`, and milliseconds to seconds.
Our bounds are a conservative subset of its native contract. Native command_ref
reservations prevent repeated motion but offer no canonical readback; Stop
acknowledgement is not verified physical stopped state, and its finally block
cannot guarantee Stop on process death/network loss. These remain activation gaps.
No service-local PTZ endpoint is substituted into the worker transport.

PostgreSQL now implements GET `/v1/backups`, `/v1/backups/{backup_id}`,
`/v1/rehearsals`, `/v1/rehearsals/{rehearsal_id}`,
`/v1/postgresql/connections`, `/v1/postgresql/security`, and
`/v1/postgresql/recovery`, in addition to status and capabilities. These are
instance-wide operational metadata, not tenant-bound reference projections.
The catalog maps all four projections to their native evidence sources; no
arbitrary SQL or remote restore exists in this integration. No `/metrics`,
`/internal`, or `/v1/internal` route is generated for public Caddy/Kong ingress.

## Verification

Focused tests cover closed schemas, PTZ bounds, timestamp validation, idempotent
outbox delivery, bound readback, signed-token audience/client/scope failures,
all five client profiles, cross-tenant reads/actions, and evidence sanitization.
Run `python scripts/validate_identity_missions.py` alongside the existing connector,
registry, control-plane, OpenAPI and integration-fabric validators. The execution
record is in [the verification report](../../reports/face-id-missions-v3-20260924.md).
