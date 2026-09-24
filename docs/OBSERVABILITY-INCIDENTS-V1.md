# Observability incident authority v1

## Purpose and status

This document defines the repository-side contract for durable observability
incidents. It does not assert that the API, migration, identity clients, private
route, or delivery capability are deployed. Source merge, immutable release,
staging verification, and a separately authorized server mission remain required.

## Trust and exposure boundary

The service is private. The Compose authority publishes no host port and joins
only named backend/private networks. A future ingress must enforce TLS and the
approved network boundary. Application authorization always runs after transport
controls:

| Caller | Audience | Write scope | Read scope | Authority |
| --- | --- | --- | --- | --- |
| `alertmanager` | `middleware-api` | `alerts.write` | `alerts.read` | alert transitions and authenticated status snapshots |
| `observability-operator` | `middleware-api` | `observability.incidents.write` | `observability.incidents.read` | incident reads and lifecycle mutations; no connector commands |
| `klyrow-alert-adapter` | `middleware-api` | `observability.alerts.events.write` | `observability.alerts.read` | provider read-back delivery events |

Every authenticated request is tenant-scoped to `codestra-platform`. Mutations
require a correlation ID and a bounded `Idempotency-Key`. Alertmanager source
requests also require a bounded `X-Source-Deployment`, and status payloads must
repeat exactly the same deployment identity. Tokens, headers, payload bodies,
email content, and secret material are never metric labels.

## State and delivery model

The canonical incident states are `firing`, `acknowledged`, `resolved`,
`inhibited`, and `silenced`. A new firing transition creates an incident; only a
firing transition with a later `startsAt` may reopen an occurrence that has
persisted resolved `endsAt` evidence. A delayed firing webhook with the same
`startsAt` is rejected before replay or projection mutation. Operators may
acknowledge an active or
suppressed incident, resolve an unresolved incident, and reopen only a resolved
incident. Every operator mutation uses optimistic `expected_version` concurrency.
Stale versions and changed semantic content under the same idempotency identity
return `409`.

Incident identity is stable per tenant and Alertmanager fingerprint. Transition
identity is stable across transport retries and includes group key, fingerprint,
state, and start time. The HTTP idempotency identity is stored separately. Either
identity replays the original result only when its canonical payload digest
matches; changed content fails closed.

Alertmanager webhook state does not reliably encode inhibited and silenced
evidence. Therefore `/v1/integrations/alertmanager/status-events` is a separate,
authenticated desired-state source. It records bounded silence/inhibition IDs and
the source observation time in the immutable timeline. The observation time is
part of the semantic idempotency digest. Status cycles such as firing to silenced
to firing are retained, while observations at or before the latest persisted
status evidence fail closed with `409` and cannot overwrite current state.
Status evidence must also carry the exact `startsAt` of the incident's current
occurrence, so a delayed snapshot cannot suppress a later recurrence. For a
resolved occurrence, its persisted `endsAt` is also ordering evidence: a status
snapshot observed at or before that instant cannot reopen the incident. A
webhook transition whose `startsAt` predates the persisted occurrence is also
rejected before replay or projection mutation, so a delayed resolved or firing
webhook cannot replace a newer recurrence. A firing webhook whose `startsAt`
equals an already-ended occurrence is likewise stale and cannot erase its
resolved evidence. A firing status observation strictly newer than the
persisted `endsAt` is authoritative reopening evidence: it clears the terminal
`endsAt` before a matching same-occurrence webhook is accepted, including when
operator acknowledgement keeps the visible projection `acknowledged` while the
authoritative source state returns to firing. PostgreSQL and
in-memory operator reopen mutations clear the same terminal `endsAt`
evidence before returning the firing projection, so an explicitly authorized
reopen cannot leave later matching delivery transitions permanently blocked.
PostgreSQL status events retain the
original sanitized response projection; retrying an older status request after
a newer status has applied therefore returns the original result without
rewinding the current projection. A multi-item snapshot returns explicit
per-item results and HTTP `207` when only
part of the snapshot applies; single-item conflicts retain their canonical
error status.

Notification policy is deterministic: critical/high are immediate, warning is
grouped after 300 seconds with a 14,400-second repeat contract, and info is
state-only. A warning repeat is eligible only after the latest persisted
notification schedule plus the repeat interval. Before that boundary the new
transport identity is durably recorded as `notification_suppressed`; after it, a
deterministic `notification_repeat` command, intent, timeline event, and audit
entry commit atomically. Replaying either transport identity returns its original
decision, including whether a grouped notification is still scheduled or was
queued immediately as a repeat. Suppression events derive that decision from the
referenced notification operation's durable repeat event, so later replay cannot
change `queued` back to `scheduled`. When
the current projection is resolved, acknowledged, inhibited, or silenced, a
delayed firing transport cannot activate or repeat a warning notification.
Status suppression/resolution and operator resolution cancel any still-pending
group-wait command and outbox record in the same transaction. Delivery remains
disabled by default. When
enabled later, a firing incident that was previously recorded without a delivery
intent is atomically given its first governed
`observability.alert.email.send.v1` command, command audit/outbox, notification
intent, a `firing` timeline event with an `activated_transition` identity, and a
`notification_activated` audit record. Grouped warnings start their group wait
at activation; immediate severities queue immediately.
The provider adapter still
requires read-back before authoritative completion. No direct SMTP path exists.
If a warning resolves while its grouped notification is still waiting, the same
transaction cancels the pending firing command and outbox record before creating
the resolved intent. This prevents a stale firing notification from being
dispatched after resolution while preserving cancellation audit evidence.

## Persistence and atomicity

Migration `0009_observability_incidents` creates:

- `middleware_observability_incidents`, the current tenant-scoped projection;
- `middleware_observability_incident_events`, an immutable ordered timeline;
- `middleware_observability_incident_audit`, immutable actor/state evidence;
- `middleware_observability_notification_intents`, linked by foreign key to both
  its incident and durable command;
- `middleware_observability_incident_mutations`, immutable replay evidence.

The PostgreSQL store takes a transaction-scoped advisory lock on tenant and
fingerprint. Incident projection, transition event, audit, command, outbox, and
notification intent commit together. A command conflict rolls the entire incident
transaction back. Readiness fails closed unless migration head 9, all incident
tables, required unique keys, and all immutability triggers are present.

No runtime performs automatic schema creation. The disposable PostgreSQL CI job
applies the numbered migrations and proves atomic commit, semantic replay,
conflict rollback, lifecycle persistence, Alertmanager status evidence,
foreign-key linkage, and immutable event enforcement.

## Failure and reconciliation

An accepted incident may have no notification because delivery is disabled or its
severity is state-only; this is an explicit status, not an unknown condition.
When a notification exists, the incident notification-attempt route joins the
intent to the durable command and attempt history. Unknown provider outcomes use
the existing command `reconciliation_required` state and cannot be represented as
success. Operators can inspect evidence, while delivery recovery remains governed
by the command operation APIs and adapter read-back contract.

## Migration, backup, and rollback

A later deployment must back up and checksum PostgreSQL before applying migration
0009, apply migrations through the exact release schema head, and pass readiness
before routing traffic. Restore evidence must use isolated temporary resources;
live data must never be destroyed for a test.

Normal application rollback keeps schema 0009 and redeploys the recorded previous
immutable image digest. The rollback candidate must pass the same-start
resolved-then-delayed-firing denial, newer-status-then-webhook reopening, and
acknowledged-status/operator-reopen-then-webhook tests for both memory and
PostgreSQL stores;
an image that can erase persisted `endsAt` evidence is not an eligible rollback
target. Schema rollback is offline and destructive to incident
evidence. It requires independent approval, stopped writers, exports and checksums
for all five tables, isolated restore/read validation, and the reviewed script
`migrations/rollback/0009_observability_incidents.down.sql`.
