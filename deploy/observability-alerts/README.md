# Middleware observability-alert service

This deployment is a narrow API/worker binding built from the canonical Middleware image. It belongs on the core application host (`65.109.65.169`), not on the provider host. Alertmanager on `37.27.128.39` reaches it over the approved private network; the Middleware worker then reaches the Klyrow email API over mTLS.

The production request path is:

```text
Prometheus -> Alertmanager -> Middleware alert API -> durable command/outbox
           -> Temporal command worker -> Klyrow alert adapter -> Klyrow API
           -> alerts@codestra.co -> appolon1908@gmail.com
```

This repository defines desired state only. `observability-alert-api` has no
published host port. A separately reviewed private ingress must terminate TLS,
authenticate the approved source network, and forward only to the
`observability_ingress` network. The API then requires Keycloak service identity,
tenant, scope, correlation ID, transport idempotency key, and
`X-Source-Deployment`; network reachability alone never authorizes a request.

## Durable incident lifecycle

Apply numbered migrations through the canonical head
`0069_agent_provisioning_rls` before starting this service (the
incident lifecycle tables were introduced in `0059_integrated_monitoring`). One PostgreSQL transaction records the incident projection,
immutable timeline event, immutable audit evidence, durable command/outbox, and
notification intent. Alert transition identity is derived from Alertmanager's
group key, fingerprint, state, and start time. It is independent of the HTTP
`Idempotency-Key`, while both identities are persisted and conflict checked.

The authenticated API surface is documented in
`contracts/observability/alert-api.v1.openapi.yaml`. Alertmanager submits webhook
transitions and a separate authenticated status snapshot for inhibited/silenced
state. Operators use the separate `observability-operator` client and bounded
incident list, detail, timeline, notification-attempt, acknowledge, resolve, and
reopen routes. The operator identity has no connector-command authority.

Severity behavior is source-controlled in
`config/observability-alert-policy.v1.json`:

- `critical` and `high`: immediate durable notification intent;
- `warning`: grouped with a five-minute wait and four-hour repeat contract;
- `info`: state and audit only, with no notification operation.

The checked-in default remains delivery disabled. When disabled, alert and
incident state is still durable but no email command is created.

`OBSERVABILITY_ALERT_EMAIL_DELIVERY` is independent from general customer, campaign, and bulk delivery. The following must remain false for the initial alert-only activation:

```text
LIVE_EMAIL_DELIVERY=false
ENABLE_EXTERNAL_DELIVERY=false
EMAIL_DELIVERY_ENABLED=false
```

The Compose file is source authority only. It requires an exact immutable Middleware image, a protected source SHA, and secret files rendered by OpenBao. Do not deploy from this branch. Production installation requires protected merge, signed image, staging certification, backup, rollback, and a separate activation record.

## Future installation and rollback gates

Before a later server mission may install this desired state, it must verify the
protected merge SHA, signed immutable OCI digest, SBOM/provenance attestations,
configuration checksum, migration backup, private TLS route, Keycloak desired
state, `/health`, `/readiness`, and a no-effect incident ingestion test. It must
not enable provider delivery during configuration validation.

Rollback is forward-compatible by default: deploy the previous immutable image
while retaining migration 0009 and its evidence tables. Removing the schema is an
offline, independently approved last resort. If that is authorized, first stop
all writers, export and checksum every incident table, prove the export can be
read in an isolated disposable database, then execute
`migrations/rollback/0009_observability_incidents.down.sql`. Never run the
rollback against a live writer or without retained evidence.


## Recipient cutover procedure

Before deploying a recipient-policy change, query the durable command ledger for non-terminal `observability.alert.email.send.v1` commands containing the prior recipient. The deploy gate must stop if any are queued but not submitted. Reissue those alerts as new commands with new idempotency identities and the active fixed-recipient policy.

The adapter accepts the retired recipient only during provider read-back. It never submits or resubmits a legacy-recipient payload. A legacy command with no matching provider record fails closed with `controlled reissue` instead of silently dropping the alert or sending to the retired inbox.
