# Codestra Connector SDK v1

## Purpose

The Connector SDK turns the Codestra Integration Fabric into a repeatable connector platform. A new software product is onboarded with:

1. one secret-free connector manifest;
2. one trusted adapter implementation;
3. versioned command and event contracts;
4. a protected Keycloak client/scope declaration;
5. generated Kong route and webhook policy;
6. an inactive n8n workflow pack;
7. contract, negative, replay, tenant, and no-effect staging tests.

Existing Integration Fabric v2 files are not modified by this workstream. This branch is an additive child of `architecture/codestra-integration-fabric-v2`.

## Security boundary

```text
Caddy -> Kong -> Middleware Connector SDK -> trusted adapter -> product
                                 |
                                 +-> durable inbox/outbox/event ledger
                                 +-> n8n orchestration through Middleware only
```

The connector manifest is data, not executable code. It cannot name or import a Python module. Application bootstrap code explicitly registers a trusted adapter factory for a previously validated connector ID.

The manifest cannot contain passwords, access or refresh tokens, OAuth client secrets, private keys, provider tokens, or webhook secret values. It contains external secret aliases only.

## Package layout

```text
middleware/connector_sdk/
  models.py       immutable manifest/runtime types
  manifest.py     fail-closed parser and canonical digest
  registry.py     connector and trusted adapter registry
  interfaces.py   adapter, secret, replay and capability protocols
  runtime.py      command/capability/read-back enforcement
  webhooks.py     raw-body HMAC and replay protection
  catalog.py      framework-neutral connector catalog service
  generation.py   deterministic Kong/Keycloak/n8n/command artifacts

contracts/connectors/
  connector-manifest.v1.schema.json
  connector-management-api.v1.yaml
  connector-storage.v1.sql

connectors/manifests/
  one *.connector.json per current integration
```

## Adapter interface

Each trusted adapter implements:

```python
validate_configuration(manifest, configuration)
test_connection(manifest, configuration)
execute_command(request)
read_back(request, prior_result)
normalize_webhook(verified_webhook)
reconcile_unknown(request, prior_result)
health()
compensate(request, prior_result)  # optional
```

A command is not submitted until Middleware has established authenticated machine identity, tenant and actor authority, command ownership, connector state, required capability, semantic idempotency, workflow/job authorization, and a valid payload contract.

An `UNKNOWN` provider outcome is reconciled before any resubmission. `readback_required=true` prevents success without authoritative destination read-back.

## Manifest lifecycle

```text
DECLARED
  -> VALIDATED
  -> INSTALLED_DISABLED
  -> ACTIVE
  -> SUSPENDED

Any state -> FAILED
```

Installation is disabled-first. Activation is intentionally not exposed as a normal connector-management endpoint. It requires the Integration Fabric release/canary process.

## Webhook contract

The SDK verifies the exact raw body using:

```text
HMAC-SHA256(secret, "<unix_timestamp>.<raw_body>")
```

Required policy is declared per endpoint: signature header, timestamp header, event-ID header, maximum clock skew, maximum body size, acknowledgement deadline, secret reference, and route path.

The durable replay key is `connector_id:endpoint_key:event_id`; the atomic replay store also records `sha256(raw_body)`. An identical key and body is an exact replay. Reuse of the key with a different body is a semantic conflict. Production persists the verified inbox record before returning `202`.

## Management API

`connector-management-api.v1.yaml` adds:

```text
GET  /v1/connectors
POST /v1/connectors/validate
POST /v1/connectors/install
GET  /v1/connectors/{connector_id}
GET  /v1/connectors/{connector_id}/manifest
POST /v1/connectors/{connector_id}/test
POST /v1/connectors/{connector_id}/upgrade
POST /v1/connectors/{connector_id}/disable
GET  /v1/connectors/{connector_id}/health

GET/POST /v1/integrations/connections/{connection_id}/webhooks
GET/PATCH/DELETE /v1/webhooks/{webhook_id}
POST /v1/webhooks/{webhook_id}/test
POST /v1/webhooks/{webhook_id}/rotate-secret
GET  /v1/webhooks/{webhook_id}/deliveries
GET  /v1/webhook-deliveries/{delivery_id}
POST /v1/webhook-deliveries/{delivery_id}/replay-request

POST /v1/webhooks/{connector_id}/{endpoint_key}
```

There is deliberately no public generic connector-command proxy. Domain APIs continue to own customer-facing operations.

## Adding a new connector

1. Run `scripts/scaffold_connector.py` with a connector ID, repository, command prefix, capability, workflow family, event type, and optional webhook endpoint key.
2. Review the generated disabled-first manifest.
3. Implement `ConnectorAdapter` in a dedicated product adapter branch.
4. Register its adapter factory explicitly in trusted application bootstrap code.
5. Run `scripts/generate_connector_artifacts.py` and review the generated Kong, Keycloak, n8n, and command-registry desired state.
6. Run `scripts/validate_connector_sdk.py`.
7. Run `python -m unittest tests.test_connector_sdk_v1`.
8. Add Keycloak desired-state apply and Kong route deployment in separate PRs.
9. Import n8n workflows inactive into isolated staging.
10. Prove no direct provider/database access, duplicate safety, conflict handling, replay protection, unknown-outcome reconciliation, tenant isolation, backup, and rollback.
11. Activate through a separately approved bounded canary.

## Current source-only state

```text
CONNECTOR_MANIFESTS=8
RUNTIME_BINDINGS=UNVERIFIED_TEMPLATE_ONLY
CONNECTORS_ENABLED_BY_DEFAULT=NO
DIRECT_N8N_ACCESS=NO
LIVE_SECRETS_IN_GIT=NO
CONNECTOR_INSTALL=false
CONNECTOR_UPGRADE=false
CONNECTOR_DISABLE=false
WEBHOOK_SECRET_ROTATION=false
WEBHOOK_REPLAY_REQUEST=false
PROVISIONING_WRITE=false
LIVE_SERVER_CHANGED=NO
PRODUCTION_DEPLOYED=NO
```
