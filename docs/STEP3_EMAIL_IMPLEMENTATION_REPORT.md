# Step 3 Email Implementation Report

Date: 2026-08-30

## Authority

Frozen SDK contract:

`appolon1908-hue/SDK-repository:feat/communications-api-v1-contracts@63c793e88cca5daecfb5c8a688b8674ab288c522`

Middleware branch:

`feat/communications-api-v1-email-runtime`

Klyrow provider branch:

`appolon1908-hue/klyrow.com:feat/communications-api-v1-email-provider@15b14b63d2f17a74091702d9f6ddc5787237e317`

## Scope Implemented

Middleware now exposes the email subset of Communications API v1:

- `POST /v1/communications/messages`
- `GET /v1/communications/messages`
- `GET /v1/communications/messages/{messageId}`
- `GET /v1/communications/messages/{messageId}/events`
- `POST /v1/communications/messages/{messageId}/cancel`
- `GET /v1/communications/providers/health`
- `GET /v1/communications/reputation`
- `GET /v1/communications/usage`

The runtime maps `channel=email` requests to `email.message.send.v1` commands targeting `klyrow-email`, preserving tenant, actor, bearer authorization, scopes, correlation ID, and idempotency key. It maintains the canonical message read model and event timeline and updates that read model from signed Klyrow provider events accepted through the existing webhook ingress path.

Command-ledger state is reconciled into the canonical message model. An uncertain provider outcome becomes `indeterminate`; it is never represented as success and the Temporal command workflow does not automatically retry it. Exact create replays reuse the original command, while signed provider callback replays are deduplicated without duplicating timeline effects.

The unknown-outcome path now has explicit deterministic reconciliation evidence: the provider execution activity runs once, the command enters `reconciliation_required`, and a separate bounded reconciliation workflow performs authoritative read-back attempts using the original operation identity. The fixture succeeds after two transient read-back failures and proves the execution count remains one. Reconciliation does not resubmit the email.

## Step 3 Completion Boundary

The email control-plane mapping, contract validation, fail-closed capability gate, tenant isolation, idempotency, uncertain-outcome quarantine, command read-back state mapping, signed callback/replay behavior, bounded reconciliation read-back, and no-resubmission rule are implemented and covered by automated tests.

Step 3 source completion requires:

1. Middleware exact source-head CI green;
2. Middleware exact merge-result CI green;
3. runtime and test images construct successfully;
4. disposable PostgreSQL/Redis, NATS, Temporal, and no-effect E2E green;
5. Klyrow provider CI green at its pinned head;
6. final exact SHAs and run IDs posted to both PRs;
7. production delivery and provider credentials remain disabled.

The authoritative final Middleware run is the GitHub check set attached to PR #52 after the reconciliation-evidence commit completes.

## Safety Boundary

This branch does not enable live email delivery, Postal, Mautic, Keycloak, Kong, Caddy, n8n, Odoo, production DNS, or provider write flags.

## Known Production Follow-Up

The current Step 3 runtime uses an in-memory Communications read store even when command storage is Postgres-backed. Before production activation, this read model and its provider-event deduplication index must be backed by durable storage with migration and rollback coverage.

The production Klyrow adapter and `reconcile_operation` activity must be bound to the reviewed Klyrow private message lookup through OAuth2 plus mTLS, and the same no-resubmission scenario must pass against isolated staging. These are production-readiness gates; they do not block source completion or the start of source-only SMS work after Step 3's final CI and evidence gates pass.
