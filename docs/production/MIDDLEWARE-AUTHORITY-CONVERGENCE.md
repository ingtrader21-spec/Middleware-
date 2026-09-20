# Server A Middleware authority convergence

> **Status (2026-09-20):** the canonical Alembic head is now
> `0067_service_catalog_monitoring_state` (`config/middleware-forward-release-authority.v1.json`,
> `.github/workflows/release.yml`). References to `0057_platform_service_catalog` below
> describe the signed evidence generation of 2026-09-08 and are retained as history; they
> are not the current forward release or runtime requirement.

## Decision

Protected `main` in `ingtrader21-spec/Middleware-` is the **only forward source**
authority. Every future Middleware image admitted to staging or production must
be built by `.github/workflows/release.yml` from the exact protected-main event
SHA, must carry schema head `0057_platform_service_catalog`, and must be addressed by an
immutable GHCR digest.

The machine-readable current authority is:

```text
config/middleware-forward-release-authority.v1.json
```

The dated Server A inventory is:

```text
config/middleware-authority-convergence.v1.json
```

These files have intentionally different roles. The current authority controls
future release admission. The convergence file records the 31 workloads and 16
image families observed on Server A on September 1, 2026. Its embedded signed
image was current only when that snapshot was captured; it is now a **historical
predecessor** and is not a current candidate.

`Codestra-SRL/codestra-middleware` and every image derived from it remain
rollback-only source and image history. They are not deleted, force-pushed,
rebuilt as new forward releases, or allowed to expand their runtime footprint.

No file in this change authorizes a deployment, traffic change, provider call,
database write, queue consumption, container retirement, live communication, or
PSTN call.

## Current release state

```text
FORWARD_REPOSITORY=ingtrader21-spec/Middleware-
FORWARD_REF=refs/heads/main
SOURCE_RESOLUTION=EXACT_PROTECTED_MAIN_EVENT_SHA
STATIC_SHA_AUTHORITY=NO
REQUIRED_SCHEMA_HEAD=0057_platform_service_catalog
SIGNED_CANDIDATE_STATUS=PENDING_EXACT_PROTECTED_MERGE_BUILD
CURRENT_SIGNED_CANDIDATE=NONE
PRODUCTION_DEPLOYED=NO
```

The current authority deliberately contains `currentSignedCandidate: null`.
That value must remain null until the eventual protected merge SHA is built by
the release workflow and the resulting image has verified provenance, SBOM,
signature, vulnerability evidence, release-manifest binding, and schema
`0057_platform_service_catalog`.

A repository commit cannot truthfully predict its own future squash-merge SHA or
image digest. Recording a fabricated candidate would weaken the exact-source
release gate. Therefore `PENDING_EXACT_PROTECTED_MERGE_BUILD` is the only valid
state at this stage.

Two later signed `0057_platform_service_catalog` bundles are recorded as
non-authoritative evidence: source `164969b4824fb4d2eb38b232bfb7abc18e33d8ac`
with digest `sha256:18017a1a40a7969495661446badd8b43d1d4153c2036d89b0fb3065469e27941`,
and its previous release source
`4668de7d7ddc6f98968c06b7dc02d7650ff5e88a` with digest
`sha256:41ae78d368b5e2db2e9fe9be50fd5041b3f1a07ae4837170a76a68889be565e6`.
Their signatures, provenance, SBOMs, and vulnerability reports pass independent
verification. The records are deliberately not promoted: the protected merge
created by this change must receive its own exact-head release, and recovery
and runtime certification remain separate gates.

## Historical signed predecessor

The following artifact remains valid evidence for the earlier release path, but
it predates the realtime-gateway migration and the authority convergence merge:

| Field | Historical value |
|---|---|
| Role | `historical-predecessor-only` |
| Promotion authorized | `false` |
| Source SHA | `b03b378f3a358de333e37cf6cc7a37668f004b4f` |
| Git tree | `8e9a4be456a2f82ef3352a277f6f76f1a2e18d90` |
| Image | `ghcr.io/appolon1908-hue/codestra-middleware@sha256:dfdcfb92538242df9c9e81c27f15f9bd14b2cb840ea4c16d91dccc8f0eed7a3c` |
| Release ID | `b03b378f3a35-dfdcfb925382` |
| Workflow run | `33908027409`, attempt `1` |
| Artifact ID | `9950295151` |
| Schema head | `0009_observability_incidents` |
| Verification | signed, SBOM present, vulnerability gate passed |

This artifact is retained for audit and rollback analysis only. It must not be
promoted as though it contains migration `0057_platform_service_catalog`, PR #140, this
correction, or any later protected merge.

The dated inventory still uses the field name `currentSignedCandidate` because
that was the snapshot schema when it was captured. The current validator treats
that object exclusively as the historical predecessor and requires byte-for-byte
identity with `historicalSignedPredecessor` in the current authority file. It
also requires `promotionAuthorized=false` and a null current candidate.

## Source and runtime truth

Repository source authority and runtime truth are separate facts.

Source authority is resolved dynamically from the exact protected-main GitHub
event SHA. Runtime truth exists only after
`.github/workflows/production-runtime-certification.yml`, under issue #118,
proves the same source, image digest, schema head, runtime profile, migration
state, effective capabilities, backups, isolated restore, rollback, and zero
live-effect counters.

A valid future candidate must satisfy all of the following:

1. exact protected-main source SHA;
2. exact source tree;
3. immutable image digest;
4. signed release manifest;
5. verified provenance and SBOM;
6. no fixable high or critical vulnerability under the protected policy;
7. schema head `0057_platform_service_catalog`;
8. locked runtime profile;
9. source/digest/schema/profile read-back from the candidate runtime;
10. backup, isolated restore, and rollback rehearsal evidence;
11. no movement in calls, email, SMS, social, provider, Odoo, n8n, payment, or
    other live-effect counters.

Until all evidence exists for the same immutable tuple, the candidate remains
pending and no runtime promotion is authorized.

## Comparison result

The original convergence review compared the then-current appolon source
`b03b378f3a358de333e37cf6cc7a37668f004b4f` with the historical anchor
`f3437709c06747249586598590145234ea2c7327`. It also compared legacy protected
main `167bd6221911ec3fa988d719eb259646fa90f296` with legacy anchor
`2f1c7af41f87c27e2881c3695621ece787b97445`.

That comparison remains useful historical evidence. It is not a live source
pointer. Protected main later advanced through migration
`0057_platform_service_catalog` and PR #140. Future release and certification workflows
must always resolve their exact event SHA rather than using either comparison
snapshot.

The appolon architecture now includes:

- authenticated `/api/v1` compatibility routes;
- quarantine list, detail, discard, and review controls;
- reconciliation list, detail, and resolution controls;
- signed intake plus durable inbox, outbox, command, and audit ledgers;
- Klyrow email/alert, Postly social, Telnexa SMS, and Odoo adapters;
- Temporal workflows, provider-control policy, idempotency, and read-back;
- exact source, digest, schema, runtime-profile, capability, SBOM, provenance,
  signature, and vulnerability evidence;
- the `0057_platform_service_catalog` migration and its realtime source authority.

The repositories remain divergent architectures, not byte-identical releases.
One appolon image cannot safely replace every legacy worker command. A blind
whole-fleet replacement could break entrypoints, double-consume queues, drift
schemas, lose unknown-outcome reconciliation, or enable unintended effects.

## What “synced” means

Middleware is synced when one canonical contract and release authority owns all
new development and each required legacy behavior is ported through an explicit,
tested boundary. It does not mean merging the old monolith wholesale.

The following component boundaries still require separate certification before
retirement:

- Asterisk/PJSIP connector parity;
- a Keycloak-validated short-lived webphone session issuer;
- Breero normalization, idempotency, and Odoo read-back parity;
- Kyqra/scraper cursor, replay, idempotency, and Odoo read-back parity;
- queue drain, replay-safe handoff, and unknown-outcome reconciliation;
- database restore, schema migration, route ownership, and rollback proof.

## Server A runtime finding

The September 1 inventory did not show two interchangeable Middleware images.
It showed one stale appolon API and multiple Codestra-SRL image families serving
different API and worker entrypoints.

The stale appolon runtime was:

```text
container=codestra-appolon-middleware-integration-api-1
source=f6748a58f8d2590520a4f28776770957061cdea1
image=ghcr.io/appolon1908-hue/codestra-middleware@sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820
```

Representative legacy APIs were:

```text
container=codestra-middleware-1
source=b3ca9aa458fef843e3065aeff3397c656349f138
image_id=sha256:5dd751a9da60e2417c9ee553ddea68f54e76981dcc896eb3676b27617d121f38

container=codestra-middleware-integration-api-1
source=35448ef85ae56db3651a72b61db8e242b7aacd2e
image=ghcr.io/codestra-srl/codestra-middleware@sha256:09d4bd0f7b2376e0a06d3efae27a6642429389fa7e3277791ec0b36584e87175
```

The complete record contains 31 Middleware workloads grouped into 16 image
families. PostgreSQL, Redis, and rehearsal-only objects remain separate from
Middleware forward image authority.

Server A has not been re-read during this repository correction. Every workload,
source SHA, image ID, command hash, Compose file, network, mount destination,
health state, readiness state, queue position, and schema state must be verified
again before any host mutation.

## Exact registry backups

Four legacy images have immutable Codestra-SRL GHCR manifest digests. The manual
workflow `.github/workflows/mirror-codestra-legacy-middleware-images.yml` copies
their manifests and layers without rebuilding them into:

```text
ghcr.io/appolon1908-hue/codestra-middleware-legacy
```

The workflow:

- runs only through `workflow_dispatch` from protected `main`;
- verifies the exact checkout SHA;
- requires exactly four reviewed mirror records;
- uses `skopeo --all --preserve-digests`;
- requires destination manifest and raw manifest identity;
- records `rebuilt=false`, `runtime_promoted=false`, and source retention;
- never contacts Server A.

Codestra-SRL GHCR is private. Repository secret `CODESTRA_GHCR_TOKEN` must have
`read:packages` access before dispatch. Optional secret `CODESTRA_GHCR_USER`
identifies the token owner. Missing or invalid source access fails closed; it is
not treated as a successful mirror.

## Server A local-image backups

Eleven image families are identified only by local Docker image IDs or local
tags. After Server A enrollment, the reviewed operator is:

```bash
sudo ./scripts/server-a-backup-legacy-middleware-images.sh status
sudo ./scripts/server-a-backup-legacy-middleware-images.sh archive
sudo ./scripts/server-a-backup-legacy-middleware-images.sh mirror
```

The operator requires root, validates the Server A address and catalog, fails on
missing workloads or image-ID drift, records no environment values or mount
source paths, creates root-only `docker image save` archives, verifies archive
structure and OCI config identity, cleans temporary tags, and verifies the final
checksum manifest.

Archive verification is not an isolated restore. A separate isolated
`docker load`, application startup, health/readiness, source/config read-back,
and rollback rehearsal remain mandatory before cutover.

None of the backup modes restarts or stops a container, edits Compose, changes
traffic, consumes a queue, or enables a provider.

## Protected completion order

1. Merge the authority correction through protected `main` with exact-head CI,
   resolved threads, and fresh independent approval.
2. Build and sign a new immutable image from that exact protected merge SHA.
3. Verify the release manifest reports schema `0057_platform_service_catalog` and the
   exact protected source/tree/image tuple.
4. Add `CODESTRA_GHCR_TOKEN` and run the protected-main legacy mirror workflow.
5. Enroll Server A and rerun the complete read-only inventory.
6. Archive all eleven local-only image families and verify the evidence checksum.
7. Create paired PostgreSQL, queue/state, configuration, and image backups and
   prove an isolated restore.
8. Admit the new appolon digest as an isolated read-only canary with every write,
   delivery, provider, crawler, social, email, SMS, Odoo, n8n, and PSTN control
   disabled.
9. Compare route contracts, auth/tenant decisions, data reads, latency,
   health/readiness, source/digest/schema/profile read-back, and zero-effect
   counters against the existing APIs.
10. Move only reviewed read-only route authority to the canary. Never start a
    second consumer for a legacy queue.
11. Rehearse rollback to each exact captured image/configuration tuple.
12. Retire duplicate APIs to stopped rollback-only state and migrate each worker
    through a separate protected release.

## Current execution status

```text
APPOLON_FORWARD_SOURCE_AUTHORITY=PROTECTED_MAIN_DYNAMIC
REQUIRED_SCHEMA_HEAD=0057_platform_service_catalog
SIGNED_CANDIDATE_STATUS=PENDING_EXACT_PROTECTED_MERGE_BUILD
CURRENT_SIGNED_CANDIDATE=NONE
HISTORICAL_PREDECESSOR_PROMOTION_AUTHORIZED=NO
LEGACY_RUNTIME_IMAGE_CATALOG=HISTORICAL_2026-09-01_SNAPSHOT
LEGACY_GHCR_MIRROR_WORKFLOW=PREPARED_MANUAL_PROTECTED_MAIN_ONLY
LEGACY_GHCR_MIRROR_EXECUTION=BLOCKED_CODESTRA_GHCR_TOKEN
LOCAL_IMAGE_BACKUP=BLOCKED_SERVER_A_ENROLLMENT
SERVER_A_RUNTIME_REVALIDATION=NOT_EXECUTED
ISOLATED_RESTORE=NOT_EXECUTED
APPOLON_CANARY=NOT_EXECUTED
ROUTE_CUTOVER=NOT_EXECUTED
LEGACY_CONTAINER_RETIREMENT=NOT_EXECUTED
PRODUCTION_CHANGED=NO
CALLS_PLACED=0
```

## Fail-closed boundary

```text
SOURCE_ONLY=YES
SERVER_A_CHANGED=NO
PRODUCTION_TRAFFIC_CHANGED=NO
DATABASE_MIGRATION_EXECUTED=NO
LEGACY_CONTAINER_STOPPED=NO
LEGACY_IMAGE_DELETED=NO
EXTERNAL_DELIVERY_ENABLED=NO
ODOO_WRITE=NO
N8N_DELIVERY=NO
LIVE_SMS=NO
LIVE_EMAIL=NO
LIVE_SOCIAL=NO
LIVE_PSTN=NO
PRODUCTION_DIALING=DISABLED
CALLS_PLACED=0
```

The WebSocket authority work is independent. This Middleware correction neither
bypasses nor resolves its reviewer, protected merge, or runtime-promotion gates.
