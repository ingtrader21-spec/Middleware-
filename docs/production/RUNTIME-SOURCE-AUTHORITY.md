# Middleware runtime source authority

> **Status (2026-09-20):** the canonical Alembic head is now
> `0069_agent_provisioning_rls` (`config/middleware-forward-release-authority.v1.json`,
> `.github/workflows/release.yml`). References to `0057_platform_service_catalog` below
> describe the signed evidence generation of 2026-09-08 and are retained as history; they
> are not the current forward release or runtime requirement.

## Canonical rule

The only forward-looking source authority is protected `main` in
`ingtrader21-spec/Middleware-`. A static SHA stored in repository metadata is not
an authority because it becomes stale as soon as another protected merge lands.
Every release or certification workflow must resolve the exact protected-main
GitHub event SHA and bind that immutable source to the release manifest, source
tree, image digest, provenance, SBOM, vulnerability evidence, migration head,
and runtime profile.

The only forward image repository is:

```text
ghcr.io/ingtrader21-spec/codestra-middleware
```

The pre-transfer package `ghcr.io/appolon1908-hue/codestra-middleware` holds the
historical signed digests and is never a forward publication target (see
`docs/RELEASE-SUPPLY-CHAIN.md`, "Repository identity versus registry namespace").

The current machine-readable authorities are:

```text
config/runtime-source-state.json
config/middleware-forward-release-authority.v1.json
```

`runtime-source-state.json` defines the dynamic source/runtime separation.
`middleware-forward-release-authority.v1.json` adds the exact release state for
the Server A convergence work. Neither file claims that a runtime is deployed or
certified.

## Current artifact state

The current source requires migration head:

```text
0058_campaign_design
```

The current signed candidate state is:

```text
PENDING_EXACT_PROTECTED_MERGE_BUILD
```

`currentSignedCandidate` is intentionally null. A repository branch cannot know
its eventual protected squash-merge SHA or immutable image digest in advance.
The field may be populated only by a separately reviewed evidence update after
the exact protected-main merge has been built, signed, scanned, and verified with
schema `0058_campaign_design`.

The authority record separately preserves two verified, non-authoritative
`0057_platform_service_catalog` bundles. `latestVerifiedSignedEvidence` binds
source `164969b4824fb4d2eb38b232bfb7abc18e33d8ac` to immutable image digest
`sha256:18017a1a40a7969495661446badd8b43d1d4153c2036d89b0fb3065469e27941`;
`previousVerifiedSignedEvidence` binds source
`4668de7d7ddc6f98968c06b7dc02d7650ff5e88a` to digest
`sha256:41ae78d368b5e2db2e9fe9be50fd5041b3f1a07ae4837170a76a68889be565e6`.
Both manifests, image signatures, SLSA attestations, SPDX SBOMs, and scan
reports were independently verified. Both records retain
`promotionAuthorized=false`; neither replaces exact protected-head resolution
or runtime recovery evidence.

The prior signed image from source
`b03b378f3a358de333e37cf6cc7a37668f004b4f` and digest
`sha256:dfdcfb92538242df9c9e81c27f15f9bd14b2cb840ea4c16d91dccc8f0eed7a3c`
remains a **historical predecessor**. It carries schema
`0009_observability_incidents`, predates migration `0057_platform_service_catalog`, and
has `promotionAuthorized=false`. It is useful for audit and rollback analysis,
but it is not a current release candidate.

## Runtime truth

Repository source and runtime state are separate facts. Runtime truth exists only
when `.github/workflows/production-runtime-certification.yml`, under issue #118,
produces and verifies evidence for the same exact signed candidate. That evidence
must include:

- exact source SHA and source tree;
- immutable image digest and verified provenance;
- signed release manifest and SBOM;
- schema head `0058_campaign_design`;
- locked runtime profile;
- effective source/digest/schema/profile and capability read-back;
- backup and isolated restore;
- rollback rehearsal and data integrity;
- zero external-effect movement.

The signed release path is:

1. `.github/workflows/release.yml` — build, scan, sign, and bind the release
   manifest to exact protected source;
2. `.github/workflows/automated-production-promotion.yml` — admit only that exact
   signed candidate without enabling business effects;
3. `.github/workflows/production-runtime-certification.yml` — run the restricted,
   internal-only read-only canary and collect immutable runtime evidence.

The manifest schema is `contracts/release-manifest.v1.schema.json`; locked runtime
profiles are registered in `config/runtime-profiles.v1.json`.

## Codestra-SRL rollback authority

`Codestra-SRL/codestra-middleware` is no longer a forward development or release
authority. Its Git history and every currently observed Server A image derived
from it are rollback-only evidence. They must not be deleted, rebuilt as new
forward releases, force-pushed, or used to expand the runtime fleet.

The per-image-family record is:

```text
config/middleware-authority-convergence.v1.json
```

That file is a dated September 1, 2026 Server A inventory snapshot, not current
release authority. Its embedded `currentSignedCandidate` name is interpreted only
within the historical snapshot. The current validator requires that object to
match the non-promotable `historicalSignedPredecessor` in the current authority
file and separately requires a null current candidate pending a new exact-main
build.

The inventory distinguishes registry manifest digests from Server A-only Docker
image IDs. Registry-addressable Codestra-SRL images are copied without rebuilding
to `ghcr.io/appolon1908-hue/codestra-middleware-legacy`; local-only images require
host-side archive and OCI-config-digest evidence. Neither backup path changes a
container, Compose project, route, queue, database, or provider capability.

The appolon image and legacy worker images are not byte-identical. Consequently,
a WebSocket-style namespace-only substitution is invalid for the Middleware
fleet. The stale appolon API may be replaced only by a newly signed appolon
read-only canary after exact evidence. Legacy APIs and workers must be retired one
family at a time after command, route, data, queue, idempotency, unknown-outcome,
health, readiness, and rollback parity are certified.

See `docs/production/MIDDLEWARE-AUTHORITY-CONVERGENCE.md` for the protected order
of operations and the historical inventory boundaries.

## Historical evidence

`MIDDLEWARE-AUTHORITY-RECONCILIATION.yaml`,
`config/middleware-authority-convergence.v1.json`, and
`docs/SERVER-RUNTIME-RECONCILIATION-MAP.md` are observed snapshots. Their pinned
SHAs, image digests, container counts, or comparison classifications must never
be used as permanent source authority or proof of current runtime state.

Before any host change, all observed values must be re-read from Server A and
matched to a newly signed candidate for the exact protected-main merge and to the
retained rollback evidence.

## Fail-closed boundary

This authority declaration does not approve a deployment, public route, provider
binding, credential, production write, Odoo/n8n effect, email, SMS, social
publication, crawler effect, external-model call, PSTN call, payment, or trading
action. All such capabilities remain disabled unless a separate exact-candidate
activation release satisfies its own protected approvals and evidence gates.
