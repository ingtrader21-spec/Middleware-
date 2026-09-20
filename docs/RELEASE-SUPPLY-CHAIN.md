# Signed release supply chain

## Release boundary

The only production-eligible Middleware image is built by
`.github/workflows/release.yml` after the complete `Middleware CI` workflow has
succeeded for an exact commit on protected `main`. Pull requests, local builds,
failed CI runs, mutable tags, and images without the expected Sigstore identity
are not production releases.

The workflow publishes exactly one `linux/amd64` image to:

```text
ghcr.io/appolon1908-hue/codestra-middleware@sha256:<digest>
```

The SHA/run tag is only a discovery aid. Staging and production must use the
digest reference recorded in the signed manifest.

### Single forward publisher

`release.yml` is the only workflow that may build, push and sign a production
Middleware image. Its `release` job is authorized as an exact narrow mutation in
`.codestra/validate-production-orchestrator-contract.py`
(`APPROVED_NARROW_MUTATION_SHA256`), so any edit to that job requires a new trust
generation; it runs only for a successful `Middleware CI` on protected `main`
of this repository (or a manual dispatch on `main`), refuses any source that is
not the current protected head, and proves that the published image carries
exactly one Alembic head, `0067_service_catalog_monitoring_state`. Every other
workflow that names the image repository, publishes an image or signs anything
carries one bounded role in `scripts/release_authority.py`
(`SUPPORTING_WORKFLOW_ROLES`), enforced by `tests/test_release_authority.py`:

| Workflow | Role |
| --- | --- |
| `exact-main-production-release.yml` | read-only admission verifier (was a second publisher; now holds no `packages: write` / `id-token: write`) |
| `verify-middleware-release.yml` | read-only verifier of `release.yml` signatures and attestations |
| `staging-candidate-build-sign.yml` | staging PR-candidate scope only; its publishing job is disabled until narrowly authorized |
| `automated-production-promotion.yml` | read-only admission / promotion gate |
| `security-owner-*-sign.yml`, `three-component-release-decision.yml`, `production-canary-authorization.yml` | blob signers for authority and decision documents |
| `sign-gateway-*.yml`, `sign-rc*-openvex.yml` | historical signers guarded on the pre-transfer repository name |

`sign-middleware-release.yml` (a duplicate signer under its own identity) was
removed. Trust pins for all of this are derived, never hand-edited, by
`scripts/derive_trust_pins.py`.

### Repository identity versus registry namespace

The repository moved from `appolon1908-hue/Middleware-` to
`ingtrader21-spec/Middleware-`; every current workflow guard, Sigstore
certificate identity, provenance URI and OCI source label names the new
repository. The GHCR package is a separate authority: user-owned packages do
not move with a repository transfer, `ghcr.io/appolon1908-hue/codestra-middleware`
still holds every published digest (public pull, verified 2026-09-19) and no
`ghcr.io/ingtrader21-spec/codestra-middleware` package exists. The release and
candidate workflows therefore keep publishing to, and the trust contracts keep
pinning, the `appolon1908-hue` namespace until the package itself is migrated
in a dedicated, reviewed change; that transitional ownership is intentional,
not a leftover.

Releases signed before the transfer keep their historical repository name and
`release.yml` identity. They stay verifiable only for the exact source SHA and
image digest pairs pinned in `scripts/release_manifest.py`
(`HISTORICAL_RELEASES`) and `contracts/release-manifest.v1.schema.json`; every
other manifest must carry the current repository and identity.

## Evidence created for every accepted build

The release workflow:

1. checks out the exact source SHA accepted by `Middleware CI`;
2. builds from a digest-pinned Python base and hash-locked runtime dependencies;
3. emits maximum-mode BuildKit provenance and an OCI SBOM attestation;
4. generates an exact-image SPDX JSON SBOM;
5. blocks fixable high or critical vulnerabilities;
6. creates a canonical release manifest binding the source, image, base image,
   runtime/test locks, contracts, runtime profiles, migrations, SBOM, scan report,
   migration head, workflow run, and build time;
7. keylessly signs the image and SBOM attestation;
8. keylessly signs the manifest as a Sigstore bundle with transparency-log proof;
9. verifies the expected workflow certificate identity and every manifest digest;
10. stores the manifest, bundle, SBOM, and scan report as one immutable workflow
    artifact.

No private signing key is stored in GitHub or in this repository. The required
certificate identity is:

```text
https://github.com/ingtrader21-spec/Middleware-/.github/workflows/release.yml@refs/heads/main
```

The required OIDC issuer is `https://token.actions.githubusercontent.com`.

## Verification before staging or production

Download the workflow evidence beside an exact checkout of the recorded source,
install the pinned Cosign release documented in the workflow, and run:

```bash
python3 scripts/release_manifest.py verify \
  --manifest release-manifest.v1.json \
  --bundle release-manifest.v1.sigstore.json \
  --expected-source-sha <40-character-sha> \
  --expected-image-digest sha256:<64-hex>
```

Then verify the registry signature independently:

```bash
cosign verify \
  --certificate-identity 'https://github.com/ingtrader21-spec/Middleware-/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/appolon1908-hue/codestra-middleware@sha256:<digest>
```

Deployment must stop if the bundle, signer identity, source SHA, image digest,
artifact digest, migration head, or runtime profile differs. Production promotion
must reuse the exact digest accepted in staging; it must never rebuild from the
same source or resolve a tag again.

Unfixed vulnerabilities remain visible in the signed scan evidence and require
explicit risk review before production approval. A reviewed VEX policy can be
added later; suppressions in ad hoc workflow arguments are not accepted.
