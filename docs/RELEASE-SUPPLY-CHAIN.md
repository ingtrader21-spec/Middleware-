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
