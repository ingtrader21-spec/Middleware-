# Three-component M05 release decision

This gate authorizes only the immutable three-component tuple required for the
controlled `TEST_SYN` / endpoint `6101` certification. It performs no
deployment and grants no customer, PSTN, SMS, or email authority.

The artifact source SHA and M05 workflow SHA are intentionally distinct. A
governance-only workflow change does not change already-built artifacts. The
decision records and signs both identities.

## Protected environment

Create `production-release-decision` with:

- deployment branches: protected branches only (`main`)
- required reviewer: `kazan555`
- prevent self-review: enabled
- administrator bypass: disabled
- environment secrets: none
- environment variables: none

The final decision job uses only `actions: read`, `checks: read`, `contents:
read`, `packages: read`, and `id-token: write`. It downloads exact run/attempt
artifacts, verifies their checksum manifests, verifies authority and release
signatures with Cosign, resolves each registry digest, generates the decision,
then signs and re-verifies that decision.

## Fail-closed invariants

- All three component digests are mandatory immutable `sha256` identities.
- Authority, candidate, and signing artifacts are selected by exact run and
  attempt.
- Candidate manifests, decisions, provenance, and exceptions bind the artifact
  source SHA and exact digest.
- Critical findings must equal zero.
- Every accepted High exception is digest-bound, source-bound, and unexpired.
- The authority must be unexpired and explicitly synthetic-only.
- The requested test scope must equal `TEST_SYN/6101`.
- The workflow never deploys, starts containers, accesses Server B, or places a
  call.

The signed output is
`three-component-production-release-decision.json`, accompanied by its Sigstore
bundle, independent verification output, and `release-decision-SHA256SUMS`.
