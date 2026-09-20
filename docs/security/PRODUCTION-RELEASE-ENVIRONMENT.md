# Production release environment

Status (2026-09-20): the `production-release` environment is no longer on any
forward release path. `.github/workflows/exact-main-production-release.yml`
was converted into a read-only admission verifier that holds no
`packages: write` and no `id-token: write`, cannot push, tag, sign or attest,
and verifies that a candidate was built and signed by the single forward
publisher, `.github/workflows/release.yml`. The configuration below is retained
as the historical record of the environment while it gated the former second
publisher; the environment may be deleted once the last historical run
evidence is archived.

The `production-release` GitHub environment was a release-evidence gate. It
never authorized deployment or activation.

Required configuration:

- required reviewer: the mapped Release Owner, currently `appolon1908-hue`;
- prevent self-review: enabled;
- administrator bypass: disabled;
- deployment branches: protected branches only (`main`);
- environment secrets: none;
- environment variables: none.

The Security Owner decision is independently enforced by the two signed input
artifacts and their protected signer environments. GitHub environment required
reviewers are an any-one gate, so adding both roles to this single environment
would not enforce two approvals. The release job therefore uses this environment
for the separate Release Owner decision.

The workflow uses only the job-scoped GitHub token. Authority and VEX artifact
coordinates are immutable `workflow_dispatch` inputs. Repository or organization
secrets must not be used to replace Security Owner approval.
