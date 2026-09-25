# 06 — GHCR package access: read-only diagnosis and owner decision

## Symptom

`denied: permission_denied: read_package` when the release job pushes `ghcr.io/ingtrader21-spec/codestra-middleware` with the repository `GITHUB_TOKEN` (`packages: write`).

## Evidence gathered without credentials or workarounds

| Probe | Result | Meaning |
| --- | --- | --- |
| `GET users/ingtrader21-spec` | `type: User` | Personal namespace; no organization package-creation policy is in play. |
| `gh repo view ingtrader21-spec/Middleware-` | `isFork=false`, `visibility=PUBLIC` | Not a fork; `GITHUB_TOKEN` is not fork-restricted. |
| Middleware- release runs before 35602170321 | all targeted `ghcr.io/appolon1908-hue/…` | This repository never pushed to the new package. |
| `mirror-codestra-legacy-middleware-images.yml` | `workflow_dispatch` only; last runs 2026-09-12, all failed | Did not create the package. |
| `staging-candidate-build-sign.yml` (also targets the new package) | zero runs | Did not create the package. |
| `https://github.com/users/ingtrader21-spec/packages/container/package/codestra-middleware` | HTTP 404 | No **public** package of that name. |
| `https://github.com/users/appolon1908-hue/packages/container/package/codestra-middleware` | HTTP 200 | The historical package is public (predecessor evidence, not promoted). |
| Anonymous `ghcr.io/v2/ingtrader21-spec/codestra-middleware/tags/list` | 403 `DENIED` | Private-or-nonexistent; GHCR does not distinguish anonymously. |
| Session `gh` token scopes | `gist, read:org, repo, workflow` | No `read:packages`; package metadata cannot be read from this session, and no PAT was minted (PAS-27 safety rule). |
| Peer lanes (`middleware-06` PAS-179 / Infustruction #126; `middleware-96` PAS-180; `middleware-69` repo visibility) | each confirmed: no docker/GHCR operations, no push to that package | No agent lane created it. |

## Interpretation

A first push from a repository to a not-yet-existing package in the **same owner's** namespace with `GITHUB_TOKEN` creates the package and links the repository with admin access. A `read_package` denial on push is the documented signature of a **package that already exists** whose "Manage Actions access" list does not include the pushing repository. Nothing in this program created such a package, so it was created manually or by a repository outside the program — or, less likely, the account itself is denying package access.

## Owner decision (account holder `ingtrader21-spec`)

1. Signed in, open `https://github.com/ingtrader21-spec?tab=packages` and look for `codestra-middleware`.
2. **Exists** → package settings → *Manage Actions access* → add repository `ingtrader21-spec/Middleware-` with role **Write** (Admin only if the workflow must manage visibility). Record who created it; nothing already in it is release evidence.
   **Does not exist** → the denial is account-level; open a GitHub Support case citing run 35602170321. Do not work around with a PAT, personal credential, local `docker push` or another namespace.
3. Re-run only the failed job: `gh run rerun 35602170321 --failed` — the `workflow_run` payload is preserved, so `SOURCE_SHA` stays `8ecf6e9b…` and the immutable tag becomes `sha-8ecf6e9b…-run-35602170321-attempt-2`. Alternatively `workflow_dispatch` `release.yml` on `main`.

Neither branch of the decision changes a workflow, validator, launcher or script byte, so the trust generation merged in #299/#301 remains authoritative and no launcher cycle is required.

## After a green run — independent verification checklist (V3-M0 exit)

- exactly one immutable digest published by run attempt N from `SOURCE_SHA=8ecf6e9b…`;
- OCI labels `org.opencontainers.image.revision` / `.source` equal the exact source;
- exactly one Alembic head: `0067_service_catalog_monitoring_state`;
- SBOM (`middleware.spdx.json`) attested to the digest (`cosign verify-attestation --type spdxjson`);
- Grype and Trivy policy results pass;
- SLSA v1 provenance subject equals the digest and `resolvedDependencies.gitCommit` equals the source SHA;
- Cosign signature verifies with the expected certificate identity (`release.yml@refs/heads/main` in `ingtrader21-spec/Middleware-`) and OIDC issuer `https://token.actions.githubusercontent.com`;
- digest recorded on PAS-27 and handed to PAS-13.

Local note: this workstation has only a Docker client (no `cosign`, `crane`, `skopeo`, `syft`, `grype`, `trivy`), so independent verification will be run from the workflow's own uploaded evidence artifacts plus a tool-equipped runner or a fresh install.
