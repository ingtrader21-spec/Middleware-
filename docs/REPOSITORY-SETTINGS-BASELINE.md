# Middleware repository settings baseline

This document is the exact target state for
`https://github.com/ingtrader21-spec/Middleware-/settings`.

## Current verified drift on 2026-08-30

Before the live application gate:

- Default branch: `main`
- `main` is not protected.
- No repository rulesets exist.
- Merge commits, squash merges, and rebases are all allowed.
- Auto-merge, automatic branch deletion, update-branch support, and web commit
  signoff are disabled.

That state permits an administrator or collaborator to bypass the exact-head CI
model already implemented in the repository.

## General

Set the repository description to:

> Codestra durable integration and automation control plane

Required topics:

`middleware`, `fastapi`, `postgresql`, `keycloak`, `kong`, `n8n`,
`integration-platform`, `outbox`, `idempotency`, `gitops`

Keep Issues enabled. Disable Wiki unless it becomes an explicitly maintained
authority. Do not change repository visibility as part of this gate.

## Pull request merge settings

Enable only:

- Allow squash merging
- Always suggest updating pull request branches
- Allow auto-merge
- Automatically delete head branches
- Require contributors to sign off on web-based commits

Disable:

- Allow merge commits
- Allow rebase merging

Use the pull request title and body for the squash commit.

## Actions

- Default workflow permissions: **Read repository contents and packages**
- Do not allow Actions to create or approve pull requests
- Keep every external action pinned to a full commit SHA
- Do not persist checkout credentials

## Active ruleset for `main`

Create one active branch ruleset named
`middleware-main-production-authority`.

Require:

- Changes through pull requests
- All review conversations resolved
- Linear history
- Branch up to date before merge
- Status checks:
  - `validate` (aggregate fail-closed result)
  - `Validate middleware source head`
  - `Validate middleware merge result`
  - `docker-runtime-build`
  - `docker-test-build`
  - `connector-runtime-build`
  - `container-security`
  - `Disposable PostgreSQL Redis integration`
  - `Disposable NATS JetStream integration`
  - `Temporal critical workflow integration`
  - `Synthetic no-effect acceptance E2E`
- Block force pushes
- Block branch deletion
- Apply to administrators
- No bypass actors

Require one approving review. The repository is no longer single-owner: a second
collaborator holds write access and already reviews pull requests, so requiring
an independent approval no longer deadlocks an author who cannot approve their
own pull request. Exact-head automated gates remain mandatory and are not
replaced by the human approval; the approval is an additional gate in front of
`main`, not a substitute for any required check.

Do not enable required code-owner review while `CODEOWNERS` resolves every path
to the sole repository owner: an owner-authored pull request could then never be
approved.

## Security and analysis

Enable dependency graph, Dependabot alerts and security updates, secret scanning,
push protection, and private vulnerability reporting. Code scanning remains a
required production-release gate.

## Environments

Create `staging` and `production`. Both accept only the `main` branch.

`staging` uses immutable digests and contains no live-write secret set true.

`production` has no mandatory human reviewer. Promotion remains fail-closed on
the protected branch, exact-head required checks, security and contract gates,
resolved review conversations, immutable digest attribution, rollback evidence,
and the read-only deployment policy. Mutable tags and live-write defaults remain
forbidden.

Only `.github/workflows/automated-production-promotion.yml` may reference the
`production` environment. Required CI enforces that constraint. It admits only
the exact protected-main artifact produced and verified by `release.yml`, and it
records a read-only canary admission with business writes and all external
effects disabled.

No environment setting in this gate deploys code, restarts a service, changes
DNS/TLS, creates provider credentials, or enables Odoo, SMS, email, PSTN,
financial, crawler, or other external effects.

## Audited application path

The connector cannot call GitHub's administrative write endpoints directly.
The repository therefore contains an idempotent, owner-only applier:

- source: `scripts/apply_repository_governance.py`
- trigger: `.github/workflows/repository-governance-apply.yml`
- authority issue: `#68`
- exact command:
  `/apply-repository-governance w0-live-v1`

The workflow runs only when GitHub reports all of the following:

- repository is exactly `ingtrader21-spec/Middleware-`;
- issue number is exactly `68` and is not a pull request;
- comment author login and numeric ID are the repository owner;
- author association is `OWNER`;
- comment body exactly matches the command above.

It checks out the exact default-branch event SHA, validates the encoded policy,
applies repository settings through the GitHub REST API, then runs both live
verifiers. It has only `contents: read` through `GITHUB_TOKEN`.

The one-time apply requires `CODESTRA_REPOSITORY_ADMIN_TOKEN` as a repository
secret with repository **Administration: write** permission. The token must not
have access to unrelated repositories. After a green apply, rotate or remove the
write-capable token; a read-capable replacement may be used for later drift
audits.

## Verification

After application:

1. `scripts/apply_repository_governance.py --verify-live` must pass.
2. `scripts/validate_repository_governance.py --live` must pass.
3. The workflow run URL and exact `main` SHA must be attached to issue `#68`.
4. `docs/evidence/W0/GATE.md` may be updated and tag `w0-complete` created only
   after live verification is green.

The applier is idempotent. Re-running it converges to the same encoded state and
does not mutate runtime or deployment configuration.
