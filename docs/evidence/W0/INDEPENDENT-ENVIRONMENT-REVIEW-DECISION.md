# W0 independent environment-review decision

- **Decision date:** 2026-09-09
- **Repository:** `appolon1908-hue/Middleware-`
- **Issue:** #68
- **Status:** SOURCE POLICY PROPOSED — LIVE APPLY NOT YET PROVEN
- **Independent reviewer:** `kazan555` (GitHub user ID `77101516`)
- **Runtime deployment authorized:** no
- **Live writes authorized:** no

## Decision

The `staging` and `production` GitHub environments require the same
fail-closed protection baseline:

- exactly one approved independent reviewer, identified by stable GitHub user
  ID rather than mutable login text;
- deployment initiators cannot approve their own deployment;
- administrators cannot bypass environment protection;
- only protected branches may deploy;
- no custom branch or tag deployment policy;
- no live-write secret authorization.

The release policy continues to deny live writes, Odoo writes, and live apply by
default. Production release intent must use the `production` environment and
receive independent human approval.

## Source and live-state boundary

The source policy, validator, applier, and tests in the associated pull request
define the intended state. They do not prove that GitHub currently enforces it.

After this source change reaches protected `main`, the repository owner must
invoke the existing owner-locked command:

`/apply-repository-governance w0-live-v1`

The resulting workflow must apply the exact protected-main source and read back
repository, ruleset, security, Actions, and environment settings. Evidence must
record the protected-main source SHA and successful workflow run without
printing tokens or secret values.

The `w0-complete` tag may be created only after that evidence is merged and the
tag target is read back. This decision does not deploy Middleware, modify a
server, connect a provider, or enable an external effect.
