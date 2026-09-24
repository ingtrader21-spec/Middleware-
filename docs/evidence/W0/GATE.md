# Gate W0 — Contract decision and repository-governance baseline

- **Status:** COMPLETE — LIVE GOVERNANCE AND TAG VERIFIED
- **Original baseline commit:** `382683958feefce73458ee56a1589092bad632b3`
- **Historical verified governance source:** `8e4e1e2e7ed38fffbd71f1b50d45b26ce325bc0e`
- **Historical live verification workflow:** `33781342722`
- **Current accepted governance source:** `996ebecef80e6efec0ae4d19d5a8c6ff87d2fe7e`
- **Current live apply-and-verify workflow:** `34388426803`
- **Authority ruleset:** `middleware-main-production-authority`
- **Decision:** Middleware adopts automation v2 (ADR-0001)
- **Live writes changed:** no
- **Deployment changed:** no

## Historical evidence

Workflow run `33781342722` successfully applied and verified the historical
policy at source `8e4e1e2e7ed38fffbd71f1b50d45b26ce325bc0e`. That run remains valid
for its exact historical source and is not used as proof for later policy.

## Current live evidence — September 9, 2026

Owner-locked workflow run `34388426803` checked out exact protected-main source
`996ebecef80e6efec0ae4d19d5a8c6ff87d2fe7e` and completed successfully.
The run reported:

- `REPOSITORY_GOVERNANCE_APPLIER=PASS mode=APPLY main_protected=YES live_effects=UNCHANGED`
- `REPOSITORY_GOVERNANCE=PASS live=PASS`
- `REPOSITORY_GOVERNANCE_APPLIER=PASS mode=VERIFY main_protected=YES live_effects=UNCHANGED`
- staging and production environment governance applied and read back
- no runtime, deployment, provider, or live-write change

The plan step on the same exact source reported twelve required checks. The
committed policy requires one independent approval on `main`, stale-review
dismissal, resolved review threads, strict up-to-date status checks, linear
history, and administrator enforcement.

Both `staging` and `production` require the approved independent reviewer
identity `77101516`, set `prevent_self_review=true`, set `can_admins_bypass=false`,
and accept deployments only from protected branches. The release policy keeps
live writes, Odoo writes, and live apply disabled by default and requires
independent human approval for production release.

No runtime, provider, credential, server, deployment, or external-effect
capability is activated by W0 governance completion.

## Exit conditions

- [x] Option A recorded
- [x] Conformance harness present
- [x] Route authority and compatibility policy recorded
- [x] Skipped-test ownership documented
- [x] Historical GitHub governance apply and audit recorded
- [x] Independent environment-review decision recorded
- [x] Updated policy merged through protected `main`
- [x] Updated policy applied and read back from exact protected-main SHA
- [x] Current run/source evidence recorded in this protected change
- [x] Tag `w0-complete` created and its exact target read back

## Completion readback — September 9, 2026

Owner-authenticated verification on protected-main commit
`eb4cee4c36f6e9f1195b967a792e56d9bbc456a3` passed both
`apply_repository_governance.py --verify-live` and
`validate_repository_governance.py --live`. The exact results were
`REPOSITORY_GOVERNANCE_APPLIER=PASS mode=VERIFY main_protected=YES live_effects=UNCHANGED`
and `REPOSITORY_GOVERNANCE=PASS live=PASS skip_files=27`.

Created `refs/tags/w0-complete` without force and read it back as a direct commit
reference to `eb4cee4c36f6e9f1195b967a792e56d9bbc456a3`. The completion record is
on [issue #68](https://github.com/appolon1908-hue/Middleware-/issues/68), now
closed. Never repoint this tag. W0 completion grants no runtime promotion,
environment approval, or live-write authority.
