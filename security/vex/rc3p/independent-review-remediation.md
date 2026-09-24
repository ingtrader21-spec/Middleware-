# RC3P Independent Review Remediation

## Governance incident

PR #1 containing the RC3P security-owner decision was merged without a submitted
independent approval.

Signing, release tagging, migration, and production deployment remain blocked.

## Exact reviewed state

- Original PR: https://github.com/Codestra-SRL/codestra-middleware/pull/1
- Original merge commit: `19fe072cd21182494066aae2aadb084152a75ee6`
- Decision file SHA-256: `396234e6356b0fc5d0ce496e4b519aef987745ee47969b23fe0b488605145326`
- Middleware image:
  `codestra/middleware@sha256:d48b4f2a6d1804b0fce14fdeaccfcdb976171c32c0c5704efadb8a6651c62ebe`
- Custom Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`

## Required independent review

A GitHub account different from `appolon1908-hue` must review:

- `security/vex/rc3p/security-owner-decision.md`
- `security/vex/rc3p/openvex.json`
- `docs/security/organizational-signing-policy.md`
- `.github/workflows/sign-rc3p-openvex.yml`

This remediation PR must receive a formal GitHub approval before it is merged.

Until then:

- Signing is prohibited.
- VEX-aware scanner adjudication is prohibited.
- The RC3P release tag must not be created.
- Production migration and deployment remain prohibited.
