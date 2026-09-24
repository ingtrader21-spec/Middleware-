# RC3P Independent Review Attestation

## Governance exception

PR #1 and PR #2 were merged without a submitted independent GitHub approval.

No VEX signature, release tag, migration, production deployment, call, email,
SMS, extension reservation, SIP activation, or n8n activation occurred.

This pull request is review-only. It must remain open until an independent
review is submitted by a GitHub user other than appolon1908-hue.

## Exact state under review

- Current main commit: `9ccd5dc1110ae484c5d1f209773791d159e2272f`
- PR #1 merge commit: `19fe072cd21182494066aae2aadb084152a75ee6`
- PR #2 merge commit: `9ccd5dc1110ae484c5d1f209773791d159e2272f`
- Security decision SHA-256: `396234e6356b0fc5d0ce496e4b519aef987745ee47969b23fe0b488605145326`
- OpenVEX SHA-256: `eed2f59523e87385abe2743c438ddb45d00c37bf7926923791ba8da245ae5a2e`
- Signing workflow SHA-256: `c8c36ce2b012c43ebe54ad943b4a096ad980937756177533ac69df626f97fcdc`
- Signing policy SHA-256: `ff4b9cd8983851355fb5c6a4f9b3be23009296c097063f3a5de0e8c8ca4a62d3`

## Product scope

- Middleware image:
  `codestra/middleware@sha256:d48b4f2a6d1804b0fce14fdeaccfcdb976171c32c0c5704efadb8a6651c62ebe`

- Custom Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`

- CVEs:
  - CVE-2026-11940
  - CVE-2026-15308
  - CVE-2026-11972

## Required reviewer inspection

The reviewer must inspect:

- security/vex/rc3p/security-owner-decision.md
- security/vex/rc3p/openvex.json
- docs/security/organizational-signing-policy.md
- .github/workflows/sign-rc3p-openvex.yml
- this attestation

The reviewer approval confirms independent review of the exact hashes above.
It does not authorize production deployment.

## Prohibited until approval

- VEX signing
- VEX-aware release adjudication
- RC3P release tagging
- Migration 0013 production execution
- Middleware production deployment
- Extension 6110 reservation
- Fixture 6198 activation
- Calls, email, SMS or n8n activation
