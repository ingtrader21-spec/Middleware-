# RC3P Security-Owner Decision

This document must be completed and signed by a named human security owner.
Automation must not populate the identity, decision, or signature fields.

## Candidate scope

- Middleware source commit:
  `419650868659efa3589dcda29c1615c27b71f493`
- Middleware image:
  `codestra/middleware@sha256:d48b4f2a6d1804b0fce14fdeaccfcdb976171c32c0c5704efadb8a6651c62ebe`
- Custom Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- CVEs: CVE-2026-11940, CVE-2026-15308, CVE-2026-11972
- OpenVEX SHA-256:
  `eed2f59523e87385abe2743c438ddb45d00c37bf7926923791ba8da245ae5a2e`

## Human-supplied fields

Decision: APPROVED_FIXED_BACKPORT

Security owner name: Ralph L. Appolon
Security owner role: Owner and Designated Security Officer
Organization: Codestra SRL
Approval timestamp: 2026-07-26T19:45:23-04:00
Review expiration: 2026-10-24T19:45:23-04:00

Middleware image:
codestra/middleware@sha256:d48b4f2a6d1804b0fce14fdeaccfcdb976171c32c0c5704efadb8a6651c62ebe

Custom Python image:
codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2

Approved CVEs:
- CVE-2026-11940
- CVE-2026-15308
- CVE-2026-11972

Decision basis:
The exact official CPython 3.13 maintained-branch security backports are
included in the digest-pinned interpreter. Their official regression tests
passed against the final image. Grype continues to classify the interpreter
using the unchanged Python 3.13.14 version and does not detect source-level
backports. Raw findings remain preserved and are not suppressed.

Residual risk:
A scanner may continue to report the three CVEs until a patched official
CPython release changes the interpreter version metadata. The deployed image
must be replaced with the next suitable official stable patched Python image
when one becomes available.

Remediation owner: Ralph L. Appolon
Approved signing identity:
https://github.com/Codestra-SRL/codestra-middleware/.github/workflows/sign-rc3p-openvex.yml@refs/heads/main

Signing policy reference:
docs/security/organizational-signing-policy.md

Select exactly one:

- [x] `APPROVED_FIXED_BACKPORT`
- [ ] `REJECTED`
- [ ] `MORE_EVIDENCE_REQUIRED`

Decision rationale:

Signature or approved identity-provider attestation:

Independent reviewer name:

Independent verification result:

No release tag may be created unless `APPROVED_FIXED_BACKPORT` is selected and
the resulting VEX signature is independently verified.
