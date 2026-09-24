# Gateway Acknowledgement Forensics RC3 Security-Owner Decision

## Authorization

Decision timestamp UTC: 2026-07-28T16:52:17Z
Decision: APPROVED_FIXED_BACKPORT
Authorization source: explicit production-release authorization in the operator mission
Mandatory review date UTC: 2027-01-28

## Immutable decision scope

- Gateway repository: `Codestra-SRL/telephony-event-gateway`
- Forensics PR: `4`
- Forensics approved head: `c8efb658e27981c577444ff88a52f0c3690d881e`
- Safety correction PR: `5`
- Safety correction approved head: `1c08d8c796f29728adcb3d511a3803307cf8f67c`
- Release merge commit: `d4abfac9b60f996b8853e0f838cf2f97f2095ee0`
- Gateway image:
  `docker.io/codestra1980/telephony-event-gateway@sha256:3b2c702d9cb86c0028b26c32ea5c78c394fa7b7889b6cef5f0f2f7821fd30171`
- Patched Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- Python version: `3.13.14`

## CVEs and official backports

- CVE-2026-11940: `771d12dda5140313db0ac550292987975651bbde`
- CVE-2026-15308: `7933f4bf7131aa4140750f9404f5de0aa2969ced`
- CVE-2026-11972: `3f031d431f80668e14f3bc066bbf4369cd9281b9`

## Evidence reviewed

- All 77 gateway tests pass at the exact release merge.
- The pre-release review reproduced and corrected exception secret leakage and
  unbounded HTTP response reads before image construction.
- The image remains non-root, read-only-root compatible, and introduces no
  listener or default-command change.
- SPDX and CycloneDX SBOMs bind to the immutable candidate.
- Trivy reports zero High and zero Critical findings.
- Grype reports only the same three version-derived Python findings covered by
  the source-patched base and prior independently reviewed VEX.

## Boundary

This decision authorizes signing and verification only for the exact digest
above. Deployment must retain `SEND_EVENTS=false` and
`ENABLE_EXTERNAL_DELIVERY=false`. A bounded canary requires a new run ID and
may make at most three attempts with no retry or fourth request.
