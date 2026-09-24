# Schema-Aware Acknowledgement Gateway RC2 Security-Owner Decision

## Authorization

Decision timestamp UTC: 2026-07-28T15:38:47Z
Decision: APPROVED_FIXED_BACKPORT
Authorization source: explicit production-release authorization in the operator mission
Mandatory review date UTC: 2027-01-28

## Immutable decision scope

- Gateway source repository: `Codestra-SRL/telephony-event-gateway`
- Acknowledgement PR: `3`
- Independently approved head: `e37811b73811e42757ad6a88be3a6b4b5a159f41`
- Merge commit: `1dd5fd1a4b3819726664fa4f15e17afdd3c4003d`
- Gateway image:
  `docker.io/codestra1980/telephony-event-gateway@sha256:c5cb68554ad14f1057bc9d65d5b466433980e550dfc307f004b38cef20936035`
- Platform manifest:
  `sha256:5512bfdd3451c278e27d9750c11878ee95ba6828cdcae0cf19bbe9d96ab80e66`
- Patched Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- Python version: `3.13.14`

## CVEs and official backports

- CVE-2026-11940: `771d12dda5140313db0ac550292987975651bbde`
- CVE-2026-15308: `7933f4bf7131aa4140750f9404f5de0aa2969ced`
- CVE-2026-11972: `3f031d431f80668e14f3bc066bbf4369cd9281b9`

## Evidence reviewed

- All 59 gateway tests passed at the exact merge commit.
- The non-release image remained non-root, read-only-root compatible, and
  introduced no listener or normal-command change.
- SPDX and CycloneDX SBOMs bind to the immutable candidate.
- Trivy reported zero High or Critical findings.
- Grype reported only the same three Python-version findings already covered
  by the source-patched base and the prior reviewed VEX.
- The acknowledgement change does not modify HMAC, payload, retry, submission
  cap, or network-listener behavior.

## Boundary

This decision authorizes signing and verification for only the exact digest
above. Global `SEND_EVENTS` and external delivery must remain false during
deployment and after the bounded canary.
