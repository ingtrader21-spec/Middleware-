# Bounded Canary Gateway RC1 Security-Owner Decision

## Human-supplied fields

Security owner name: Ralph Appolon
Security owner organizational role: Chief Executive Officer (CEO) and Security Owner
Decision timestamp UTC: 2026-07-28T13:26:21Z
Decision: APPROVED_FIXED_BACKPORT
Remediation owner: Ralph Appolon
Mandatory review date UTC: 2027-01-28

## Immutable decision scope

- Gateway source repository: `Codestra-SRL/telephony-event-gateway`
- Capability PR: `2`
- Independently approved head: `e8b004523b2a6997e94b7c70ac6d8a10f0c70fc5`
- Merge commit: `360da1382bef3e2e6d766195ef6b1a19956756a9`
- Gateway image:
  `docker.io/codestra1980/telephony-event-gateway@sha256:bbfa5e05ce9dd33d3ebc7f5475ee1810e47e5eaecd29adac0aa24c5252958266`
- Patched Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- Python version: `3.13.14`

## CVEs and official backports

- CVE-2026-11940: `771d12dda5140313db0ac550292987975651bbde`
- CVE-2026-15308: `7933f4bf7131aa4140750f9404f5de0aa2969ced`
- CVE-2026-11972: `3f031d431f80668e14f3bc066bbf4369cd9281b9`

## Evidence reviewed

- The bounded-canary capability passed 53 tests at the exact merged source.
- The image runs as `65532:65532`, supports a read-only root filesystem, adds
  no listener, and preserves the normal gateway command.
- SPDX and CycloneDX SBOMs bind to the immutable candidate.
- Fresh Trivy reported no findings.
- Fresh Grype reported three High findings, limited to the three CVEs above,
  caused by the unchanged Python version string in the source-patched base.
- The same official CPython backports were previously accepted for RC4 and
  remain present through the unchanged patched Python base identity.

## Residual risk and authorization boundary

The image must move to the next suitable officially patched Python release when
available. This decision authorizes only signing and release verification for
the exact digest above. It does not authorize deployment, enabling
`SEND_EVENTS`, automatic delivery, a call, fixture activation, firewall
changes, or changes to extension 6110.
