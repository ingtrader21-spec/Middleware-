# Gateway schema-1 correlation safety RC1 security decision

Decision: APPROVED_FIXED_BACKPORT

Independent exact-head review and merge remain mandatory before signing.

## Exact scope

- Gateway source: `b9ffcedca23628c16d8b046e8ec555d13186cf59`
- Gateway image: `docker.io/codestra1980/telephony-event-gateway@sha256:dc91007162f64410eb97b163502bad013a2adb670a28d0655572326da18f42fb`
- Python base: `docker.io/codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- Findings: CVE-2026-11940, CVE-2026-15308, CVE-2026-11972

## Decision basis

Trivy reports zero High or Critical findings. Grype reports three High findings
from Python version metadata. The exact base digest is the same reviewed custom
Python artifact covered by `security/vex/rc3p/security-owner-decision.md`,
where Codestra SRL's designated security owner approved the three official
maintained-branch security backports. This release does not suppress the raw
scanner findings and preserves both scanner reports.

This document binds that existing human fixed-backport decision to the exact
gateway product digest. Independent approval of the exact PR head is required
before signing.

Residual risk: scanners may continue to report version-derived findings until
an official Python release changes the package version. Replace the base with
the next suitable official patched release when available.

The rejected pre-safety digest
`sha256:09b7fef5207d25bfd336cd6ba239ab433ac00f5fadac6f1b79077297662f5c19`
is outside this decision and must never be signed, tagged, or deployed.
