# RC4 Lifecycle Candidate Security-Owner Decision

Automation prepared this template but did not complete any human approval
field. A real, authorized Codestra security owner must complete it before the
OpenVEX workflow may run.

## Human-supplied fields

Security owner name: Ralph Appolon
Security owner organizational role: Chief Executive Officer (CEO) and Security Owner
Decision timestamp UTC: 2026-07-27T12:23:06Z
Decision: APPROVED_FIXED_BACKPORT
Remediation owner: Ralph Appolon
Mandatory review date UTC: 2027-01-27

## Immutable decision scope

- Middleware source commit:
  `041eeb242c68ba8f606b7023c728575d389a2739`
- Gateway source commit:
  `dbf927247e6f16538e7ec65d8084c7faaba5c290`
- Middleware image:
  `codestra/middleware@sha256:8902cd852ab0b03701b3c5ab6b28d184c6a632e9d9b0deb39b0d5280ed38ed46`
- Gateway image:
  `codestra/telephony-event-gateway@sha256:5cdf841d45f5aa195494b7577c1b7f2f8396abae472dfeb02baa1ac5dc2fdf18`
- Patched Python image:
  `codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`
- Python version: `3.13.14`

## CVEs and official backports

- CVE-2026-11940:
  `771d12dda5140313db0ac550292987975651bbde`
- CVE-2026-15308:
  `7933f4bf7131aa4140750f9404f5de0aa2969ced`
- CVE-2026-11972:
  `3f031d431f80668e14f3bc066bbf4369cd9281b9`

## Evidence to review

- The Python executable, shared library, `tarfile.py`, and `html/parser.py`
  hashes are identical in the patched Python, middleware, and gateway images.
- Official CPython regression tests for all three backports passed against the
  interpreter used by the candidates.
- Fresh raw Grype: each candidate has 0 Critical and exactly 3 High findings,
  comprising only the three CVEs above.
- Fresh raw Trivy: each candidate has 0 Critical and 0 High findings.
- Full evidence:
  `/opt/codestra/compose/rc4-lifecycle-vex-governance-20260727`

## Residual risk and authorization boundary

Grype identifies the interpreter by its unchanged `3.13.14` version and cannot
detect the source-level backports. The candidates must move to the next
suitable official patched Python release when available.

An `APPROVED_FIXED_BACKPORT` decision authorizes only keyless VEX signing and
VEX-aware scanner reconciliation for the two exact image digests above. It
does not authorize merging either code PR, tagging, migration 0014, production
deployment, fixture activation, calls, or changes to extension 6110.
