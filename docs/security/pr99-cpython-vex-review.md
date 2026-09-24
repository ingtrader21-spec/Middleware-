# PR 99 CPython VEX review package

Status: **unsigned; Security Owner decision required**.

Subject: the exact candidate image and CycloneDX SBOM produced from the final
PR head. Their digest fields must be inserted by the protected release workflow;
this source document deliberately does not pre-authorize a digest.

The runtime builds CPython 3.12.13 from the SHA-256-pinned upstream archive.
`Dockerfile` downloads each named upstream commit patch, verifies its pinned
SHA-256, applies it before compilation, and fails the build on any patch error.
`security/python312/README.md` maps the generic CPE findings to those commits.
The Security Owner must independently reproduce those checks and select the
final OpenVEX state; no decision is made here.

| Finding | Scanner component | Reproducible evidence to review | Proposed state |
|---|---|---|---|
| CVE-2026-11940 | CPython 3.12.13 | `be13e86f6b9788a6f4d0419dffef72cbae5865c9`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-11972 | CPython 3.12.13 | `7f0dc59c9a70f8f3b4da33d7c4a2ba552a7acc21`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-15308 | CPython 3.12.13 | `7933f4bf7131aa4140750f9404f5de0aa2969ced`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-3644 | CPython 3.12.13 | `dae4b1a21f8df4570e30986affd61bbe4ade4cef`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-4224 | CPython 3.12.13 | `642865ddf4b232da1f3b1f7abcfa3254c4bfe785`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-6100 | CPython 3.12.13 | `e20c6c9667c99ecaab96e1a2b3767082841ffc8b`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-9669 | CPython 3.12.13 | `938ec030e90c5e53f1faac6fab1643f14e4f4a79`; pinned patch verification in `Dockerfile` | under_investigation |
| CVE-2026-4786 | CPython 3.12.13 | upstream `f4654824ae0850ac87227fb270f9057477946769` behavior plus `webbrowser-action-hardening.patch` | under_investigation |
| CVE-2026-7210 | CPython 3.12.13 / Expat 2.8.2 | pinned Expat package, `fc9b11ff49cbc82e6f917d07a61517a2b5f3145f`, and `expat-hash-salt-3.12.patch` | under_investigation |
| CVE-2026-3298 | CPython 3.12.13 | scanner advisory path is Windows-specific; candidate platform and absence of affected Windows module must be independently confirmed | under_investigation |

Required approval evidence: exact final image digest, SBOM SHA-256, full Grype
JSON, patch-file SHA-256 values, successful clean rebuild log, runtime platform,
and a separate decision plus justification for every row.
