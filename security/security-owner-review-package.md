# Security Owner review package

Status: **DRAFT — NOT APPROVED — NOT A RISK ACCEPTANCE**

Review subject is the protected-main source tuple:

- Middleware: `c0543bcb04debf07d7db6ee91ceb809726ead7ab`
- Odoo: `dd95a350e8cfa33225098aeba42f69547f4724cd`
- Diagnostic image only: `sha256:a860ebae87ead0885d3cfcd0b3d09e5cead5ce903fe701d59b8f2f4c5cd0c3ec`

The diagnostic image is not the official artifact. An official image must be
built after this PR merges, and the final VEX must bind that new digest and its
SBOM. The reviewer must reproduce both scans, validate every source backport,
and either sign the exact-image VEX or leave the findings unresolved.

Required review inputs:

1. `security/grype-trivy-reconciliation.json` and `.md`.
2. `security/openvex-draft.json`.
3. Exact Grype, Trivy, and Syft versions and database identities recorded there.
4. SBOM SHA-256 `e4b7da3ed37682866105cacc88e40cf85e289bff8b32724b0ed32c6cfe68948a`.
5. The checksum-pinned CPython build in `Dockerfile` and
   `security/python312/README.md`.
6. Fresh official-image scanner reports and SBOM produced by the protected
   post-merge workflow.

Requested decisions:

- Nine proposed `fixed` findings: independently confirm the correction is in
  the compiled official runtime, then sign or reject each statement.
- CVE-2026-3298 proposed `not_affected`: independently confirm Linux/amd64 and
  absence of the Windows Proactor path, then sign or reject it.
- No `affected` finding may proceed without separate finite risk acceptance.

Authorization must use the protected `security-owner-authority` environment and
Sigstore workflow. A GitHub comment, unsigned file, or Codex-generated identity
is insufficient.
