# Grype/Trivy reconciliation for protected-main diagnostic image

Status: **DRAFT — UNSIGNED — SECURITY OWNER REVIEW REQUIRED**

Subject image: `sha256:a860ebae87ead0885d3cfcd0b3d09e5cead5ce903fe701d59b8f2f4c5cd0c3ec`
(`linux/amd64`, source `c0543bcb04debf07d7db6ee91ceb809726ead7ab`).
SBOM SHA-256: `e4b7da3ed37682866105cacc88e40cf85e289bff8b32724b0ed32c6cfe68948a`.

## Reproduction identity

| Tool | Version/database |
|---|---|
| Syft | 1.50.0 |
| Grype | 0.116.1; schema v6.1.9; built 2026-08-12T06:38:08Z; DB SHA-256 `07a2b6b851eb63490da4d328aa442fbed9b106f6e86a7686f300a1f617b5456d` |
| Trivy | 0.72.0; DB v2 updated 2026-08-12T19:12:05.145200672Z; DB SHA-256 `3f37f18b7dc68e576f341c074d114445075e7e33606c680b4536d82dd0bcbae7` |

Commands used:

```text
syft codestra/middleware:cert-c0543bcb-exact -o cyclonedx-json=sbom.cdx.json
grype codestra/middleware:cert-c0543bcb-exact -o json > grype.json
trivy image --scanners vuln,secret --format json --output trivy.json codestra/middleware:cert-c0543bcb-exact
python3 scripts/reconcile_candidate_vulnerabilities.py --trivy trivy.json --grype grype.json --output vulnerability-matrix.csv --summary vulnerability-summary.json
```

No ignore file, severity reduction, finding suppression, or VEX was applied.
The reconciliation helper records twenty High scanner rows, canonicalized here
to ten unique CVEs. Grype identifies the CPython 3.12.13 CPE twice, at the
interpreter and shared-library paths. Trivy reports zero High/Critical findings.

## Adjudication summary

All findings are runtime binary matches in layer
`sha256:4544ac0d7dd7d9d2146006c1061aeac627219479069f36605ec908c1ed9e467f`.
Grype matches release-version metadata and cannot recognize source-level
backports. The Dockerfile downloads checksum-pinned CPython corrections and
applies them before compiling the interpreter. This evidence supports proposed
`fixed` states for nine findings, but does not authorize them. CVE-2026-3298 is
Windows-only and the subject is Linux/amd64, supporting a proposed
`not_affected` state that still requires a Security Owner signature.

| Finding | Fixed version reported by Grype | Technical disposition | Proposed VEX |
|---|---|---|---|
| CVE-2026-11940 | 3.13.15 / 3.14.7 / 3.15.0b4 | Pinned tarfile hardlink/symlink correction applied | fixed |
| CVE-2026-11972 | 3.13.15 / 3.14.7 / 3.15.0b4 | Pinned streaming EOF correction applied | fixed |
| CVE-2026-15308 | 3.15.0 | Pinned incremental HTML parser correction applied | fixed |
| CVE-2026-3298 | 3.13.14 / 3.14.5rc1 / 3.15.0b1 | Windows Proactor path absent from Linux image | not_affected |
| CVE-2026-3644 | 3.13.13 / 3.14.4 / 3.15.0a8 | Pinned cookie validation correction applied | fixed |
| CVE-2026-4224 | 3.13.13 / 3.14.4 / 3.15.0a8 | Pinned pyexpat recursion correction applied | fixed |
| CVE-2026-4786 | 3.13.14 / 3.14.5rc1 / 3.15.0b1 | Minimal 3.12 webbrowser correction applied | fixed |
| CVE-2026-6100 | 3.13.14 / 3.14.5rc1 / 3.15.0b1 | Pinned decompressor UAF correction applied | fixed |
| CVE-2026-7210 | 3.13.14 / 3.14.6 / 3.15.0b2 | Expat 2.8.2 and hash-salt corrections applied | fixed |
| CVE-2026-9669 | 3.13.14 / 3.14.6 / 3.15.0b3 | Pinned BZ2 error-state correction applied | fixed |

The machine-readable file contains package paths, reachability, remediation,
supporting evidence, and required owner actions for every finding.
