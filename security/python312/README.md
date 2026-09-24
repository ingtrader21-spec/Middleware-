# Python 3.12 release security corrections

The middleware runtime uses the checksum-pinned Python 3.12.14 source release.
That release already contains the maintained-branch corrections listed below,
so the Docker build compiles the verified archive directly. Reapplying those
commits with GNU patch would detect them as reversed patches and remove the
security corrections.

| Finding | Resolution |
| --- | --- |
| CVE-2026-11940 | Included in Python 3.12.14 (`be13e86f6b9788a6f4d0419dffef72cbae5865c9`) |
| CVE-2026-11972 | Included in Python 3.12.14 (`7f0dc59c9a70f8f3b4da33d7c4a2ba552a7acc21`) |
| CVE-2026-15308 | Included in Python 3.12.14 (`7933f4bf7131aa4140750f9404f5de0aa2969ced`) |
| CVE-2026-3644 | Included in Python 3.12.14 (`dae4b1a21f8df4570e30986affd61bbe4ade4cef`) |
| CVE-2026-4224 | Included in Python 3.12.14 (`642865ddf4b232da1f3b1f7abcfa3254c4bfe785`) |
| CVE-2026-6100 | Included in Python 3.12.14 (`e20c6c9667c99ecaab96e1a2b3767082841ffc8b`) |
| CVE-2026-9669 | Included in Python 3.12.14 (`938ec030e90c5e53f1faac6fab1643f14e4f4a79`) |
| CVE-2026-4786 | Included in Python 3.12.14 (`f4654824ae0850ac87227fb270f9057477946769`) |
| CVE-2026-7210 | Included in Python 3.12.14 and linked against Expat 2.8.4 |
| CVE-2026-3298 | Not applicable: the vulnerable code is Windows-specific and the release image is Linux/amd64 |

The historical local patch files remain as review evidence for older 3.12
builds, but are not applied to 3.12.14. Release evidence must bind the resulting
image digest to a VEX statement for each generic CPE match.
