# RC4 candidate security triage

The middleware RC4 candidate retains the digest-pinned Codestra CPython
3.13.14 base used by RC3P:

`codestra/python@sha256:541d6acdaa39568e8e9ba2a12f707ce167a819e553025256c29918a9509fe0c2`

Raw Trivy reports no Critical or High findings. Raw Grype reports the three
known version-based CPython findings:

- CVE-2026-11940
- CVE-2026-15308
- CVE-2026-11972

No scanner output is filtered or suppressed. These findings cannot be marked
inactive for RC4 without a new security-owner decision, exact candidate-image
binding, keyless signature, and independent approval. Until that governance
work occurs, the candidate is not security-clean or merge-eligible.
