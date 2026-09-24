# Acceptance evidence

Local validation on 2026-08-06:

- Authentication matrix: positive `200`; replay `409`; invalid signature, expired timestamp, wrong service, wrong key, and body mismatch `401`; missing header `422`; missing certificate rejected at TLS.
- Migration: `0030 -> 0031 -> 0030 -> 0031` passed in disposable PostgreSQL 17.
- Focused orchestration/database/worker tests: passed, including 12 simultaneous unique claims.
- Middleware regression: 716 passed; integration collection: 5 skipped by their existing environment gates.
- Bounded benchmark: 200 accepted and 200 uniquely claimed; zero duplicate claims; enqueue p50 53.339 ms/p95 76.120 ms; claim p50 683.598 ms/p95 794.281 ms; 27.757 claims/second with concurrency capped at 20.
- Server B model smoke: installed `qwen2.5:0.5b` produced a synthetic response over loopback in 40.522 seconds.
- Listener policy: LiteLLM `127.0.0.1:4000`; Ollama `127.0.0.1:11434`; public and VLAN access denied after disabling the obsolete private proxy socket.
- SBOM SHA-256: `e5b0f649b876fa13bb97856dc2475caf750cc1bd61596d28dc1a828790121180`.
- Trivy filesystem High/Critical: 0; Trivy secret findings: 0; Grype directory High/Critical: 0.
- Server B worker candidate validates as the unprivileged `qwen-agent`, remains inactive, and has no listener.

Production activation remains unauthorized. The final commit, CI result, immutable image evidence, and protected approval must be appended by the release workflow. Local validation is not production activation authority.
