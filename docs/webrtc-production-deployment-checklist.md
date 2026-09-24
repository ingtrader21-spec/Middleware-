# WebRTC production deployment checklist

This checklist prepares an inactive candidate only. It never authorizes SIP registration, PSTN routing, or a call.

1. Confirm the approved source SHA and a clean protected build context.
2. Run `scripts/webrtc-production-preflight`; stop on any technical `FAIL`.
3. Verify the artifact checksum, Ed25519 signature, CycloneDX SBOM, provenance, and security evidence.
4. Confirm the canonical issuer is `https://auth.codestra.co/realms/codestra` and production dialing remains disabled.
5. Back up middleware, policy, Asterisk/VICIdial, Keycloak export, release metadata, and the pilot packet using the protected backup procedure.
6. Validate policy schema, emergency/premium/prohibited blocks, consent, caller-ID allowlist, calling hours, capacity, and kill-switch precedence.
7. Run `scripts/deploy-webrtc-production-candidate` without an authorization argument to validate the inactive candidate.
8. Check health, login-page reachability, middleware, realtime, WSS rejection, UI bundle, release digest, and policy engine. Do not REGISTER or call.
9. Compare expected and running digests with `scripts/webrtc-config-drift-check`.
10. If any check fails, retain the active release and follow the rollback runbook. Production cutover requires a separately signed deployment authorization.

Rollback validation: restore the prior immutable digest and matching policy/config backup in isolation, run preflight and read-only smoke tests, and retain the deny-all gate until digest verification passes.
