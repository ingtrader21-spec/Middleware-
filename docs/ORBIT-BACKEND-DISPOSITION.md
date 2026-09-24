# Orbit backend recovery disposition

Status: `BLOCKED_PENDING_IMMUTABLE_SDK_ORBIT_RELEASE`

Date: 2026-09-09
Tracking: Middleware issue #109
Stale recovery reference: Middleware PR #103

## Decision

Do **not** reopen, merge, mechanically rebase, deploy, or treat the closed PR #103 head as current source authority.

Middleware remains a backend/API boundary only for Codestra Orbit. It must not own the browser shell, login page, shared header/footer, icon presentation, or frontend design implementation. Orbit backend adoption may resume only from then-current protected `main` after every prerequisite below is satisfied with immutable evidence.

## Evidence reviewed

- SDK-repository PR #75 (`feat(orbit): establish Codestra Orbit v2 system authority`) is merged at `59994f618dda555264e45a5e49c05ec65325d035`.
- PR #75 explicitly states that committed pre-correction Orbit tarballs are quarantined and that a protected post-merge release tied to the final accepted SHA is required before production consumers certify or pin Orbit packages.
- As of 2026-09-09, the SDK-repository GitHub Releases collection is empty. Therefore the required immutable post-merge Orbit consumer release is **not proven**.
- Middleware PR #101 is merged at `69a272ca3296bea8cdd3ade47995a56e0f41bc58`.
- Middleware PR #98 is merged at `a137f6081e52eeec6b101d9f325bc7b6375e4e76`.
- Legacy provider-control PR #96 remains closed and superseded; its current-main replacement requirements were recovered through later protected work, including PR #106 merged at `292190416acf301e8eb04306e3d04759ce1ee268`.
- Current protected Middleware source contains the governed provider-control routes and policy/validation contracts; that does not constitute Orbit adoption or an immutable Orbit SDK pin.

## Resume gates

Orbit backend adoption remains blocked until all of the following are true:

1. SDK Orbit publishes an immutable protected release tied to an accepted protected commit, and Middleware pins that exact release identity rather than a mutable branch or stale draft artifact.
2. The pin is verified against the then-current SDK/OpenAPI authority and generated-contract parity.
3. Every Middleware-owned Orbit operation has explicit ownership. Unproven optional operations remain absent or disabled.
4. Authentication is fail closed: canonical issuer, one exact audience, exact operation scope, validated `azp`, and server-derived tenant binding.
5. Browser OAuth/OIDC tokens remain server-side; Middleware does not create a frontend shell.
6. Mutations use semantic idempotency, correlation, expected version, durable audit/publication evidence, and tested rollback.
7. External effects remain disabled during source adoption; no source-only Orbit change authorizes DNS/TLS, Kong/Caddy, Keycloak production clients, provider writes, deployment, or live traffic.
8. The replacement PR branches from then-current protected `main`, passes exact-head/merge-result checks and applicable unit, authorization, replay, idempotency, OpenAPI/SDK, SBOM/vulnerability, rollback and no-effect gates, and receives independent review.

## Acceptance for #109

The Orbit stale-draft workstream is **explicitly dispositioned, not completed**: preserve PR #103 as historical evidence and keep Orbit backend adoption blocked until the immutable SDK release prerequisite exists. This disposition does not close #109's separate Scrapper, runtime-certification, or registry documentation/enforcement workstreams.
