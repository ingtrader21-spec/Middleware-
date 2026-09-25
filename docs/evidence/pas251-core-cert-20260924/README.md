# PAS-251 CORE-CERT-01: Core Platform production-ready certificate inputs (2026-09-24)

Linear: PAS-251. Scope: Middleware, Kong, Caddy, Odoo, Keycloak, OpenBao.

```
CERTIFICATE=BLOCKED
CERTIFICATE_CANDIDATE_SHA256=84974ba4e6013d933aaee737dd5775caf1e8d727396912dfe744d6311797e18f
BLOCKER_MATRIX_SHA256=3e1df3fce42b78c112cf2785d63a8f7a68773ecc42846db8183ad2e1be35c956
OPEN_BLOCKERS=22  GATES: PASS=11 FAIL=14 MISSING=35 (6 components x 10 mandatory gates)
PRODUCTION_GO=NO  PRODUCTION_MUTATION=NO  PROVIDER_EFFECTS=0
```

This package holds the Middleware-side inputs to the Core Platform certificate. It records the exact protected-main SHAs, the digests that exist, and the evidence found for each mandatory gate. The verdict is derived from that record, not asserted. No gate is credited without a citation, and no runtime fact was invented. Every live-environment gate (staging readback, identity/route matrix, secret binding, backup/restore, rollback, monitoring) is `MISSING` or `FAIL`, so the certificate is **BLOCKED**.

| File | Content |
| --- | --- |
| [certificate-candidate.json](certificate-candidate.json) | Machine-readable candidate: per-component SHAs, protection, digests, the 10 gate verdicts with citations and blocker ids, design review, reused evidence, local verification |
| [blocker-matrix.json](blocker-matrix.json) | 22 mandatory blockers: observed fact, clear condition, owner, evidence. Bound to the candidate by canonical sha256 |
| `scripts/validate_core_platform_certificate.py` | Fail-closed validator (stdlib only, no network) |
| `tests/test_core_platform_certificate.py` | Consistency tests, plus negative tests showing READY cannot be declared over open blockers |

Hashes are sha256 over `json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, the same canonical rule as `deploy/public-api-route-contract.sha256`.

## Observation

Observed read-only between 2026-09-25T00:05Z and 00:45Z (2026-09-24 US local): `gh api` on each exact SHA, the files at those SHAs, and evidence already on Middleware main. No host, registry, identity provider, secret store, deploy or workflow was triggered or contacted.

## Protected-main inventory

| Component | Repository | Protected main | Merged from | Required checks on merged head | Main-push CI | Exact-head review | Recorded runtime digest |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Middleware | `ingtrader21-spec/Middleware-` | `0606b0db9ff59802f8da3824d209d2effc13f87d` | #307 @ `a95d82f3` | 11/11 green | green (run 35612802733) | yes (2 non-author) | none: release denied/not started |
| Kong | `ingtrader21-spec/Kong` | `3e68cb2a4955bd71ddb3e839f4d9e3770465fc08` | #110 @ `1403090a` | `security` **red**, still merged | `security` red | yes | none (runtime variable) |
| Caddy | `ingtrader21-spec/Caddy` | `0feae8a493f54e5f32dfd1f63ba5c967aa5fbf90` | #182 @ `59624a5d` | 2/2 green | not started (billing) | yes | none for main; last signed release diverged, old namespace |
| Odoo | `ingtrader21-spec/Odoo` | `c1fb759a85b931bd64be77fdf5e26266c3b176a1` | #142 @ `7a209c31` | 5/5 green | not started (billing) | yes | none for main |
| Keycloak | `ingtrader21-spec/Keycloak` | `45a487d71a516ae3039b00c250752897469ffe7a` | #118 @ `fc5265e4` | 2/2 green | `validate` green | **no** (approval on `ea18bbcb`) | none; pattern pinned to `appolon1908-hue` |
| OpenBao | `ingtrader21-spec/Codestra-OpenBao` | `8e9f0bb0b71ac617de859a5ff49971fae2289c1e` | #82 @ `787b6dcf` | none configured | none (0 check-runs) | **no** (self-merged) | none (main is a source-only bootstrap) |

Pinned upstream base images (inputs, not release digests):

- Caddy: `docker.io/library/caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c`
- Odoo: `docker.io/library/odoo@sha256:f54272f31d5f77e4146b887efb3761c98480317daf687e4b4b5e76ed8bcc08c5`
- Keycloak: `quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067`
- Kong standby auth: `python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31`

## Gate matrix

| Gate | Middleware | Kong | Caddy | Odoo | Keycloak | OpenBao |
| --- | --- | --- | --- | --- | --- | --- |
| protected_main | PASS | PASS | PASS | PASS | PASS | FAIL B060 |
| exact_main_ci | PASS | FAIL B020 | FAIL B001 | FAIL B001 | PASS | MISSING B060 |
| independent_review | PASS | PASS | PASS | PASS | FAIL B050 | FAIL B060 |
| signed_immutable_artifact | FAIL B010 B001 | MISSING B021 | FAIL B030 | FAIL B040 B001 | MISSING B051 | MISSING B061 |
| staging_digest_readback | MISSING B002 B011 | MISSING B002 | MISSING B002 | MISSING B002 | MISSING B002 | MISSING B002 |
| identity_route_matrix | MISSING B012 | FAIL B022 | FAIL B031 | MISSING B041 | FAIL B052 | MISSING B061 |
| secret_binding | MISSING B006 | FAIL B023 B006 | MISSING B006 | MISSING B006 | MISSING B006 | MISSING B061 B006 |
| backup_restore | MISSING B003 | MISSING B003 | MISSING B003 | MISSING B003 | MISSING B003 | MISSING B003 |
| rollback_rehearsal | MISSING B004 | MISSING B004 | MISSING B004 | FAIL B004 | MISSING B004 | MISSING B004 |
| monitoring_continuity | MISSING B005 | MISSING B005 | MISSING B005 | MISSING B005 | MISSING B005 | MISSING B005 |

Blocker ids are abbreviated; the full id is `PAS251-Bnnn` in `blocker-matrix.json`.

## Design review (source level)

- **Caddy → Kong → Middleware:8095.** Four repositories pin the same route contract, `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`: Middleware, Kong, Caddy and Keycloak. It lists 117 operations: 105 `shared_edge` to `middleware-integration-api:8095`, 10 denied and 2 `private_only` to `odoo:8069`. Kong main has exactly 105 openid-connect routes to that upstream. Each carries a post-function identity-header scrub, correlation-id, fail-closed Redis rate limiting and size limiting. Kong main also has 10 `request-termination` denials. Caddy has no direct route to 8095. Two defects remain:
  - Caddy's transitional `@realtime` handler and its legacy catch-all forward client identity headers unscrubbed (B031).
  - Production Kong was last read back on 2026-09-06, and that readback shows legacy routes and upstreams that differ from main (B022).
- **Token/JWKS.**
  - Middleware pins the per-environment issuer and requires `KEYCLOAK_JWKS_URL == <issuer>/protocol/openid-connect/certs`, `aud=middleware-api`, RS256, an `azp` allowlist and a lifetime of 300 s or less.
  - Kong validates the same issuer by OIDC discovery with per-route scopes.
  - Keycloak sets a 300 s access-token lifespan but no explicit `defaultSignatureAlgorithm` and no key-rotation policy. Its v3 Middleware access contract is `PREPARED_DISABLED` (B052).
- **OpenBao references.** Middleware stores references only. The vendored schema pin `8762a999da747a9450d73dc876718a3f70a3fb47fd1e065689cdf2357849a665` verifies, but its owner contract is absent from OpenBao main. OpenBao main has no policies, auth roles, audit or unseal custody (B006, B061). Kong still uses the env vault (B023).
- **Odoo ACL/readback.** The bridge group has scoped CRUD without unlink, and grants nothing on `project.task`. The PAS-46 deterministic readback is unmerged on both sides, and the only staging evidence is stale (B041).
- **Listener trust.** `--forwarded-allow-ips=127.0.0.1` means Middleware does not trust Kong's `X-Forwarded-For`. This fails safe and is recorded as an observation, not a blocker.
- **Governance.**
  - The Actions billing lock (B001) is the largest single blocker. It has been recorded since 2026-09-17 and was reconfirmed at 2026-09-25T00:19Z.
  - Kong main was merged with a red required check, although its ruleset lists no bypass actors (B020).
  - Three pre-transfer `appolon1908-hue` identities remain in runtime-authority positions: the Keycloak image pattern, the Caddy signed release, and the OpenBao secret-reference `$id`.
  - `config/production-integration-lock.v1.json` (2026-09-13, `NO_GO`) is stale, and this candidate does not rely on it.

## Reused evidence

- PAS-27 release lane: `docs/evidence/pas27-schema-0067-rc-20260921/`. The release was denied, `TARGET_IMAGE_DIGEST=PENDING_OWNER_PACKAGE_ACCESS`, and the F-07 deploy-script receipt mismatch is recorded there.
- Canonical identity: `docs/evidence/canonical-core-architecture-20260918/07-identity.md`.
- Monitoring/OpenBao runtime gate: `docs/evidence/monitoring-openbao-runtime-20260917/FINAL-GATE.md`, with `STAGING_*_GO=NO`.

## Local verification (not a substitute for exact-SHA CI)

The following suites were run on the development host (Python 3.14.4; the runtime image pins 3.14.7) against base `0606b0d`: the route contract, secret reference, edge certification harness, Odoo readback/transport/acceptance/staging gate, scraper JWT, core config authority and security. Result: **177 passed, 0 failed**. The certificate tests and validator for this package are also run locally. They prove internal consistency only.

```
python scripts/validate_core_platform_certificate.py          # prints CERTIFICATE=BLOCKED, CONSISTENT=yes
python -m pytest -q tests/test_core_platform_certificate.py
```

## Order to clear (each step produces evidence; none is performed here)

1. Restore Actions billing (B001). Re-run the required checks on each exact main, and fix Kong `security` (B020).
2. Grant Middleware GHCR package write and run `release.yml` on exact main (B010). Build, sign and record the Kong, Caddy, Odoo and Keycloak digests under `ingtrader21-spec` (B021, B030, B040, B051).
3. Protect OpenBao main and promote its reviewed runtime authority and secret-reference contract (B060, B061, B006). Re-review Keycloak main at its exact head (B050).
4. Land the governed fixes for the Middleware deploy receipt (B011), the Caddy bypass scrub (B031), Keycloak RS256 and key rotation (B052), and Odoo PAS-46 readback (B041).
5. Deploy the exact digests to staging. Run the edge identity/route matrix, Odoo ACL/readback, OpenBao binding, backup/restore, rollback rehearsal and monitoring readback (B002 to B005, B012, B022).
6. Regenerate this candidate with every gate cited. The validator admits `READY` only when every gate is `PASS` and every blocker is `CLEARED`.
