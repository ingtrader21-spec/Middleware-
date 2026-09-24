# PAS-146 governance preflight — 2026-09-21

Evidence for steps 1–2 of the PAS-146 "current staging objective" (CADDY-05):
verify branch-protection/review enforcement before any runtime action, and freeze
the exact Caddy / Kong / Keycloak / Middleware SHAs, the route-contract digest and
the immutable Caddy runtime. Machine-readable record:
[`pas146-governance-preflight-freeze.v1.json`](pas146-governance-preflight-freeze.v1.json).

Everything below was read from the GitHub API, the Docker Hub registry and fresh
clones. No runtime, DNS/TLS, provider or business effect was produced.
Linear: PAS-146 (freeze thread), PAS-178 (protection decision).

## 1. Protected `main` requires review + CI

### Before (11:32Z)

| Repo | Visibility | `branch.protected` | Cause |
|---|---|---|---|
| Middleware- | public | `true` | classic protection + rulesets 22120968 / 22196852 |
| Caddy | private | `false` | plan gate |
| Kong | private | `false` | plan gate |
| Keycloak | private | `false` | plan gate |
| Infustruction-repo | private | `false` | plan gate |

The plan gate: `GET /branches/main/protection`, `GET /rules/branches/main` and
`GET /rulesets` all answered `403 Upgrade to GitHub Pro or make this repository
public to enable this feature`. The owner (`ingtrader21-spec`) is a Free user
account; branch protection and rulesets exist only on public repositories there.
Caddy's `apply-branch-protection.yml` could not help: its only run
(34306189553, 2026-09-09) failed at `test -n "$GH_TOKEN"` because
`CODESTRA_GITHUB_ADMIN_TOKEN` is unset, and the PUT would have hit the same 403.

A second, independent owner blocker was confirmed at 11:40Z: GitHub Actions
refused to start jobs on the private repositories ("recent account payments have
failed or your spending limit needs to be increased"; e.g. Infustruction-repo job
106313452241 with zero steps). Public Middleware- jobs kept running.

### Owner decision and result (12:42Z)

Decision: make the repositories public rather than upgrade the plan.

Full-history secret scan before flipping (gitleaks 8.30.1, release checksum
verified, all `refs/heads` + tags): Caddy 21 hits, Kong 13, Keycloak 13,
Infustruction-repo 53 — every hit a commit SHA, sha256 digest, identifier name,
Postman variable name, the RFC 6455 `Sec-WebSocket-Key` sample nonce, a
`$…_SECRET` variable reference, an internal container URL, a `uid:gid` pair or a
gitleaks test fixture. No credential material. Kong's `main` hits are exempted by
the repo's own `.gitleaks.toml` allowlist (`authenticationProfile` catalogue
identifiers); a scan from a bare mirror does not load that file.

| Repo | Visibility | `main.protected` | Live rulesets on `main` (all pre-existing, dormant while private; bypass actors: none) |
|---|---|---|---|
| Caddy | public | `true` | 22138259 *Protect main* — PR, 1 approval, dismiss stale on push, last-push approval, thread resolution, extra approval for unattributed changes, squash only; strict `validate-source` + `validate-merge-result`. 22196743 *server65-default-branch-gates* — PR, 1 approval, linear history. **22657889 *Protect Caddy promotion branches* — see defect below.** |
| Keycloak | public | `true` | 21608098 *Bootstrap protect main* — PR, 1 approval, dismiss stale, last-push approval, code-owner review, thread resolution, squash; strict `validate` + `validate-merge-result`. 22197063 *server65-default-branch-gates*. |
| Kong | public | `true` | 22197413 *server65-default-branch-gates* — PR, 1 approval, dismiss stale, thread resolution, squash, linear history; strict `validate` + `kong-config` + `security`. |
| Infustruction-repo | **private** | `false` | Not flipped — its content is a production topology inventory (`PRODUCTION-API-MATRIX.yaml`, server paths); owner decision. |

PAS-178 minimums 1–6 are met on Caddy, Kong and Keycloak.

**Defect (owner action):** ruleset 22657889 also targets `refs/heads/main` and
requires `promotion-guard` + `immutable-release-gate`, jobs that exist only on
`development`/`test`/`staging`/`production`. Until `main` is removed from that
ruleset's targets, pull requests into Caddy `main` wait forever on "Expected"
checks. `main` stays fully protected by 22138259 + 22196743, which is exactly the
committed `config/github/main-ruleset.json` policy.

## 2. Frozen accepted SHAs

| Authority | Exact SHA | Tree | CI on the exact SHA |
|---|---|---|---|
| Caddy | `22c6d51ed2f5340139177131fb810e787f0f7550` | `9ec70691…` | *Validate Caddy source authority* PASS (35560793449); *Codestra deploy readiness* FAIL (35560793977) at `cosign verify-blob` — reusable workflow `Infustruction-repo@9d32d421` still expects the pre-transfer `appolon1908-hue/…` identity |
| Kong | `3e68cb2a4955bd71ddb3e839f4d9e3770465fc08` | `b84547c3…` | 5/6 push workflows PASS; *Security and supply-chain validation* red on the push run only because `--all` pulled superseded lane branches (PR #115 `security` is green) |
| Keycloak | `45a487d71a516ae3039b00c250752897469ffe7a` | `852efb54…` | 3/3 PASS |
| Middleware | `2862af0aa97367b18cb360af69212abe4243a1ac` | `5f1b04f8…` | MAIN_AFTER_TRUST_CONVERGENCE (#295); validator `850cd5ec…`, launcher `08b5e28a…`, closure `2b0b8e83…`, schema head 0067. Not the current head: `main` advanced through #297, #299, #298, #301 |
| Contract | `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b` | — | canonical-JSON digest of `deploy/public-api-route-contract.json`, 117 routes (105 shared_edge / 10 denied / 2 private_only); file bytes `0724a0c6…`; unchanged on every later `main` |

Cross-repo pins verified on the frozen trees: Caddy → Middleware `2862af0a`,
Kong `3e68cb2a`, Keycloak `45a487d7`, contract `9c32daec`; Kong → Middleware
`2862af0a`, Keycloak `45a487d7`, `9c32daec`; Keycloak → `9c32daec`.

Drift to fix before execution: `release/pas146/caddy-staging-candidate.v1.json`
and `scripts/validate_caddy_staging_candidate.py` in Caddy still carry
`merged_main_sha = cd912a1e…` (pre-#178/#180/#179) and must be re-pinned to
`22c6d51` in a Caddy PR.

Pending ruling: a commit repinning Kong PR #115 from Middleware `2862af0a` to
`bd406a65` was pushed by an unidentified session at ~12:00Z. The digest is
identical, but the named source SHA now differs from Caddy. Either the repin is
reverted (keep `2862af0a`) or Caddy is repinned in the same wave (advance the
accepted authority).

## 3. Frozen immutable Caddy runtime

- Image: `docker.io/library/caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c`
  — verified live on Docker Hub (manifest HEAD 200, `Docker-Content-Digest`
  match). OCI image index = tag `2.10.0-alpine` (`2.10.0` is a different index,
  `133b5eb7…`); `CADDY_VERSION=v2.10.0`, built 2025-04-19; `linux/amd64`
  manifest `sha256:f43d8810c944e27e6f7ea80b165de11dbdab16cff15c8a80d83ae3e1a109a35d`.
- Configuration SHA-256 at `22c6d51`: `f77be0593ce3c728749ee8930ebe21c6f7191bb6c6d47d661a2cee056f50463b`
  (recomputed with `scripts/config_digest.py`; equals the prepared candidate).
  Caddyfile bytes `7294ada0…`. Candidate record `34ca2f5d…`, evidence template
  `816e67e5…`, `PAS146_PREPARATION=PASS`.
- Not available: a signed `deploy-ready-22c6d51…` source bundle. Caddy's
  deploy-readiness uses `artifact_strategy: source-bundle` (no Dockerfile) and
  the cosign identity check fails until `Infustruction-repo#126` is accepted and
  Caddy repins the reusable workflow. Latest existing bundle: `deploy-ready-a1ade1f2…`
  (2026-09-09, pre-V3).
- The running edge is not on the pinned image yet (public `caddy.service` is a
  custom binary; the internal gateway runs `sha256:5f5c8640…` v2.11.4).

## Verdict

```
PROTECTED_MAIN_REVIEW_CI_ENFORCED  Middleware-=YES Caddy=YES* Kong=YES Keycloak=YES Infustruction-repo=NO
ACCEPTED_SHAS_FROZEN=YES
IMMUTABLE_CADDY_IMAGE_DIGEST_FROZEN=YES
SIGNED_DEPLOY_READY_BUNDLE_22c6d51=NO
STAGING_EXECUTION_AUTHORIZED=NO
PROVIDER_EFFECTS=0  BUSINESS_WRITES=0  PRODUCTION_GO=NO
```

`*` Caddy `main` is protected but unmergeable until ruleset 22657889 drops `main`.
