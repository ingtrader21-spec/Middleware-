# Edge digest-chain convergence and deploy-readiness identity gate — 2026-09-21

Mission: PAS-162 (CADDY-03A) Agent 1 — make the Middleware → Kong → Caddy digest chain self-consistent on the accepted authorities, then clear what the merge exposed: the reusable deploy-readiness workflow rejecting its own post-transfer Sigstore identity, a Caddy route generator that had drifted from reviewed edge policy, and the Kong route-parity pin. Source-only: no runtime, deployment, DNS/certificate, registry or provider effect was performed. Everything below was certified at exact SHAs from Windows-hosted worktrees with sibling files extracted from the exact accepted commits; Linux CI is the authority wherever the host could not run a step.

## Verdicts

| Verdict | Value | Basis |
|---|---|---|
| `MIDDLEWARE_KONG_CADDY_DIGEST_CHAIN` | **PASS** | Middleware `2862af0a` publishes `9c32daec…`; Kong protected main `3e68cb2a` pins `9c32daec…`; Caddy's chain record requires and records `9c32daec…` on both sides of the handoff. Strict Kong validator PASS against Caddy PR head `e292479`, merged main `cd912a1` and current main `22c6d51`. |
| `CADDY_DIGEST_CHAIN_RECORD` | **PASS** | `config/edge-contract-chain.v1.json` no longer carries the stale Kong `7580123d…` / `STALE_REPIN_REQUIRED`; its Postman digest now equals the committed collection bytes and is test-pinned. |
| `CADDY_EDGE_EXIT_GATES` | **PASS** (PAS-145, on Caddy main) | `API_URL_REGISTRY`, `PUBLIC_HOST_REGISTRY`, `UPSTREAM_REGISTRY`, `WEBHOOK_REGISTRY`, `PLATFORM_V1_TO_KONG`, `AUTOMATION_V2_TO_KONG`, `PRIVATE_NAMESPACE_DENIAL`, `DATABASE_PUBLIC_EXPOSURE=0`, `POSTMAN_API/WEBHOOK/PRIVATE_ROUTE_CERTIFICATION`, `POSTMAN_DIGEST_CHAIN` — recorded by PAS-145 at Caddy main after `e292479`. |
| `UNKNOWN_ROUTE_FALLBACK` | **TRANSITIONAL** | Deliberately retained. `UNKNOWN_ROUTE_FALLBACK=0` is not claimed. |
| `DEPLOY_READINESS_IDENTITY_FIX` | **MERGED, UNPROVEN** | Infustruction-repo #126 merged (`5b8cdbb8`); Caddy caller repin open (#184). Proof requires a Caddy main push whose `immutable-candidate` job starts, which is blocked by repository visibility (below). |
| `PRODUCTION_GO` | **NO** | Never issued by this mission. |

## Repositories, branches, SHAs and pull requests

| Repository | Accepted / base SHA | Result | Pull request | State |
|---|---|---|---|---|
| Middleware- | `2862af0aa97367b18cb360af69212abe4243a1ac` (accepted; `origin/main` has since advanced to `4f8069e7` → `bd406a65` → `8ecf6e9b`, contract unchanged) | — | — | authority only |
| Kong | protected main `3e68cb2a4955bd71ddb3e839f4d9e3770465fc08` | parity repin `8dddd2a` | ingtrader21-spec/Kong#115 | open — all 10 checks green, 1 approval required |
| Caddy | PR #175 head `56fd73d1647f7023cb07bdb14b1f72522c7b48d8` | `e29247990a05c6ed1d8c88bfd48a2816dfa90770` → merged `cd912a1e1a3caeb370d70b16d195428f97c8c56c` (tree identical) | ingtrader21-spec/Caddy#175 | **merged** 2026-09-21T04:11:56Z by kazan555 |
| Caddy | main `22c6d51ed2f5340139177131fb810e787f0f7550` (after PAS-145 #177/#178/#180 and PAS-146 #179) | generator fix `eef2647` | ingtrader21-spec/Caddy#181 | open — source authority green, deadlocked by ruleset (below) |
| Caddy | main `22c6d51…` | deploy-readiness repin `a70aac0` | ingtrader21-spec/Caddy#184 | open — cannot start until Infustruction-repo is public (below) |
| Infustruction-repo | `9d32d421c8272ef33b7a442ac81617bea6d16897` | `09703be` (+ `60eff4c` one-line governance fix added before merge) → merged `5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636`; `origin/main` now `c288723b` (docs ADR on top, workflow bytes unchanged) | ingtrader21-spec/Infustruction-repo#126 | **merged** 2026-09-21T12:48:25Z by appolon1908-hue |
| Keycloak | `45a487d71a516ae3039b00c250752897469ffe7a` | — | — | authority only (caller contract + token matrix) |

## Digest chain

| Link | Value | Verification |
|---|---|---|
| Middleware public contract | `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b` | sha256 over `json.dumps(contract, sort_keys=True, separators=(",", ":"))` of `deploy/public-api-route-contract.json` at `2862af0a`; `.sha256` pin agrees; 117 routes (105 shared_edge / 10 denied / 2 private_only). Identical at `4f8069e7`, `bd406a65`, `8ecf6e9b` — no commit has touched the contract since `2862af0a`. |
| Kong Middleware contract | `9c32daec…` | canonical digest of `config/middleware-public-api-route-contract.v1.json` at Kong main `3e68cb2a`; gateway retries 0; upstream `middleware-integration-api:8095`. |
| Caddy chain record | `kong.source_sha=3e68cb2a…`, `kong.middleware_contract_sha256=9c32daec…`, `kong.required_sha256=9c32daec…`, `kong.status=PASS`, `middleware.source_sha=2862af0a…` | `config/edge-contract-chain.v1.json` at Caddy main; asserted by `tests/test_edge_api_url_webhook_boundaries.py`. |
| Caddy vendored contract | `9c32daec…` | `config/middleware-public-api-route-contract.v1.json` canonical digest; test-linked to the chain and public-edge registry pins by `tests/test_generate_middleware_edge_contract.py` (Caddy #181). |
| Postman collection | `6d287acd5dc917f0e7db6bea79f941a894acac87885d5bd1f4081c55529622bc` | sha256 of the committed LF bytes of `postman/Caddy-V3-Edge-Certification.postman_collection.json`; the previously recorded `9a9904ea…` matched neither the bytes nor any canonical serialisation and was replaced. PAS-145 records the same value. |
| Caddy source / edge-contract / config digests | `GENERATED_AT_CERTIFICATION` | Filled at exact-head certification; never self-referenced from source. |

## Gates executed

| Gate | Where | Result |
|---|---|---|
| Caddy pytest | `e292479`, CI-pinned pytest 8.4.2 (validate-source and validate-merge-result) | 103 passed / 3 skipped (baseline `56fd73d`: 102 / 3) |
| Caddy pytest | main `22c6d51` + #181 | 125 passed / 3 skipped / 18 subtests (baseline 122) |
| Caddy repository authority, Caddy→Kong contract | every Caddy head above | `CADDY_REPOSITORY_AUTHORITY=PASS`, 14/14, `KONG_ROUTE_CONTRACT_BIDIRECTIONAL=PASS` |
| Strict cross-repo parity (`Kong/scripts/validate_kong_cross_repo_parity.py`, no `--allow-pending-lane-a`) | Middleware `2862af0a` files, Keycloak `45a487d7` files, Kong main, Caddy `e292479` / `cd912a1` / `22c6d51` | `KONG_CROSS_REPO_PARITY=PASS`, `CADDY_KONG_MIDDLEWARE_DIGEST_CHAIN=PASS`, `KONG_FINAL_CONTRACT_REPIN=PASS`, `KEYCLOAK_CALLER_TOKEN_CONTRACT=PASS`; `caddy_snapshot_kong_status` STALE_REPIN_REQUIRED → PASS |
| Kong Postman generator | Kong main / #115 | `KONG_POSTMAN_GENERATION=PASS` |
| Caddy exact-head CI | `e292479` | Validate Caddy source authority PASS (run 35558762577), Codestra deploy readiness PASS (35558762856), Monitoring onboarding PASS (35558762420) |
| Caddy main-push CI | `cd912a1` | source authority PASS (35560075322); deploy readiness FAIL in `immutable-candidate` (35560075759) — root cause below |
| Kong #115 CI | `8dddd2a` | validate, kong-config, security, certify, manifest-check, merge-result, release-preflight, source-head, static-certification — all PASS |
| Infustruction #126 CI | `09703be` | validate-signing-identity, provenance-integrity (source-head + merge-result), regression, repository-name-authority, release-policy-review-tests, calling-contract verify-head/merge-result, source-authority-matrix PASS; `production-orchestrator-contract` and `release-policy-review` red — pre-existing on main since the 2026-09-17 transfer (validator-side identity drift, not touched) |
| `git diff --check` | every commit | PASS |

## Findings

| # | Finding | Root cause | Disposition |
|---|---|---|---|
| F1 | Caddy digest-chain record self-inconsistent (`STALE_REPIN_REQUIRED` while Kong already pinned the final digest) | Record predated Kong's repin | Fixed in Caddy #175 `e292479` (merged) |
| F2 | Caddy chain recorded an unverifiable Postman digest | Value never derivable from the committed bytes | Replaced with the committed-bytes digest; test-pinned; PAS-145 concurs |
| F3 | Every caller's main-push `immutable-candidate` fails: `cosign verify` expected SAN `…appolon1908-hue/Infustruction-repo/…`, got `…ingtrader21-spec/Infustruction-repo/…@9d32d421…` | Reusable workflow hard-coded its pre-transfer owner at both identity sites; the upstream variant's `WORKFLOW` authority likewise; job skipped on `pull_request` so no PR check could see it | Fixed in Infustruction-repo #126 (merged `5b8cdbb8`); Caddy repin #184 open; other callers (N8N/Odoo `@1b4a9081`, Codestra-Alertmanager/Alloy/Loki/Prometheus/Telemetry/Tempo `@92f73103`, Codestra-Node-Exporter `@f509d61a`) owned by PAS-179 |
| F4 | `scripts/generate_middleware_edge_contract.py` rendered only `/metrics`; re-running it would silently drop the `/metrics/*` public denial (`GENERATOR_RENDER_COMPARE=DRIFT`); nothing in CI runs the generator | #175 edited contract and site by hand | Fixed + guard test in Caddy #181 (open) |
| F5 | Kong parity record named Caddy's pre-merge head `56fd73d` / PR 175 | Merge happened after the record | Repinned to Caddy main `22c6d51` in Kong #115 (open) |
| F6 | Kong required `security` check red: 4 gitleaks findings | Full-history `gitleaks git --all` scans two superseded lane branches (`mission/kong-v3-integration-parity-20260920`, `mission/kong-v3-identity-security-20260920`) whose pre-rename lines carry the public Keycloak commit SHA and a synthetic `TEST_SYN` idempotency key; main history alone scans clean with the repo config | Four exact `commit:file:rule:line` fingerprints in `.gitleaksignore` (repo convention), Kong #115; CI `security` PASS |
| F7 | Stale local `converge/caddy-v3-final-20260920` ref (7044bc6) would have deleted the registries/chain/Postman on a force-push | Diverged pre-rewrite lineage | Reset to origin `e292479`; lineage parked at `archive/converge-local-7044bc6-20260921` |

## Owner blockers (not resolvable from source)

| Blocker | Effect | Required owner action |
|---|---|---|
| Infustruction-repo is private while Caddy is public | GitHub refuses a public repository's `uses:` of a private repository's reusable workflow → `Codestra deploy readiness` `startup_failure` on every Caddy PR and main push, regardless of pin | Make Infustruction-repo public (or Caddy stops calling it) |
| Caddy ruleset 22657889 "Protect Caddy promotion branches" also targets `main` and requires `promotion-guard` + `immutable-release-gate`, which no main workflow reports | Every Caddy PR is deadlocked (`BLOCKED`) — #181 and #184 cannot merge | Remove `main` from ruleset 22657889 (22138259 "Protect main" is the correct one) |
| GitHub Actions on private repositories of `ingtrader21-spec` refused to start jobs ("recent account payments have failed or your spending limit needs to be increased"); public repositories run on free minutes | No CI for private repos; Infustruction #126 merged with zero-step checks | Restore billing / spending limit |
| Unattributed commits `2a20fc0` / `66e9154` on Kong #115 repin Middleware `2862af0a` → `bd406a65` across Kong config, validators, tests and docs (Caddy, Kong main and the PAS-146 candidate all pin `2862af0a`; Middleware main is already `8ecf6e9b`, contract unchanged) | Changes the accepted Middleware authority; all six peer sessions disclaim the push | Rule on the accepted Middleware SHA. Keep `2862af0a` → revert those two commits on #115; adopt a newer SHA → repin Caddy chain/registry/generator in the same wave. Caddy repin held until ruled |
| Infustruction-repo validators still keyed on `appolon1908-hue/…` (`.codestra/validate-production-orchestrator-contract.py` `EXPECTED_IDENTITIES`, `policy/scripts/validate_release_policy_review.py`) | `production-orchestrator-contract` and `release-policy-review` red on every Infustruction PR since the transfer | Governed repair, owned by PAS-179 |
| Independent approvals | Kong #115, Caddy #181, Caddy #184 each need one | Reviewer |

## Not done, on purpose

- The transitional legacy unknown-route fallback was not removed; `UNKNOWN_ROUTE_FALLBACK=0`, `UNCLASSIFIED_PUBLIC_ROUTES=0`, `UNCLASSIFIED_WEBHOOKS=0`, `UNCLASSIFIED_UPSTREAMS=0` are not claimed.
- `docs/caddy-v3-edge-transport-audit.md` still cites `7580123d…` as historical audit context and was left as written.
- `scripts/certify_caddy_edge_api.py` (PAS-145) is not wired into `scripts/validate-ci.sh`; noted for that lane.
- No ruleset, branch-protection or visibility change was made by this mission.
