# PAS-179 — Deploy-readiness repair: post-transfer signing identity and core caller repins

Linear: [PAS-179](https://linear.app/passion-fruit/issue/PAS-179/deploy-readiness-repair-post-transfer-signing-identity-and-repin-core)
Source repository: `ingtrader21-spec/Infustruction-repo` (GitHub repository id `1350724865`)
Recorded: 2026-09-21 (UTC), session `middleware-06`. All commands and logs in this directory are reproducible from the
`scripts/` folder against the SHAs named below. Nothing here deployed, built, signed or published anything.

## 1. Outcome in one paragraph

PR [#126](https://github.com/ingtrader21-spec/Infustruction-repo/pull/126) (head `60eff4c3ea848a202561412610728000de299f29`)
was squash-merged by `appolon1908-hue` at 2026-09-21T12:48:25Z as **`5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636`**
(tree `e0699d97…`, byte-identical to the head tree). The merged change does repair the reusable workflows' Sigstore
identity (both `called_identity_pattern` sites and the upstream `WORKFLOW` authority now name
`ingtrader21-spec/Infustruction-repo`), and the merged tree passes 7 of the 9 PR-time workflows when executed
locally on Ubuntu with the exact CI commands. The other two are governance gates that are **still red on main after
the merge**, both verified by execution, neither fixable by a one-line patch: (a) the `Production orchestrator contract` check fails
because #126 changed the byte-pinned required-check workflow (`5d5f118c…` → `b1c377b6…`) without regenerating the
release-intent pin chain, and (b) the `pull_request_target` `Independent release policy review` fails for every PR
because main's `scripts/validate_release_policy_review.py` still binds the pre-transfer slug. A verified repair
candidate for both — a two-validator pin generation plus the review-gate identity — is included as
`infustruction-repair-candidate.patch` (local commit `018e4d04`, tree `f1e46d35…`), all ten Linux checks PASS. It is
**not pushed**: it modifies Infustruction trust artifacts and needs the owner's go plus kazan555 review. Hosted CI for
`Infustruction-repo` has not executed a single step today (account billing gate on private repositories), so no
exact-head hosted result exists for #126, for main, or for the candidate.

## 2. Exit criteria

| Criterion | State | Basis |
|---|---|---|
| `REUSABLE_DEPLOY_READINESS` | **PASS (local Linux)** / hosted **NOT EXECUTED** | `certify-60eff4c-rerun-20260924.log`: deploy-readiness build-context, container-contract and release-assets suites PASS on tree `e0699d97`; hosted jobs zero-step (billing) |
| `POST_TRANSFER_WORKFLOW_IDENTITY` | **PASS** | `tests/test_upstream_signing_identity.py` 10/10 (authority derived from workflow text = `ingtrader21-spec/…`); both `called_identity_pattern` sites and `WORKFLOW` at `5b8cdbb8` name the post-transfer owner; OIDC issuer, keyless flow, caller-identity alternative unchanged |
| `PROVENANCE_INTEGRITY` | **PASS (python parts) / carried** | `tests/test_reusable_provenance.py` 44 passed, 1 skipped; predicate generation OK (`certify-60eff4c-rerun-20260924.log`; also `verify-repair-018e4d04.log`). The Go/cosign round-trip was hosted-green on `09703be` (run 35561063743) and no provenance-relevant file changed between `09703be` and `5b8cdbb8` (only `production-orchestrator-contract.yml`) |
| `SOURCE_AUTHORITY_MATRIX` | **PASS** | `scripts/validate_production_source_authority_matrix.py` → `SOURCE_AUTHORITY_MATRIX=PASS`; gitleaks 8.30.1 `no leaks found`; `GITLEAKS_POLICY_REGRESSIONS=PASS (23 cases)`; `test_pr30_evidence_authority` 5/5 |
| `PRODUCTION_ORCHESTRATOR_CONTRACT` | **FAIL on main `c288723b`** → **PASS on candidate `018e4d04`** | main: `validate-release-intent.py --self-test` → `required check workflow definition drift: appolon1908-hue/Infustruction-repo:.github/workflows/production-orchestrator-contract.yml` (finding F1). Candidate: `RELEASE_INTENT_SELF_TEST=PASS`, `PRODUCTION_ORCHESTRATOR_CONTRACT=PASS` (`verify-repair-018e4d04.log`) |
| `CALLER_REPIN_SHA` | **RECORDED** | `5b8cdbb8819863c9230d9bc3a39f2aa9b57e2636` — see `caller-repin-plan.md` |
| `PRODUCTION_GO` | **NO** | No runtime deployment from this mission; Caddy staging not run |

## 3. Reproduction of the hosted failures on exact head `60eff4c`

All 9 PR-triggered workflows (14 jobs) on `60eff4c` completed with **zero steps** and the check-run annotation
*"The job was not started because recent account payments have failed or your spending limit needs to be
increased"*. Re-running all nine at 12:44Z (attempt 2; Repository Name Authority attempt 3) reproduced the same
zero-step result. The post-merge `push` runs on `5b8cdbb8` (12:48Z) and `c288723b` (12:49Z) are zero-step too.

Why Middleware- CI runs while Infustruction's does not: `ingtrader21-spec/Middleware-`, `Caddy`, `Kong`, `Keycloak`
and `Odoo` are **public** (free hosted minutes); `Infustruction-repo`, `N8N` and every `Codestra-*` monitoring repo are
**private** and bill to the ingtrader21-spec account. The gate is a billing/visibility owner action, not a code
defect. Run ids: 35593324392, 35593324361, 35593324604, 35593324601, 35593324468, 35593324463, 35593324288,
35593324091, 35593321234 (PR), 35601684802…35601684654 (push 5b8cdbb8), 35601755706…35601756076 (push c288723b).

The only hosted runs that ever executed for this PR were on the first head `09703be` (04:27Z): 7 green, 2 red —
`Production orchestrator contract` (`repository is outside the protected catalog identity map`) and `Independent
release policy review` (`RELEASE_POLICY_REVIEW=FAIL: workflow repository mismatch`). The second commit `60eff4c`
addressed only the first and was never executed by a runner.

## 4. Local Linux certification of the merged tree (`60eff4c` ≡ `5b8cdbb8`)

First run: WSL Ubuntu; re-run: native Linux. Both Python 3.14.4 (CI: ubuntu-24.04 python3 / setup-python 3.11–3.12), PyYAML 6.0.3, pytest 8.4.2,
gitleaks 8.30.1 (sha256 verified). Env mirrored: `GITHUB_REPOSITORY=ingtrader21-spec/Infustruction-repo`,
`GITHUB_REPOSITORY_ID=1350724865`, `EXPECTED_SHA=60eff4c…`, `COMPARISON_SHA=9d32d421…`. Log: `certify-60eff4c-rerun-20260924.log`.

**Erratum (2026-09-24).** The first run, `certify-60eff4c.log`, is kept unchanged as recorded, but its SUMMARY block is
not trustworthy. Its `run_check` called each check function as an `if` condition. Bash suspends `errexit` there,
so each check reported only the exit status of its last command. Three summary lines were wrong:
`production-orchestrator-contract PASS` (the validator failed, and only the trailing `git diff --check` passed);
`calling-contract-pin PASS` (the check script path did not exist, so the check never ran); and the provenance
predicate step, which likewise never ran. `scripts/certify.sh` now runs every check in a subshell with `errexit`
re-armed, resolves its helper scripts from its own directory, and takes the PR JSON as an input. The re-run on the
same exact head (tree `e0699d97…`) executed all nine checks and is the evidence cited here. The count in §1 was
corrected from 8 to 7 of 9 accordingly. `verify-repair-018e4d04.log` is unaffected because
`scripts/verify_repair.sh` chains each check's commands with `&&`.

| Workflow | Result |
|---|---|
| Validate upstream signing identity | PASS (10 tests) |
| Production orchestrator contract | **FAIL** — `validate()` passes under `env -u GITHUB_REPOSITORY`, then the release-intent self-test reports workflow definition drift (F1). Without the wrapper: `outside the protected catalog identity map` (the `09703be` failure) |
| Release policy review tests | PASS (14 + 8 tests) |
| Deploy readiness build context regression | PASS (3 tests, 10 + 2 pytest) |
| source-authority-matrix | PASS (`SOURCE_AUTHORITY_MATRIX=PASS`, no leaks, 23 policy regressions) |
| calling-contract-pin | PASS (`CALLING_CONTRACT_PIN=PASS`, `CALLING_CONTRACT_MERGE_RESULT=PASS`) |
| Provenance integrity regression | PASS (python parts; Go round-trip carried from `09703be`) |
| Repository Name Authority | PASS (aliases, transition, 32 tests) |
| Independent release policy review (main's validator, real PR #126 JSON) | **FAIL** — `workflow repository mismatch` (F2) |

## 5. Findings

**F1 — `Production orchestrator contract` is red on main after #126 (new, caused by #126).**
`.codestra/validate-release-intent.py` pins `ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = 5d5f118c…` — the
portfolio-wide canonical bytes of `production-orchestrator-contract.yml` (12 repositories share the constant). Its
`--self-test`, invoked as the last step of `.codestra/validate-production-orchestrator-contract.py`, hashes the local
workflow and now sees `b1c377b6…`. The `env -u GITHUB_REPOSITORY` wrapper therefore moved the failure from
`validate()` to the self-test; the check cannot pass on `5b8cdbb8`/`c288723b` under any runner. The PR body's claim
"no validator source/hash was changed" was true but insufficient: the *workflow* is hash-pinned.
Attribution: the drift comes from the second commit only — `60eff4c` "fix(governance): bind orchestrator validation
to stable repository ID" (author identity `ingtrader21-spec`, 2026-09-21T11:17Z), added to the branch after the
first head `09703be` (author `Ralph Appolon`, 04:26Z, the signing-identity fix proper, which touched only the two
reusable workflows). The #126 author session (middleware-8f) reports the second commit was not theirs.

**F2 — `Independent release policy review` is red for every PR (pre-existing since the transfer).**
main's `scripts/validate_release_policy_review.py` binds `REPOSITORY = "appolon1908-hue/Infustruction-repo"` and
requires both `GITHUB_REPOSITORY` and `pr.base.repo.full_name` to equal it. Because the workflow is
`pull_request_target` and executes the validator **from main**, no PR can fix its own check; main must be repaired
first. The kazan555 exact-commit approval requirement (`REVIEWER_ID 77101516`) is intact and should stay.

**F3 — Merge governance as observed (fact, no judgement).** #126 was merged with all hosted checks zero-step and
with an `APPROVED` review from `appolon1908-hue` on `60eff4c`, not from the policy's independent reviewer
(`kazan555`, id 77101516). The repository is private on a plan without branch protection, so GitHub enforced nothing.

**F4 — Repairing F1 is a trust generation, not a patch.** The shared orchestrator validator (`6006bbc7…`, byte-identical
to `SHARED_PRODUCTION_VALIDATOR_SHA256`) binds the release-intent validator by
`release_validator_security_fingerprint`, which covers every byte except five normalized hash bindings —
`EXPECTED_CHECK_WORKFLOW_SHA256` is **not** normalized. Re-pinning the workflow hash changes the fingerprint
(`15dbaa6d…`), which the orchestrator validator enforces; the orchestrator validator's own digest is then pinned
back by the release validator through a normalized binding. Two files must move together.

**F5 — Pre-existing stale release-intent pins for this repository (not caused by #126).**
`EXPECTED_CHECK_WORKFLOW_SHA256["…Infustruction-repo"][source-authority-matrix.yml] = 1ca826d1…` has never matched
the file at any commit since #116 (`dde1f59`, 2026-09-10; actual `90bcf50c…`), and
`EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256["…Infustruction-repo"] = 218de464…` matches no recent main tree
(9d32d421 → `1b7189e1…`, 5b8cdbb8 → `b936eedb…`, c288723b → `cf609de9…`). Both only bite the remote release-intent
flow (`--recheck-protected-gates`), not PR checks; they belong to the next release generation.

**F6 — Downstream pins of Infustruction trust bytes.** `ingtrader21-spec/Keycloak` `config/bootstrap/protected-candidate.json`
lists `.codestra/validate-release-intent.py` = `049fc925…` and `production-orchestrator-contract.yml` = `5d5f118c…`.
Any Infustruction generation (the candidate below included) invalidates that snapshot; the Keycloak lane must re-pin.

## 6. Repair candidate (verified, not pushed)

Branch `fix/post-transfer-governance-pins-20260921` off main `c288723b`, local commit `018e4d04fed88fcbbafd8cf1695bc35c15f462a6`
(tree `f1e46d357fcc40ff6766dc080e0b487a9d735b78`); patch: `infustruction-repair-candidate.patch`
(sha256 `77998418b4b602a0…`). Generated by `scripts/generate_repair.py` — the two digests are derived by the
validators' own functions and re-verified, not typed.

| File | Change |
|---|---|
| `.codestra/validate-release-intent.py` | `INFUSTRUCTION_ORCHESTRATOR_CONTRACT_WORKFLOW_SHA256 = b1c377b6…` used only for the Infustruction entry (the canonical `5d5f118c…` constant is untouched for the other 11 repos); `INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256 = 910d111c…` (normalized binding) for the Infustruction executable entry |
| `.codestra/validate-production-orchestrator-contract.py` | `INFUSTRUCTION_PRODUCTION_VALIDATOR_SHA256` joins `RELEASE_VALIDATOR_NON_SELF_REFERENTIAL_BINDINGS`; `INFUSTRUCTION_RELEASE_VALIDATOR_SECURITY_SHA256 = 13c559ed…` replaces the STANDARD fingerprint for the Infustruction key only |
| `scripts/validate_release_policy_review.py` | `REPOSITORY = "ingtrader21-spec/Infustruction-repo"`; new `GITHUB_REPOSITORY_ID == 1350724865` binding; `REVIEWER_ID` unchanged |
| `tests/test_release_policy_review.py` | regression guard: post-transfer identity, pre-transfer slug rejected |

Chain closure: fingerprint(release-intent) = `13c559ed…` → written into orchestrator validator → sha256(orchestrator
validator) = `910d111c…` → written into release-intent as a normalized binding → fingerprint re-computed = `13c559ed…`
(stable). Verification (`verify-repair-018e4d04.log`): all ten checks PASS, including
`RELEASE_INTENT_SELF_TEST=PASS`, `PRODUCTION_ORCHESTRATOR_CONTRACT=PASS`, Repository Name Authority PASS (the new
owner slug in a `scripts/*.py` file is accepted), and the review gate end-to-end: a synthetic open PR bound to the
post-transfer repository with a kazan555 exact-head approval → `"status": "PASS"`; `GITHUB_REPOSITORY_ID=1` →
`workflow repository ID mismatch`; pre-transfer slug in env → `workflow repository mismatch`.

Not done by the candidate (deliberately): the pre-transfer keys in `EXPECTED_IDENTITIES`/`APPROVED_*` tables, the
name-authority manifest, F5 pins, and the shared-validator identity-map programme that `ingtrader21-spec/Middleware-`
already completed for itself (`ingtrader21-spec/Middleware-` keys + `run-trusted-production-orchestrator.py`
launcher). That is the durable path (keeps the canonical workflow, retires `env -u`) and is the repository-name
transition programme's scope; the candidate is the minimal step that makes main green with what was merged.

## 7. Owner decisions required (blocking)

1. **Hosted CI for private repositories**: fix billing for `ingtrader21-spec`, or make `Infustruction-repo` public.
   Note that public callers (`Caddy`, `Odoo`) **cannot** call a private repository's reusable workflow at all
   (startup `workflow file issue`), so visibility also gates their repins.
2. **Adopt the repair candidate as an Infustruction PR** (writer to be named; middleware-8f authored #126,
   middleware-06 prepared this candidate) and obtain kazan555 review on its exact head — or choose the durable
   identity-map generation instead.
3. **Merge discipline**: #126 was merged red and without the policy reviewer; decide whether main stays as is or a
   revert-and-regenerate is preferred.

## 8. Files

- `certify-60eff4c-rerun-20260924.log` — local Linux execution of all 9 PR workflows on the merged tree (authoritative)
- `certify-60eff4c.log` — first run, kept as recorded; its SUMMARY is superseded (see §4 erratum)
- `verify-repair-018e4d04.log` — same plus release-intent self-test and review-gate end-to-end on the candidate
- `infustruction-repair-candidate.patch` — `git format-patch` of `018e4d04`
- `caller-repin-plan.md` — exact `uses:` lines, preconditions, sequence, ownership
- `scripts/certify.sh`, `scripts/verify_repair.sh`, `scripts/generate_repair.py`, `scripts/calling_contract_check.py`,
  `scripts/provenance_generate.py` — reproduction
