# PAS-179 — completion record (2026-09-24)

PR: [#308](https://github.com/ingtrader21-spec/Middleware-/pull/308), branch `pas-179/deploy-readiness-repair-evidence-20260921`.
Reviewed head: `1867563dfefb27ce28a4d01c0d157edd86085ecf` (tree `ff3a64c9…`, main `0606b0db` is an ancestor).
This record ships with the next commit on that branch. The pushed SHA and the regenerated source-closure pin are in the PR
conversation, because this file is inside the closure it would otherwise have to name.

## Verdict

`PAS179_EVIDENCE=COMPLETE_WITH_CORRECTIONS` · `MIDDLEWARE_TRUST_PINS=FIXED_POINT` · `HOSTED_CI=NOT_EXECUTED (billing lock)` ·
`INFUSTRUCTION_F1_F2=OPEN (owner)` · `CALLER_REPINS=HELD (preconditions)` · `PRODUCTION_GO=NO`

## Review by area

| Area | Result | Basis |
|---|---|---|
| Signing identity (Infustruction `5b8cdbb8`) | **PASS, unchanged since** | `test_upstream_signing_identity` 10/10 on exact head `60eff4c` (tree `e0699d97` = merge tree). Infustruction main is now `e322730c` (#127, docs/agent files only). The reusable deploy-readiness workflows, `production-orchestrator-contract.yml`, `.codestra/validate-release-intent.py` and `scripts/validate_release_policy_review.py` have identical blob SHAs at `5b8cdbb8` and `e322730c` |
| Orchestrator contract (Infustruction) | **F1 still red on main** | Re-run: `required check workflow definition drift` (`certify-60eff4c-rerun-20260924.log`). Repair candidate `018e4d04` still applies: all four patched files have the same blobs at `c288723b` and `e322730c`. Patch sha256 `77998418b4b602a0232128e42994142e70cacfd702b811a544a1023585ce4402` matches README |
| Orchestrator contract (Middleware, this PR) | **PASS locally** | `run-trusted-production-orchestrator.py` in a `pull_request_target` layout (trust root = main `0606b0db`, candidate = PR head) → `RELEASE_INTENT_SELF_TEST=PASS`, `PRODUCTION_ORCHESTRATOR_CONTRACT=PASS`, `PROTECTED_BASE_VALIDATOR_TRUST=PASS` |
| Release-intent / trust authority | **Fixed point, 0 stale** | `scripts/derive_trust_pins.py --check`: `ACTIVE_STALE_BEFORE=0`, `ACTIVE_STALE_AFTER=0`, `LAUNCHER_PARITY=YES`, `UNKNOWN_TRUST_TABLES=0`, `FINAL_RELEASE_SECURITY_FINGERPRINT=63192fd8…`, `FINAL_VALIDATOR_SHA256=15c35ad1…`. The only functional diff in the PR is the generated `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256["ingtrader21-spec/Middleware-"]`. It covers every tracked blob, so it is regenerated whenever the evidence changes |
| Caller repins | **HELD, plan still valid** | Every caller's `origin/main` `uses:` line (Caddy, N8N, Odoo, six `Codestra-*`, Node-Exporter) was re-read on 2026-09-24 and is byte-identical to `caller-repin-plan.md`. No caller moved. `CALLER_REPIN_SHA=5b8cdbb8…` remains correct: its reusable-workflow bytes equal those on Infustruction main |
| API / design flow impact | **None** | The diff touches only `docs/evidence/**` and the one generated pin. No app code, OpenAPI/Postman, workflow, image, signing or registry change |

## Defects found and fixed in this pass (mission-scoped)

1. **False PASS results in `certify-60eff4c.log`.** `scripts/certify.sh` ran each check as `if fn; then`, and Bash
   suspends `errexit` inside such a call. Each check therefore reported only its last command's status. As a result
   `production-orchestrator-contract` showed PASS even though its validator failed, `calling-contract-pin` showed PASS even
   though its script path did not exist, and provenance predicate generation never ran. **Fix:** `run_check` now runs
   each check in a subshell with `errexit` re-armed. Helper scripts resolve from the script's own directory, and the
   PR JSON and work root are explicit inputs. A harness self-test confirmed that a failing middle command and a
   missing script both give FAIL. The re-run on exact head `60eff4c` is recorded as `certify-60eff4c-rerun-20260924.log`:
   7 PASS and 2 FAIL (F1, F2); `CALLING_CONTRACT_PIN=PASS`; `provenance predicate generated: True`; gitleaks
   `no leaks found`. The original log is kept verbatim, and README §4 carries an erratum.
2. **README overcount.** §1 said the merged tree passes "8 of the 9" PR workflows, a figure taken from the flawed summary.
   It is 7 of 9, because both governance gates are red. Corrected in the README and the PR body.

No gate, pin table or validator was weakened. `verify-repair-018e4d04.log` is unaffected because its checks chain with `&&`.

## Validation run for this record (no Docker, no full suite)

- `python3 scripts/derive_trust_pins.py --check`: exit 0, fixed point, both before and after regenerating the closure pin.
- `pull_request_target` simulation of `production-orchestrator-contract` with main as the trust root: PASS.
- `pytest` on `test_trusted_production_orchestrator_gate`, `test_governance_authority`, `test_calling_contract`,
  `test_architecture_governance`, `test_middleware_forward_release_authority_strictness`,
  `test_middleware_authority_assets`, `test_release_workflow_regressions` and `test_orchestration_contract`:
  83 passed, 1 skipped, 50 subtests.
- `git diff --check origin/main HEAD`: clean.
- Infustruction certification re-run (Python / gitleaks only) as above.

## Hosted CI and blockers

- **Middleware hosted CI is not executing.** Every job on head `1867563d` (runs created 2026-09-24T05:06Z) completed in
  2–3 s with zero steps and the annotation *"The job was not started because your account is locked due to a
  billing issue."* This now affects the public Middleware- repository as well, not only the private repos (README §3).
  The red checks on #308 are therefore **not code results** and must not be read as passes or overridden. #319 is also
  red or cancelled, with no active run. **Owner action:** clear the `ingtrader21-spec` billing lock, then re-run #308
  on its exact head.
- **Infustruction F1/F2** (README §5–§7) stay open. The repair candidate needs owner approval and a kazan555
  exact-head review. It was not pushed by this lane.
- **Caller repins** stay held on the README §7 / `caller-repin-plan.md` preconditions: Infustruction visibility for the
  public callers, billing, and the accepted-authority ruling.
- **Stacking:** #308 carries #305's commits (`docs/edge-digest-chain-convergence-evidence-20260921`, still open) and the
  #306 files merged into that branch. Merge #305 first, or merge #308 as the superset.
- **Review:** a new head dismisses the prior approvals (`dismiss_stale_reviews`), so kazan555 is re-requested.
  Do not merge while CI is red or unexecuted.
