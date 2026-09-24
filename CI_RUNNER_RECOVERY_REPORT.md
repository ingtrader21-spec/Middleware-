# Middleware CI Runner Recovery Report

- Repository: `ingtrader21-spec/Middleware-`
- Canonical main: `0606b0db9ff59802f8da3824d209d2effc13f87d`
- Mission branch/workspace: `mission/ci-runner-recovery-20260924`
- Report time: 2026-09-24T12:58Z
- Operator identity: `gh` as `ingtrader21-spec` (ADMIN). Token scopes: `gist, read:org, repo`. **No `workflow` scope.**

## Status

**BLOCKED, with two concrete authorization/system blockers.** The self-hosted runner is provisioned, online and idle. The required checks still can't execute because:

1. **Root cause (account billing lock).** Every failed required job carries this GitHub annotation:
   `The job was not started because your account is locked due to a billing issue.`
   All Middleware workflows target GitHub-hosted labels (`ubuntu-24.04` / `ubuntu-latest`), so every job is rejected before a runner is assigned. That's why `runner_name` is empty and there are zero steps.
2. **Rerouting to self-hosted needs a governed trust transition that I can't authorize.** All 11 required contexts come from `.github/workflows/middleware-ci.yml`. The repo's trust system (`scripts/derive_trust_pins.py`, `.codestra/run-trusted-production-orchestrator.py`) byte-pins that file. Changing `runs-on` makes 7 trust pins stale, and fixing them needs the one-way two-stage successor protocol (launcher-first PR, then candidate PR, as in #299 → #301). Re-deriving the pins was declined as a security-weakening action and needs owner/code-owner authorization. Pushing any workflow change also needs the `workflow` token scope.

## 1. Required checks inventory

Branch protection on `main` (strict, enforce_admins=true, dismiss stale reviews) plus ruleset `middleware-main-production-authority` (22120968) require these contexts, all from GitHub Actions (app 15368):

| Context | Workflow / job | Previous `runs-on` |
|---|---|---|
| validate | middleware-ci.yml `required-validation` | ubuntu-24.04 |
| Validate middleware source head | `source-head-validation` | ubuntu-24.04 |
| Validate middleware merge result | `merge-result-validation` | ubuntu-24.04 |
| docker-runtime-build | `docker-runtime-build` | ubuntu-24.04 |
| docker-test-build | `docker-test-build` | ubuntu-24.04 |
| connector-runtime-build | `connector-runtime-build` | ubuntu-24.04 |
| container-security | `container-security` | ubuntu-24.04 |
| Disposable PostgreSQL Redis integration | `runtime-integration` | ubuntu-24.04 |
| Disposable NATS JetStream integration | `nats-jetstream-integration` | ubuntu-24.04 |
| Temporal critical workflow integration | `temporal-workflow-integration` | ubuntu-24.04 |
| Synthetic no-effect acceptance E2E | `synthetic-acceptance-e2e` | ubuntu-24.04 |

Push-only job `Validate middleware main push` (`main-validation`) is also ubuntu-24.04. PR reviews: ruleset requires 1 approval plus code-owner review. CODEOWNERS gives `/.github/workflows/` to `@appolon1908-hue`.

I did not modify, disable or bypass branch protection or rulesets.

## 2–3. Runner provisioned and registered (repo-scoped)

| Item | Value |
|---|---|
| Runner name / id | `codestra-ubuntu-middleware` / 22 |
| Scope | repository `ingtrader21-spec/Middleware-`, runner group Default |
| Labels | `self-hosted, Linux, X64, middleware-ci` |
| Version | actions/runner v2.337.0 (tarball SHA-256 `70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613`, checked against the release notes) |
| Directory | `/home/codestra/actions-runner-middleware` |
| Work folder | `/home/codestra/actions-runner-middleware/_work` |
| Service | **user** systemd unit `actions.runner.ingtrader21-spec-Middleware-.codestra-ubuntu-middleware.service` (`~/.config/systemd/user/`), enabled and active, `Restart=on-failure` |
| Boot persistence | `loginctl enable-linger codestra` → `Linger=yes` |
| Host | Ubuntu 26.04.1 LTS, 4 vCPU, 14 GiB RAM, Docker 29.8.0, user `codestra` (in `docker` group) |

Why not `/opt` or a system service: there is no passwordless sudo (`sudo: interactive authentication is required`). The Kong and Leads runners use root-created `/opt/...` dirs and system units. Optional follow-up for parity: `cd ~/actions-runner-middleware && sudo ./svc.sh install codestra && sudo ./svc.sh start`, then `systemctl --user disable --now actions.runner.ingtrader21-spec-Middleware-.codestra-ubuntu-middleware.service`.

Registration note: the first registration mistakenly used `--no-default-labels`. I removed it with a remove-token and re-registered with the default labels plus `middleware-ci`. The final state is shown above.

## 5. Runner verification (GitHub API, 2026-09-24T12:5xZ)

```
Middleware-        22  codestra-ubuntu-middleware  online  busy=false  middleware-ci,self-hosted,Linux,X64
Kong               22  codestra-ubuntu-kong        online  busy=false  self-hosted,X64,Linux,codestra-ci
Leads-Workstation  2   codestra-ubuntu-leads       online  busy=false  self-hosted,Linux,X64,codestra-backup-ci
systemctl (system): kong=active leads=active   systemctl --user: middleware=active, enabled
```

Kong and Leads runners were not touched.

## 4. Runner-selector compatibility: what was tried

1. **Hosted-label aliasing (zero repo change). Result: does not work.** I temporarily added the custom label `ubuntu-24.04` to runner 22 and reran the failed jobs of #312's Middleware CI (run `35914711384`, attempt 2, head `8d7c2e05031e4a040545d2e70c5344f7465dbbc8`). GitHub still sent all jobs to hosted runners and rejected them with the same billing annotation (for example job `107635607310`, "Validate middleware source head"). I removed the label right away, so the runner is back to its 4 labels.
2. **Workflow selector change: prepared, not pushed.** The minimum change is 12 lines in `middleware-ci.yml`. Job names, steps and needs are unchanged, so no required context changes. Applied to main, it produced exactly **1 failing test out of 3,585** locally: `tests/test_release_authority.py::test_trust_derivation_check_passes`. The failure reports 7 stale pins:
   - validator `APPROVED_CONTROL_PLANE_WORKFLOW_SHA256[middleware-ci.yml]`
   - release `EXPECTED_CHECK_WORKFLOW_SHA256[middleware-ci.yml]`
   - validator `MIDDLEWARE_RELEASE_VALIDATOR_SECURITY_SHA256`
   - release `MIDDLEWARE_PRODUCTION_VALIDATOR_SHA256`
   - release `EXPECTED_CHECK_WORKFLOW_EXECUTABLE_SHA256[production-orchestrator-contract.yml][validate-production-orchestrator-contract.py]`
   - gate-test `repaired`
   - release `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256`

   Because the production validator's digest (`FINAL_VALIDATOR_SHA256`, currently `15c35ad1…1a21`) changes, the protected launcher must first authorize the successor on main. That is the launcher-only stage-1 PR. Under the billing lock, the stage-1 PR's own required checks can't run on hosted runners, so the protocol can't bootstrap without either (a) the billing lock being cleared or (b) an explicit code-owner decision on how to sequence the transition.

   Proposed diff (every `runs-on: ubuntu-24.04` in `middleware-ci.yml`, 12 jobs):
   ```diff
   -    runs-on: ubuntu-24.04
   +    runs-on: [self-hosted, Linux, X64, middleware-ci]
   ```
   (`sed -i 's/^    runs-on: ubuntu-24.04$/    runs-on: [self-hosted, Linux, X64, middleware-ci]/' .github/workflows/middleware-ci.yml`)

   This follows the Kong precedent, Kong PR #120 (PAS-245), which routes Kong's required checks to `[self-hosted, Linux, X64, codestra-ci]`. On this same machine, Kong self-hosted jobs ran after the billing lock started (for example Kong run `35905497941`, 2026-09-24T02:49:54Z, runner `codestra-ubuntu-kong`, 17 steps). So **self-hosted execution is not affected by the billing lock.** Kong #120 then hit a *GitHub Actions artifact storage quota* at `upload-artifact`. Middleware's `container-security` uploads an SBOM artifact and will likely hit the same quota after rerouting.

   Governance note: the release authority verifies provenance with `--deny-self-hosted-runners` (`.codestra/validate-release-intent.py`). Rerouting CI checks doesn't affect release signing, but moving required checks from ephemeral hosted VMs to a persistent desktop runner changes the trust posture. That decision belongs to the code owner.

## 6–7. Exact-head check reruns and evidence

Latest Middleware CI run on each open PR head. All are `failure` from the billing lock (0 steps, no runner):

| PR | Base | Exact head SHA | Middleware CI run (attempt) | Behind main |
|---|---|---|---|---|
| #312 | main | `8d7c2e05031e4a040545d2e70c5344f7465dbbc8` | `35914711384` (2, rerun by this mission, billing-locked again) | 0 |
| #313 | #312 branch | `6e28f33f9af9980adaf97d7cc5afa2bc5055579c` | `35949718873` (1) | n/a |
| #314 | #313 branch | `ed2f6ff91372828ebb1da353f22f9f04c3f0076b` | `35959248893` (1) | n/a |
| #304 | main | `4e524fc84c10bdf40efbc5b9b37a3e6f1c9b4381` | `35958552932` (1) | 0 |
| #305 | main | `4492823ea76fedc11fc64d8a3e2685cb916aa0e2` | `35949703651` (1) | 0 |
| #308 | main | `1867563dfefb27ce28a4d01c0d157edd86085ecf` | `35958488076` (1) | 0 |
| #309 | main | `16afd4688680cbe8738d657a1e0d7e62b8956835` | `35659524740` (1) | 0 |
| #310 | main | `46acb8825f3193faab387f7c1124de231cb5deb1` | `35958521821` (1) | 0 |
| #311 | main | `eee60d3c650d77c3c22ab737d1c5a8b9572927a2` | `35855297024` (1) | 0 |
| #316 | main | `76a8713f09eb03efb203d00a9f702b9d089dc9f1` | `35956070543` (1) | 0 |

Earlier "Required exact-SHA CI" evidence for #312: run `35914711068` attempt 2, jobs `107471686293` and `107471694359`, `runner_name` empty, 0 steps, same billing annotation.

I did not rerun the other PRs: without a routable runner, each rerun only produces another billing-locked failure. Reruns are serialized behind #312 → #313 → #314 once execution is possible.

Review state to keep in mind: #313 is approved on its current head. #314 approvals are on `aaafe946…`, not the current head `ed2f6ff9…`, so they are stale. #304 and #316 show `REVIEW_REQUIRED`.

## 8. True code/test failures (found locally, not in CI)

I ran the fail-closed `scripts/run_ci.sh` on clean detached checkouts of each exact head (local Python 3.14.4; CI uses 3.12/3.13). Then I reran the failing tests on clean trees with a hash-locked `requirements-test.txt` venv. **Main `0606b0d` passes the same tests**, so these failures come from the PRs, not the environment:

| PR | Result | Failing tests |
|---|---|---|
| #312 `8d7c2e0` | 2 failed / 3585 passed | `tests/test_platform_catalog_monitoring.py::test_registration_persists_the_descriptor_and_secret_references_as_pointers`: the fixture still registers `appolon1908-hue/sample-api` (line 38), which #312's new owner rule rejects with 422 `repository must belong to ingtrader21-spec`. Also `tests/test_release_authority.py::test_trust_derivation_check_passes`: stale `EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256` (have `59c70756…a9db6`, want `53efb635…4ad0`). |
| #313 `6e28f33` | 2 failed / 3585 passed | Same two. Closure want `e2c55ec0…2dff1`. |
| #314 `ed2f6ff` | 4 failed / 3597 passed | Same two (closure have `f6b65437…590d`, want `2df0c119…bb8b`), plus `tests/test_public_api_route_contract.py::test_contract_covers_every_required_operation_with_complete_metadata` (routes such as `/platform/v1/activity`, `/api/v1/callbacks`, n8n/Odoo campaign GETs are not covered by the public API contract), and `tests/test_staging_intake_observability_contract_validation.py::test_committed_staging_contract_is_valid` (`ContractError: staging runtime profile drift`). |

**Not fixed, on purpose:**
- The catalog fixture fix is small (update line 38 to an `ingtrader21-spec/...` repository).
- The closure-pin fix is a trust-pin re-derivation (`derive_trust_pins.py --apply-candidate`), the same action that was declined for this mission.
- Pushing a partial fix would change the PR heads and trigger `dismiss_stale_reviews`, discarding current approvals, while CI still can't run.
- Each PR's mission owner should apply these fixes along with their unique work.

## 9. Merges

None. No PR has green required checks. No protection or ruleset was edited or bypassed.

## Changes made by this mission

- Created runner dir `/home/codestra/actions-runner-middleware`, user systemd unit, and user linger.
- Registered runner id 22 on `ingtrader21-spec/Middleware-`. The temporary `ubuntu-24.04` label was added and then removed.
- Reran failed jobs of run `35914711384` (attempt 2, billing-locked).
- Repo content changes: none pushed. The prepared routing diff is recorded above. Local scratch worktree `Middleware-.worktrees/ci-middleware-self-hosted-routing` (branch `ci/middleware-self-hosted-required-checks`) was removed after its diff was captured here.
- Attempted, declined by the permission guard, and **recommended**: set fork-PR workflow approval to `all_external_contributors` (currently `first_time_contributors`). The repo is **public** and now has a self-hosted runner. Any prior contributor's fork PR could edit a workflow to `runs-on: [self-hosted, middleware-ci]` and run code on this desktop.

## Exact next actions (owner)

1. **Fastest, and needs no repo change:** clear the billing lock for account `ingtrader21-spec` at https://github.com/settings/billing (payment method / spending limit). Then rerun, in order:
   `gh run rerun 35914711384 --failed -R ingtrader21-spec/Middleware-`, then `35949718873` (#313), then `35959248893` (#314), then the rest of the table.
2. Harden the self-hosted runner before any job targets it:
   `gh api -X PUT repos/ingtrader21-spec/Middleware-/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors`
3. If self-hosted CI routing is still wanted, code owner `@appolon1908-hue` authorizes the two-stage trust transition:
   - Stage 1: a launcher-only PR that adds the successor `FINAL_VALIDATOR_SHA256` from `derive_trust_pins.py --emit-transition`.
   - Stage 2: a candidate PR with the 12-line `runs-on` change plus `derive_trust_pins.py --apply-candidate`.
   - Pushing either needs `! gh auth refresh -h github.com -s workflow`.
   - Expect the artifact-storage quota to block `container-security`'s `upload-artifact`, as in Kong #120.
4. Mission owners for #312/#313/#314 fix the code failures in section 8. The catalog fixture owner is #312; the closure pin has to be re-derived per head; #314 also has route-contract coverage and staging profile drift. After that, re-obtain current-head approvals.
