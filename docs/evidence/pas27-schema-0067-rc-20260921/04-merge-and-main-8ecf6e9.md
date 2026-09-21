# 04 — Governed merge and protected main `8ecf6e9`

## Reviews on the exact head

Pushing `0d61de4` dismissed every approval recorded on earlier heads (as intended by the ruleset). Fresh reviews recorded on `0d61de48870fd990e8992c9547e08196a3bb09d8`, as returned by `gh pr view 301 --json latestReviews` after merge:

| Reviewer | Role | State |
| --- | --- | --- |
| `kazan555` | independent / security owner | APPROVED |
| `appolon1908-hue` | workflow Code Owner (`/.github/workflows/`) | APPROVED |

Unresolved review threads: 0. `reviewDecision=APPROVED`. The pushing identity (`ingtrader21-spec`, PR author) recorded no review. No branch-protection or CODEOWNERS change was made (the broad co-owner PR #302 remains closed).

## Merge

Squash auto-merge, armed earlier on the PR, fired once the required checks (03) and both reviews were present.

| Field | Value |
| --- | --- |
| Merge commit | `8ecf6e9b75a7adf4c82c4c7094ba71d64d73e692` |
| Parent | `bd406a6508c8095a3f23b35149a2eebcb94c94c6` |
| Committed | 2026-09-21T12:47:10Z |
| PR state | MERGED |

`8ecf6e9` is the new protected main and the only source the release job may build from (`SOURCE_SHA` is bound to the CI-accepted head, see 05).

## Main-push CI on `8ecf6e9`

| Workflow | Run | Result |
| --- | --- | --- |
| Middleware CI | 35601565535 | success |
| Production integration lock | 35601565551 | success |
| Production orchestrator contract | 35601565541 | success |
| CodeQL Advanced | 35601565728 | success |
| Python quality baseline | 35601565645 | success |
| Odoo calling endpoint contract | 35601565584 | skipped (path filter) |
| source-lock-candidate-build | 35601565587 | skipped |

`Middleware CI` success on `main` is the `workflow_run` trigger for `Signed Middleware Release` (05).
