# 02 — Closure repair on the exact head → `0d61de4`

## Method

The repair used only repository-owned tooling, in a session-owned scratchpad worktree created from the exact remote head (`git worktree add --detach … 0185fc84e4b898c90aca29b3b6dffe25f1f89d45`). The Administrators-owned canonical worktree `Middleware-.worktrees\pas27-ghcr-generation-v2` was not touched.

1. `python scripts/derive_trust_pins.py --check --root .` on `0185fc84` reproduced the hosted report byte-for-byte (same `have`/`want`, same `CANDIDATE_TREE=e56bba86…`).
2. `python scripts/derive_trust_pins.py --apply-candidate --root . --json-output …` → `ATOMIC_APPLY=PASS changed=.codestra/validate-release-intent.py`.
3. `git write-tree` on the staged result = `e56bba865b87062edb874198e76c843e3dbcc2cc`, equal to the `CANDIDATE_TREE` the failing hosted runs had computed.
4. Commit `0d61de48870fd990e8992c9547e08196a3bb09d8` ("security(release): re-derive PAS-27 Middleware source closure on 0185fc84"), then `--check` on the committed head.

## Diff (complete)

```diff
--- a/.codestra/validate-release-intent.py
+++ b/.codestra/validate-release-intent.py
@@ -381,8 +381,8 @@ EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256 = {
         "fcdd0d5c3832479b10deda8c6a6afca6"
     ),
     "ingtrader21-spec/Middleware-": (
-        "b81d33b520a7644948595dde3922494f02"
-        "e7e84aac3bf99d0d518fae2167c546"
+        "96701332522babe435f3f145294e657ca1"
+        "88bf4f034487cae6ec17cca06ff9c8"
     ),
     "appolon1908-hue/codestra": (
         "4e3ea69c3ec2a4bd6e4b50395672f44d"
```

One file, one table entry, 2 insertions / 2 deletions. `git diff --check`: clean.

## Fixed point on the committed head

```
TRUST_DERIVATION_REPORT
LEAF_PIN_COUNT=50
READ_ONLY_SCRIPT_PIN_COUNT=9
WORKFLOW_PIN_COUNT=18
ACTIVE_STALE_BEFORE=0
FINAL_RELEASE_SECURITY_FINGERPRINT=63192fd83f7fc19fa624e2bf26d3b2ccc3941042e4e3c941ba378ff50581e565
FINAL_VALIDATOR_SHA256=15c35ad11c65b7605d44812e08d45493e31afdea678876b3a44a16d27c1c1a21
FINAL_SOURCE_CLOSURE_SHA256=96701332522babe435f3f145294e657ca188bf4f034487cae6ec17cca06ff9c8
ACTIVE_STALE_AFTER=0
STRUCTURAL_EXCEPTION_COUNT=1
STRUCTURAL_EXCEPTION: APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256 (documented fixed-point exception)
UNKNOWN_TRUST_TABLES=0
LAUNCHER_PARITY=YES
CANDIDATE_TREE=e56bba865b87062edb874198e76c843e3dbcc2cc
```

Exit code 0. The validator digest and release-security fingerprint are unchanged, so the launcher transition merged in PR #299 (`850cd5ec… → 15c35ad1…`, fingerprint `63192fd8…`) still admits this generation; no new launcher cycle was needed.

The full JSON report from step 2 is `trust-derivation-report-0185fc84-to-e56bba86.json`.

## Local tests (pinned venv `C:\mwv257`, Windows host)

| Suite | Result |
| --- | --- |
| `tests/test_release_authority.py` | 64 passed, 1 skipped |
| `tests/test_release_authority.py::test_trust_derivation_check_passes` (the failing gate) | 1 passed |
| Focused regression: `test_exact_main_production_release`, `test_integration_main_release_authorities{,_v2}`, `test_middleware_forward_release_authority_strictness`, `test_portfolio_main_release_authorities`, `test_portfolio_release_reviewer_access`, `test_post_merge_release_workflow`, `test_release_manifest`, `test_migration_head_contract`, `test_migration_lineage`, `test_*trust*`, `test_*launcher*`, `test_*orchestrator*` | 100 passed, 1 failed |

The single local failure, `tests/test_trusted_production_orchestrator_gate.py::test_safe_file_rejects_a_symlinked_parent_that_escapes_candidate`, is `OSError: [WinError 1314] A required privilege is not held by the client` from `os.symlink` — a Windows host privilege limitation. The same test passed on the Linux runner in run 35596647238 and again on `0d61de4` (03).

## Publication

Fast-forward push `0185fc84 → 0d61de48` to `origin/security/ghcr-package-authority-generation-20260920-v2` after the remote head was re-read and confirmed unchanged. No force push. Peer sessions `middleware-06`, `middleware-96` and `middleware-69` each confirmed beforehand that they do not write to that branch.
