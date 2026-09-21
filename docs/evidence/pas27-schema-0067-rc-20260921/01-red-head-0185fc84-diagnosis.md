# 01 — Red head `0185fc84`: diagnosis

PR #301 was refreshed onto protected main `bd406a6508c8095a3f23b35149a2eebcb94c94c6` (after PAS-102 / PR #298) by a concurrent session as exact head `0185fc84e4b898c90aca29b3b6dffe25f1f89d45` (tree `aa7f1c93a6932908209174a50fc98e5c5460d738`, commit "security(release): rederive PAS-27 source closure on protected main bd406a65").

Hosted verification on that head reported three required failures:

| Workflow | Run | Job | Result |
| --- | --- | --- | --- |
| Required exact-SHA CI | 35596647238 | Test exact repository SHA → Run migration chain and database tests | FAIL |
| Middleware CI | 35596647306 | Validate middleware source head → Run fail-closed source-head validation | FAIL |
| Middleware CI | 35596647306 | Validate middleware merge result | FAIL |

Every other job on the head was green (CodeQL, Python quality, route contract, integration lock, release component matrix, Connector SDK, container security, NATS/Temporal/PostgreSQL integration, no-effect E2E, runtime and test image builds).

## Single root cause

All three failures are the same pytest assertion. Excerpt from job 106322879426 (`Test exact repository SHA`), identical in job 106323551686 (`Validate middleware source head`):

```
FAILED tests/test_release_authority.py::test_trust_derivation_check_passes
  AssertionError: STALE  release   EXPECTED_REQUIRED_CHECK_SOURCE_CLOSURE_SHA256
           have=b81d33b520a7644948595dde3922494f02e7e84aac3bf99d0d518fae2167c546
           want=96701332522babe435f3f145294e657ca188bf4f034487cae6ec17cca06ff9c8
  TRUST_DERIVATION_REPORT
  LEAF_PIN_COUNT=50
  READ_ONLY_SCRIPT_PIN_COUNT=9
  WORKFLOW_PIN_COUNT=18
  ACTIVE_STALE_BEFORE=1
  FINAL_RELEASE_SECURITY_FINGERPRINT=63192fd83f7fc19fa624e2bf26d3b2ccc3941042e4e3c941ba378ff50581e565
  FINAL_VALIDATOR_SHA256=15c35ad11c65b7605d44812e08d45493e31afdea678876b3a44a16d27c1c1a21
  FINAL_SOURCE_CLOSURE_SHA256=96701332522babe435f3f145294e657ca188bf4f034487cae6ec17cca06ff9c8
  ACTIVE_STALE_AFTER=1
  STRUCTURAL_EXCEPTION_COUNT=1
  STRUCTURAL_EXCEPTION: APPROVED_DEFAULT_TEST_DISCOVERY_SOURCE_SHA256 (tracked Python source (launcher, gate test) embeds the validator digest, so a fresh discovery fingerprint would be a SHA-256 fixed point; the pin stays byte-identical to protected main and fails closed)
  UNKNOWN_TRUST_TABLES=0
  LAUNCHER_PARITY=YES
  CANDIDATE_TREE=e56bba865b87062edb874198e76c843e3dbcc2cc

1 failed, 3724 passed, 120 skipped, 150 warnings, 94 subtests passed in 252.78s
```

The refresh carried the closure value derived before the rebase (`b81d33b5…`, recorded in the 11:56Z Linear checkpoint) while the mechanical derivation over the rebased tree yields `96701332…` — the same value the preserved alternate local rebase `preserve/pas27-local-rebase-d26e02e` had derived. Validator digest, release-security fingerprint and launcher parity were already correct on the red head.

## What it was not

- Not a database defect. The `ERROR:` lines in the job's "Stop containers" section (`uq_telephony_active_extension`, `social_post_accounts_…_fkey`, `relation "middleware_schema_migrations" does not exist`) are the disposable PostgreSQL's log of the suite's negative tests; the migration chain and 3724 tests passed.
- Not a source-head or merge-result defect beyond the pin: both Middleware CI validations run the same fail-closed trust test.
- Not a launcher or validator change: `FINAL_VALIDATOR_SHA256` remained `15c35ad1…`, the successor authorized by the merged launcher PR #299.
