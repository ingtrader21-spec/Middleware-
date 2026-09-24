# Step 3 Email Test Evidence

Date: 2026-08-30

## Focused email contract evidence

Executed with the repository's locked Python 3.13 test environment:

```text
python -m pytest tests/test_communications_email.py -q
6 passed, 14 warnings
```

The focused suite covers:

- canonical email command acceptance and sender authorization;
- strict tenant isolation and the `EMAIL_DELIVERY` kill switch;
- idempotent command replay with exactly one communications message and one command operation;
- signed Klyrow delivery callbacks, exact replay acceptance, and conflicting replay rejection;
- unknown provider outcomes surfaced as `indeterminate` without creating a second command;
- suppression and provider-event state transitions.

## Source-head validation

Executed with Python 3.13 through the same entry point used by Middleware CI:

```text
bash scripts/run_ci.sh
164 passed, 23 skipped, 25 warnings, 11 subtests passed
RUNTIME_CONTRACT_ROUTES=PASS
PROJECT_SPECIFIC_CI=PASS
```

All repository, workstream, connectivity, identity, n8n, site, intake, and project-specific source validators passed.

## Temporal uncertain-outcome and reconciliation evidence

Executed against the pinned Temporal test-server environment:

```text
bash scripts/temporal_integration_ci.sh
1 passed
TEMPORAL_EMAIL_UNKNOWN_OUTCOME_NO_RETRY=PASS
TEMPORAL_EMAIL_RECONCILIATION_READBACK=PASS
TEMPORAL_EMAIL_RECONCILIATION_NO_RESUBMIT=PASS
```

The workflow test injects a possible-after-acceptance provider timeout, records `reconciliation_required`, and proves there is exactly one provider execution attempt. It then runs a separate reconciliation workflow for the same email operation. Two transient read-back failures are retried within the bounded reconciliation policy, the third authoritative read-back matches, and the provider execution-attempt count remains unchanged. No second email command or provider submission is created.

## Exact-head and merge-result evidence

GitHub Actions is authoritative for disposable PostgreSQL/Redis, NATS JetStream, Temporal, synthetic no-effect, runtime Docker, test-target Docker, container security, exact source-head, and exact merge-result validation.

Before the reconciliation-evidence update, exact head `3ebff01ee426d6ee5307f864d07dac83ebd5291f` passed Middleware CI run `33317448335` and Production route contract run `33317448302`, including source-head and merge-result validation. The final reconciliation-evidence head must repeat every required gate successfully; the final exact SHA and run IDs are recorded in PR #52 after GitHub completes the new checks.

Step 3 is complete only when every required GitHub check is green at the unchanged final head and merge result.
