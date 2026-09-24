# PR #145 durable rejection and paired-source review

Observed 2026-09-06T07:46:57.961176+00:00. This continuation adopted concurrent
head `638b56c56b2e40631571141827ca5d020bef36f3` without rewriting its work.
Earlier no-send persistence and pairing were introduced at
`5e4d3ccf1b035e6e722b362322b51aaf2ce383a3`; subsequent preparation fixes and
638b56c's policy-denial/provider-ID/Temporal/documentation fixes are retained.

## Remaining crash window closed

The execution activity already committed a cancellation before returning a
conclusive rejection. Its workflow ActivityError handler did not reload that
proof after loss of the activity completion acknowledgement. It now invokes a
registered, read-only recovery activity, verifies the request against durable
intent, and returns cancelled only for the matching committed failed attempt and
no-send cancellation. Absence of committed proof stays reconciliation-required;
no provider readback or mutation is used to infer no-send. Recovery does not
replenish the grant or write another audit outcome.

Real PostgreSQL plus a supported Temporal time-skipping server exercise an
injected activity failure after the transaction commits but before activity
completion is recorded, and separately a failure before proof commits. This is
actual workflow/activity registration, serialization and ActivityError execution,
not only reconstruction of a Python activity object. It is not a claim to have
dropped a real network acknowledgement packet. PostgreSQL regressions also cover
competing dispatch winners/losers, repeated recovery, one cancellation audit
record and rejection of another originate using the consumed authorization.

The real adapter and policy loader are also exercised against missing, unreadable,
malformed, invalid-schema and unsafe-mode policy files after enqueue. Each case
commits cancellation and one audit record, with zero transport sends. Only root
ownership observation is emulated in these unprivileged file tests; file contents,
mode checks, adapter behavior, database transactions and workflow are real.

The accepted Asterisk uniqueid constraint from 638b56c now also applies inside
the reconciliation persistence transaction. Otherwise a later valid-looking
terminal observation could replace accepted uniqueid A with B. The new PostgreSQL
regression proves this mismatch cannot complete the command or replace A.

## Validation

Environment: Server B codestra-admin, Python 3.13.15, hash-locked runtime/test and
quality dependencies; isolated rootless PostgreSQL image
`postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685`
on loopback port 55432, database `middleware_test_calling`, unique disposable
schemas. No production database or telephony transport is accessed.

With CALLING_TEST_DATABASE_URL pointing to that disposable database and
TEMPORAL_INTEGRATION_TESTS=1:

```text
python -m pytest -q tests/test_calling_postgres.py   tests/integration/test_temporal_workflows.py tests/test_calling_contract.py   tests/test_calling_api.py tests/test_vicidial_internal_call_adapter.py   tests/test_reconciliation_activity.py
```

Result: **86 passed, 1 skipped, 50 subtests passed in 13.16s**. The skip is the
separate root-owned file acceptance test. The contract suite also passed in
the rootless namespace: **23 passed, 45 subtests passed in 0.03s**. The calling CI now sets TEMPORAL_INTEGRATION_TESTS=1
for the PostgreSQL suite too, so the new real Temporal failure tests cannot be
silently skipped by that gate.

Actual selected-source pairing: **1 passed in 1.08s**, using `podman unshare` to
run the protected-file test in an isolated rootless user namespace (namespace
UID 0 maps to codestra-admin; this grants no host administrator privilege).
CODESTRA_SELECTED_SERVER_B_ROOT pointed to a detached 9ac8ef checkout and
CODESTRA_SELECTED_SERVER_B_SHA matched it; command:
`python -m pytest -q tests/pairing/test_selected_server_b.py`.
This uses the real selected Server B client/authenticator/routes/durable SQLite
state and synthetic AMI only. Existing expiry-safe owner readback/hangup and
terminal lifecycle checks remain intact. Published artifact identity and durable
signature evidence are recorded in SERVER-B-PAIRING-9ac8ef48.md.

Ruff 0.12.10 passed for changed Python files. Whitespace and patch-only
Gitleaks checks passed. Unscoped whole-tree Gitleaks reported 25 pre-existing
findings in untouched files; it is not reported as a clean tree scan. Required
repository security checks remain authoritative and are not relaxed. Final-head
required CI/review evidence belongs in the PR review replies once those checks
complete; local tests are not substituted for protected merge requirements.

No deployment, live symlink change, activation, account mutation, browser
enrollment, SIP registration, Odoo call or unrelated delivery occurred.

## Persistence retry follow-up — 2026-09-06T07:55:05Z

Review 3943314127 is addressed with three bounded attempts of the idempotent
no-send cancellation transaction inside the owning activity. PostgreSQL
connection/serialization/deadlock and transport timeout failures retain the
already-proven rejection in memory; the adapter is never retried. A lost database
commit acknowledgement reloads the committed cancellation without another audit
record. Exhaustion without durable proof remains uncertain and cannot replenish
the consumed grant. This does not claim recovery of uncommitted in-memory proof
after process loss.

Final combined PostgreSQL/Temporal/client/workflow suite: **89 passed, 1 skipped,
50 subtests passed in 16.27s**. New regressions cover failure before commit,
ambiguous commit acknowledgement, and retry exhaustion. Rootless namespace
selected-source pairing plus protected policy tests: **24 passed, 45 subtests
passed in 1.09s** against source 9ac8ef4840f78ba4ad9b816e4e409298505103ce.
Changed Python files pass Ruff; git diff --check passes. An additional unscoped
Ruff run reports 116 existing findings outside the changed files; required CI
remains authoritative. No lint or security gate was weakened.
