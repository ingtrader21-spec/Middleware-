# Phase 1 sales lead foundation acceptance evidence

Evidence was collected on Codestra Middleware Server A from the isolated
`feature/sales-lead-foundation` worktree. All provider implementations used
test doubles; no paid provider, Odoo mutation, VICIdial publication, or
outreach path was activated.

## Functional evidence

```text
VALID_CANDIDATE_TEST=PASS
INVALID_CANDIDATE_REJECTED=PASS
EXACT_COMPANY_MATCH=PASS
EXACT_CONTACT_MATCH=PASS
POSSIBLE_DUPLICATE_HELD=PASS
CROSS_TENANT_MATCH_DENIED=PASS
GLOBAL_DNC_BLOCKED=PASS
CAMPAIGN_DNC_BLOCKED=PASS
SUPPRESSION_BLOCKED=PASS
CONSENT_WITHDRAWAL_BLOCKED=PASS
IDEMPOTENT_REPLAY=PASS
PAYLOAD_CONFLICT_REJECTED=PASS
VALID_WEBHOOK_ACCEPTED=PASS
INVALID_WEBHOOK_REJECTED=PASS
WEBHOOK_REPLAY_REJECTED=PASS
DRY_RUN_JOB_COMPLETED=PASS
ODOO_CREATE_COUNT=0
ODOO_UPDATE_COUNT=0
ODOO_DELETE_COUNT=0
VICIDIAL_WRITE_COUNT=0
OUTREACH_EVENT_COUNT=0
```

## Validation evidence

```text
MIGRATION_VALIDATION=PASS (0033 -> 0034 -> 0033 -> 0034 on isolated PostgreSQL)
UNIT_AND_REPOSITORY_TESTS=877 passed, 21 skipped
FOCUSED_SALES_TESTS=35 passed
DATABASE_INTEGRATION_TESTS=1 passed on isolated PostgreSQL
OPENAPI_VALIDATION=PASS (181 paths, 94 schemas, strict sales request schema)
RUFF_LINT=PASS
MYPY=PASS (158 source files)
PIP_AUDIT=PASS (no known vulnerabilities)
GITLEAKS_CHANGED_FILES=PASS
TRIVY_FILESYSTEM=PASS (HIGH/CRITICAL vulnerabilities, secrets, misconfiguration)
TRIVY_RUNTIME_IMAGE=PASS (0 HIGH/CRITICAL vulnerabilities)
```

The repository-wide format check reports 51 files that already differed from
Ruff formatting on the base SHA. None is part of this change; all changed
Python files pass Ruff formatting.

Grype reports version-based findings against the repository's patched Python
3.12.13 runtime. The identical findings reproduce on the existing main image
`codestra/middleware:pr176-289047c`; Trivy and `pip-audit` report no applicable
HIGH/CRITICAL vulnerability in the candidate. This branch neither changes the
runtime base nor suppresses the pre-existing scanner discrepancy.
