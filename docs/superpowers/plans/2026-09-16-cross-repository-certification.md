# Cross-Repository Certification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce exact-SHA source and local integration evidence across all six repositories.

**Architecture:** A fail-closed coordinator compares vendored contract bytes/digests, route and identity matrices, repository tests, secret scans, and an isolated namespaced local stack when prerequisites exist.

**Tech Stack:** PowerShell/Python certification scripts, Git, Docker Compose, service-specific validators.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Never connect to production data, providers, telephone networks, or live DNS.
- Never report `PRODUCTION_GO`.

---

### Task 1: Static exact-SHA certification

- [ ] Commit logical repository changes, record final SHAs, and require clean feature worktrees.
- [ ] Compare canonical contract bytes and canonical SHA-256 across all consumers.
- [ ] Run complete available suites, secret scans, route/client/scope/upstream matrix checks, and no-8080 checks.
- [ ] Record missing binaries/runtime services as blockers with exact reproduction commands.

### Task 2: Isolated local runtime and handoff

- [ ] If Docker engine/images are available, start namespaced non-production Compose services and exercise token, edge, replay, denial, correlation, and reconciliation paths with `TEST_SYN`.
- [ ] Do not run staging without DNS, secret-file references, seeded data, logs, and restart authority.
- [ ] Produce `SOURCE_GO`, `LOCAL_INTEGRATION_GO`, `STAGING_GO`, and `PRODUCTION_GO` fields with evidence; force `PRODUCTION_GO=NO`.
