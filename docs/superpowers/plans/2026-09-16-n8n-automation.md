# N8N Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every source workflow communicate only with canonical Middleware operations while remaining inactive and credential-free.

**Architecture:** Vendor the public contract, validate templates and workflow exports against it, preserve command/lease/correlation/causation/idempotency context, and forbid retries after unknown outcomes.

**Tech Stack:** n8n workflow JSON, Python validators/unittest, Compose policy.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Production bindability remains `NO_GO`; every workflow remains inactive.
- No direct Odoo, provider, email, SMS, or calling endpoint is allowed.

---

### Task 1: Contract and workflow parity

**Files:** Add vendored contract/hash; modify Middleware surface, automation API contract, templates, runtime bindings, validators, and tests.

- [ ] Add failing tests requiring exact contract digest and all `/v2/automation/*` plus result submit/read operations.
- [ ] Remove deprecated aliases from active/new templates and preserve all context fields.
- [ ] Reject direct destinations and automatic unknown-outcome retries.
- [ ] Run workflow, policy, integration-contract, and repository validators; repair the pre-existing umbrella digest drift separately.
