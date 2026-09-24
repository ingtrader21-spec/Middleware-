# Kong Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate exact, fail-closed staging and production Kong routes from the Middleware contract.

**Architecture:** Vendor the exact contract and generate declarative manifests that share one 8095 upstream while applying per-operation issuer, audience, azp, scope, size, rate, and correlation policy.

**Tech Stack:** Kong declarative YAML/JSON, Python generators, pytest, decK.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Production apply authorization remains false.
- No canonical route may target port 8080 or a provider/Odoo directly.

---

### Task 1: Contract-generated manifests

**Files:** Modify `config/middleware-public-api-route-contract.v1.json`, route generators, staging/production manifests; test canonical route and campaign edge suites.

- [ ] Add failing parity tests for every method/path/classification and retired path.
- [ ] Generate anchored route expressions and one `middleware-integration-api:8095` service.
- [ ] Assert unsupported methods and retired aliases resolve to 404/405.
- [ ] Validate both manifests with Python tests and decK when available.

### Task 2: Security and deterministic repository checks

**Files:** Modify OIDC/plugin config and any generator manifests changed by tooling; test `tests/test_kong_change_authority.py` plus route/security suites.

- [ ] Add failing tests for issuer, audience, azp, exact scope, limits, and correlation propagation.
- [ ] Implement least-privilege plugins with fail-closed defaults.
- [ ] Regenerate governed file manifests after generator changes.
- [ ] Run the full suite and separate unavailable Linux/decK/runtime evidence from source failures.
