# Keycloak Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align service identities and exact least-privilege scopes with the canonical Middleware contract.

**Architecture:** Extend repository-only desired state for canonical clients and isolated TEST_SYN test clients; never write secrets or contact a realm during source work.

**Tech Stack:** Keycloak desired-state JSON, Python reconciler/certifier, pytest.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Clients: `middleware-api`, `middleware-worker`, `n8n-automation`, `odoo-integration`.
- No integration scope is realm-default; production clients remain inactive/unapplied.

---

### Task 1: Contract and grants

**Files:** Modify edge certification contract, client scopes/clients, service integration grants, desired-state validator, and tests.

- [ ] Add failing tests for every contract scope, exact audience/azp, forbidden scopes, and one-scope test clients.
- [ ] Add only referenced scopes and explicit client grants; use `telephony.commands.write`, never `telephony:command`.
- [ ] Assert Middleware lacks `odoo.campaign.control.write` and no realm default leaks integration scopes.
- [ ] Run edge certification, service integration, platform identity, and provider authority suites.
