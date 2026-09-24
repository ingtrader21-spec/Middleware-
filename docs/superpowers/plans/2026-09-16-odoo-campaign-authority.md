# Odoo Campaign Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the `cc.campaign` desired/effective lifecycle and private Middleware readback boundary without a duplicate campaign state machine.

**Architecture:** `codestra_campaign_control_plane` extends `cc.campaign`; immutable configuration versions, provisioning runs, outbox commands, and readbacks remain Odoo-owned evidence. Middleware pulls commands and posts normalized results/readback.

**Tech Stack:** Odoo 19 ORM/controllers/XML, PostgreSQL, Python static validators.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- No direct provider/N8N writes or automatic design automation from Middleware-created campaigns.
- Correct API mapping: 403, 409, 422, and 500; cross-tenant resources remain hidden.

---

### Task 1: Lifecycle and API parity

**Files:** Modify `custom-addons/codestra_campaign_control_plane/**`, `custom-addons/call_center_campaign/**`, `contracts/odoo/**`, endpoint catalog/generator/validator.

- [ ] Add failing tests for immutable versions, expected version conflicts, provisioning idempotency, stale/future readback, explicit allowlists, pull-only delivery, and TEST_SYN fixtures.
- [ ] Implement minimal lifecycle and controller corrections on inherited `cc.campaign`.
- [ ] Regenerate the endpoint catalog and prove catalog/controller/capability/scope parity.
- [ ] Run static validators; run install/upgrade/ORM tests only against an isolated Odoo 19 PostgreSQL runtime.
