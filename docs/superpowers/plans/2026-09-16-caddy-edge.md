# Caddy Edge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every canonical shared-edge request to Kong before legacy fallback without authenticating it in Caddy.

**Architecture:** Vendor the Middleware contract, generate method-aware Caddy matchers, and prove route resolution from adapted configuration. Caddy preserves identity and correlation headers and never mints trusted identity.

**Tech Stack:** Caddyfile, Python validators, unittest/pytest, Caddy adapter.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Never reload live Caddy.
- Wrong methods and denied paths must not reach legacy upstreams.

---

### Task 1: Canonical route coverage

**Files:** Modify `sites/api.codestra.co.caddy`, `config/caddy-kong-contract.v1.json`, vendored contract and validators; test `scripts/test_caddy_kong_contract.py`, `tests/test_caddy_adapted_routes.py`.

- [ ] Add failing route-resolution cases for v2 automation, platform, Odoo event, N8N result subpath, both campaign reads, wrong methods, and retired aliases.
- [ ] Generate or maintain exact method/path matchers before the prefix-level deny-to-Kong handler.
- [ ] Verify Host, Authorization, correlation, and forwarding headers remain preserved.
- [ ] Run repository validation, unit tests, formatting, and `caddy adapt/validate` when the binary is available.
