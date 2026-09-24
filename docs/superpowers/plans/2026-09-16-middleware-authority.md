# Middleware Authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the deployed Middleware app the single contract-backed cross-system command authority.

**Architecture:** Expand the existing public route contract, mount one shared router registry in every application factory, preserve durable domain services, and certify fail-closed behavior. No provider capability is enabled.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, pytest, JSON/OpenAPI contracts.

**Spec:** `docs/superpowers/specs/2026-09-16-one-codex-cross-repository-integration-certification-design.md`

## Global Constraints

- Runtime listener: `middleware-integration-api:8095`.
- Audience: `middleware-api`; no `odoo.campaign.control.write` grant.
- `TEST_SYN` only; all external-effect switches false.

---

### Task 1: Canonical contract

**Files:** Modify `deploy/public-api-route-contract.json`, `deploy/public-api-route-contract.sha256`; test `tests/test_public_api_route_contract.py`.

- [ ] Add a failing test that requires every canonical operation and metadata field.
- [ ] Run `python -m pytest -q tests/test_public_api_route_contract.py` and confirm the missing-operation failure.
- [ ] Expand the existing contract and recompute its canonical SHA-256.
- [ ] Rerun the test and confirm zero failures or xfails.

### Task 2: Shared router registry and auth semantics

**Files:** Create `app/router_registry.py`; modify `app/main.py`, `app/appolon_factory.py`, `app/entrypoints/integration_api.py`, `app/api/v1/integrations.py`; test `tests/test_integration_api_entrypoint_routes.py` and authorization tests.

- [ ] Write failing parity tests for all factories and 401/403/404/409/422 behavior.
- [ ] Implement `mount_canonical_routers(app: FastAPI) -> None` and use it in every factory.
- [ ] Bind Odoo ingress to `azp=odoo-integration` and preserve specialized validation errors.
- [ ] Run the targeted suites, then the named integration suite with `-rxX`; remove every xfail in that named suite.

### Task 3: Runtime and certification

**Files:** Modify `deploy/compose.runtime.yaml`, `Dockerfile.runtime`, `scripts/certify_edge_integration.py`; test `tests/test_runtime_compose.py`, `tests/test_certify_edge_integration.py`.

- [ ] Write failing tests rejecting canonical 8080 references and permissive certification outcomes.
- [ ] Point the integration API to 8095 and keep production/apply flags false.
- [ ] Run the fail-closed certification runner and complete relevant pytest suites.
- [ ] Commit contract, router/auth, and runtime/certification changes separately.
