# Release component ownership

The protected release source is one commit in `Codestra-SRL/codestra-middleware`.
No component may be built from a sibling repository, generated output, or an
uncommitted worktree.

| Component | Build context | Deterministic lock | Test ownership | Image |
|---|---|---|---|---|
| Middleware / webphone issuer | repository root | `requirements.lock`, `requirements-test.lock` | `tests/` | `ghcr.io/codestra-srl/codestra-middleware` |
| Agent Desktop | `agent_desktop/` | `agent_desktop/package-lock.json` | `agent_desktop/src/*.test.ts`, `agent_desktop/tests/browser/` | `ghcr.io/codestra-srl/codestra-agent-desktop` |
| WebSocket Gateway | `websocket_gateway/` | `websocket_gateway/requirements.lock` | `websocket_gateway/test_*.py` plus isolated certification sources | `ghcr.io/codestra-srl/codestra-websocket-gateway` |

`.github/workflows/release-component-ci.yml` validates the complete matrix on
pull requests. `.github/workflows/release-component-candidate.yml` performs
exact-main candidate builds, digest-bound SBOM and vulnerability evidence,
Security Owner decision generation, and protected digest signing with SBOM and
SLSA provenance attestations.

The Desktop staging browser configuration is declared in source and remains
bounded to campaign `TEST_SYN`, endpoint `6101`, and echo extension `6000`.
Production routes and transfer behavior remain disabled. Gateway schema changes
are applied only through the maintained migration chain; application startup
checks the exact migration head and does not create schema inline.
