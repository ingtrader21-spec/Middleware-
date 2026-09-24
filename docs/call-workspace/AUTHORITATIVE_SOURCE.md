# Codestra Call Workspace authoritative source

Inventory captured 2026-08-22. Durable changes must originate from these repositories and protected branches; the dirty runtime checkouts are evidence sources only.

| Component | Repository / source | Baseline SHA | Running revision or image | Deployed source |
|---|---|---|---|---|
| Odoo `codestra_vicidial_crm` | `Codestra-SRL/codestra-odoo-addons`, `ci_addons/codestra_vicidial_crm` | `3b8cac3c60af8bc4e103d5d9abb5ddaff9441fc4` | Odoo digest `sha256:f54272f31d5f77e4146b887efb3761c98480317daf687e4b4b5e76ed8bcc08c5`; module baseline 19.0.2.0.0 | `/opt/codestra/odoo-addons/ci_addons/codestra_vicidial_crm` |
| Middleware and Agent Desktop | middleware Git remote; branch created from protected `main` | `04cf073` | middleware revision `b3ca9aa`; Agent Desktop revision `9b817116` | `/opt/codestra/middleware`, `/opt/codestra/middleware/agent_desktop` |
| Application WebSocket gateway | middleware repository `websocket_gateway` | `04cf073` | gateway revision `80954a1`; image digest to be recorded at release | `/opt/codestra/middleware/websocket_gateway` |
| Provisioning service | `appolon1908-hue/codestra-provisioning-service` | `0e7d8893ec7fda96a9ff9b5f91151d3537c28ae7` | image `sha256:2ce593371c26db217fa38be8cdbe08ef1798c2973b271e1639b57fb47636d5bf` | `/opt/codestra/provisioning-service`; clean source `/opt/codestra/worktrees/professional-call-workspace-provisioning` |
| Internal Odoo proxy | infrastructure Caddy configuration | deployment-controlled | `codestra/caddy:2.11.4-hardened-20260723` | internal Caddy deployment configuration |
| VICIdial connector | Odoo repository module and middleware adapters | `3b8cac3…` / `04cf073…` | current production revisions above | authoritative repository paths above |

Working branches are `agent/professional-call-workspace-20260822` in clean worktrees `/opt/codestra/worktrees/professional-call-workspace-odoo` and `/opt/codestra/worktrees/professional-call-workspace-middleware`. Production-only edits are prohibited. Exact full SHAs, immutable image digests, SBOM, provenance, signatures, PR review and merge SHA remain release gates and must not be inferred from a source build.

The canonical SIP signaling URL is `wss://wss.codestra.agency:8089/ws`. This is distinct from the application WebSocket URL used by Agent Desktop.
