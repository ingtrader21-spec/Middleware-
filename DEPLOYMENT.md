# Deployment design — ingtrader21-spec/Middleware-

This repository is classified as **integration-control-plane** and remains independently deployable.

## Canonical integration boundary

Public ingress remains **Caddy -> Kong**. Cross-system commands/effects use **Middleware :8095 /platform/v1**. This repository keeps its own domain/runtime ownership and must not become a duplicate command authority.

## Detected deployment assets

- Dockerfile/Containerfile detected: **true**
- Compose detected: **true**
- Kubernetes/Helm detected: **false**
- Health/readiness signal detected: **true**

The values above describe the current repository tree. They do not claim a runtime is deployed.

## Required deployment gates

1. Build from an immutable Git SHA and, where containerized, record the immutable image digest.
2. Keep provider/business effects disabled by default until the repository-specific production certification passes.
3. Consume secrets by OpenBao/governed references only; do not commit credentials or copy secret values into evidence.
4. Define health/readiness before staging activation. Current status: **detected-review-required**.
5. Keep /internal/* and /metrics private; expose public APIs only through the reviewed Caddy/Kong route.
6. Record staging deployment, API/readback, observability and rollback evidence before production promotion.
7. Rollback must identify the prior SHA/image/config and must not require provider effects to validate.
8. Cross-repo provider-changing effects must be issued through the Middleware command lifecycle with idempotency and readback/reconciliation.

## Next implementation step

This document and .codestra/deployment-contract.json are the deployment-design authority. Any missing runtime artifact (Docker/Compose/Kubernetes/health probe) must be added in a repo-owned implementation PR only when that runtime is actually required; do not invent an unused deployment stack.
