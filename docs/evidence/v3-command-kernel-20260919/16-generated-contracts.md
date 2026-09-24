# 16 — Generated contracts

Generated from the final canonical application, LF: contracts/platform/middleware-openapi.generated.json (315 operations), contracts/platform/integration-fabric-api.v2.yaml, config/api-completion-matrix.yaml, deploy/public-api-route-contract.json (117 rows: 105 shared_edge, 2 private_only, 10 denied). `generate_api_contracts.py --check` = PASS; `generate_route_authority_report.py --check` = MATCH. contracts/observability/integrated-monitoring.openapi.json unchanged (its generator is pydantic-version sensitive; the committed rendering is the CI image's).

OLD_EDGE_CONTRACT_SHA256=be25ea3a15687616fc1a17c451bb731c9e8bb85bbbd970e563d2baedc062b99e (pre-V3; sibling branches pinned to it must re-pin)
V3_EDGE_CONTRACT_SHA256=9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b (canonical compact-hash readback = pinned digest)
V3_EDGE_ROUTE_COUNT=117

Six kernel rows:

| method | path | client class | scope | idempotency | upstream |
|---|---|---|---|---|---|
| POST | /platform/v1/commands | platform-command-client | platform.command | Idempotency-Key | middleware-integration-api:8095 |
| GET | /platform/v1/kernel/describe | platform-command-client | platform.command.read | none | middleware-integration-api:8095 |
| GET | /platform/v1/operations/{operation_id} | platform-command-client | platform.command.read | none | middleware-integration-api:8095 |
| POST | /platform/v1/operations/{operation_id}/cancel | platform-command-client | platform.command | Idempotency-Key | middleware-integration-api:8095 |
| POST | /platform/v1/operations/{operation_id}/replay | platform-command-client | platform.command.replay | Idempotency-Key | middleware-integration-api:8095 |
| GET | /platform/v1/operations/{operation_id}/timeline | platform-command-client | platform.command.read | none | middleware-integration-api:8095 |

Every row carries method, path, classification, calling_client, audience (middleware-api), scope, auth, request/response schema, idempotency, correlation, error statuses, owner and upstream.
