# Loki (2026-09-17) — Codestra-Loki @ `639f171047ff`

- Bounded labels: `redaction-contract.v1.json` `labelPolicy` limits indexed labels to the service/business/environment/deployment/level class; `correlation_id`, `trace_id`, `span_id` are structured metadata, never stream labels (`neverStreamLabels`). The collector reports `label_names` and `label_names_bounded` (≤ 15) from `/loki/api/v1/labels`.
- Tenancy: `X-Scope-OrgID` from the deployment (`codestra_business`), never a customer id; caller-supplied tenant headers are not trusted.
- Forbidden content classes are redacted before ingestion by Alloy/OTel (see ALLOY-OTEL.md); Loki adds no filter of its own.
- OpenBao audit stream and rules: `{service="openbao", log_source="openbao-audit"}`, `codestra/rules/platform/openbao-audit-rules.yml` (+ `.sha256`), HMAC preserved.
- TEST_SYN proof: the runner queries `{service="middleware-integration-api"} | json | correlation_id="<id>"` (X-Scope-OrgID set), requires ≥ 1 line whose `trace_id` equals the request trace, and fails on any secret-shaped content in the correlated lines (`test_log_line_leaking_a_token_fails_redaction`).

Validation: `validate_codestra_loki_platform.py --require-cross-check` PASS, unittest 6 OK. Runtime `/ready`, `/config`, label list on staging: **not observed**.
