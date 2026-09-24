# Loki (2026-09-16) — `Codestra-Loki` `639f1710`, PR #40

- Server: `auth_enabled: true` (business-domain tenants), bounded labels (15 names/series, 128/2048 lengths, 256 KB lines), `allow_structured_metadata: true`, `reject_old_samples`, retention, ruler API disabled, no host port (`LOKI_PUBLIC_LISTENER=NONE`).
- Redaction contract `codestra/redaction-contract.v1.json`: every forbidden class (bearer tokens, OpenBao tokens, OAuth secrets, passwords, authorization headers, webhook signatures, private keys, database and SMTP credentials, JWT-shaped values) names the Alloy stage and OpenTelemetry processor that enforces it before ingestion; `correlation_id`/`trace_id`/`span_id` and OpenBao audit fields are structured metadata only, never indexed labels; caller-supplied tenant headers never trusted.
- OpenBao audit stream `{service="openbao", log_source="openbao-audit"}`: HMAC preserved, never a public endpoint; ruler rules `codestra/rules/platform/openbao-audit-rules.yml` pinned to the OpenBao authority (`LOKI_OPENBAO_AUDIT_RULES_CROSS_CHECK=PASS`): audit stream silent, root-token use, permission-denial surge, policy/control-plane mutation, initialisation and authentication failures.
- Secrets: `codestra/<env>/observability/loki/object-storage` (identity `loki-runtime`) rendered as the AWS shared credentials file.
- Validator `validate_codestra_loki_platform.py` PASS; tests 6/6.
