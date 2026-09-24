# Alloy and OpenTelemetry (2026-09-16)

## OpenTelemetry Collector — `Codestra-Telemetry` `bf48a9c1`, PR #57

- Agent profile `codestra/collector-agent.yaml`: OTLP on `127.0.0.1:4317` and `127.0.0.1:4318` (`/v1/traces`, `/v1/metrics`, `/v1/logs`) only; `attributes/redact` deletes `authorization`, `cookie`, passwords, API keys, client secrets, tokens, private keys, `x-vault-token`/`x-openbao-token`, `jwt`, `db.statement`, request/response headers, personal contact data; `transform/secret_shaped` scrubs Bearer, OpenBao (`hvs.`/`hvb.`), JWT (`eyJ…`) and PEM values from attributes and log bodies; bounded file-backed queue; single mTLS exporter to the gateway; never a direct backend export; never a non-loopback bind.
- Gateway `codestra/collector.yaml`: mTLS OTLP receivers, resource identity enforcement, redaction, tenant filter, tail sampling, Tempo/Loki/Prometheus exporters; `transform/correlation` keeps `correlation.id` on spans and logs (bounded to 128) while metrics and resource attributes still strip it. Every `/run/secrets/otelcol_*` file is an OpenBao reference (identity `otel-gateway`).
- `otelcol-contrib 0.159.0 validate --config` exit 0 for both profiles (a deliberately broken OTTL statement exits 1); validator PASS with negative controls (`0.0.0.0` bind rejected, `token` key rejected); tests 53/53.

## Alloy — `Codestra-Alloy` `f1be1cd3`, PR #39

- Stays the business-scoped log-file/journal agent (`opentelemetryOwnsApplicationOtlp` unchanged — decision R9).
- OpenBao audit tail `/var/log/openbao/openbao-audit*.jsonl` (read-only mount on the OpenBao host only), static bounded labels, audit type/operation/error as structured metadata, through the shared redaction stage.
- Redaction gains OpenBao tokens (`hvs.`/`hvb.`/`s.`), JWT-shaped values and the OpenBao header names; `correlation_id`/`trace_id`/`span_id` from JSON logs become structured metadata (never labels); intake services keep dropping them.
- Every `/run/secrets` file (`loki_ca`, `alloy_client_cert`, `alloy_client_key`) is an OpenBao reference (identity `alloy-collector`).
- Three validators in sync and PASS; tests 6/6. Native `alloy fmt`/`validate` run in CI with the locked executable (the Windows release binary cannot load on the certifying host).

Never included in spans, logs or metric labels: Authorization, Cookie, API keys, passwords, private keys, OpenBao tokens, JWTs, database passwords, SMTP passwords, provider credentials — enforced at the agent, the gateway and Alloy, and declared in Loki's redaction contract.
