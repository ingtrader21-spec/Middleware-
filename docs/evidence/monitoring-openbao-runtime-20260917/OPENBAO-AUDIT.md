# OpenBao audit pipeline (2026-09-17)

Path: OpenBao file audit device → Alloy (`codestra/config.alloy`, `openbao_audit` file_match/source/process) → Loki stream `{service="openbao", log_source="openbao-audit"}` with structured metadata `audit_type`, `audit_operation`, `audit_error` → Loki rules `codestra/rules/platform/openbao-audit-rules.yml` (sha256-pinned) → alerts to Alertmanager → Middleware incidents.

Guarantees:

- HMAC preserved: audit entries keep OpenBao's HMAC'd fields; nothing re-hashes or strips them (`redaction-contract.v1.json: openbaoAudit.hmacPreserved=true`).
- Redaction before Loki write (Alloy `runtime.v1.json: redaction.beforeLokiWrite=true`): OpenBao tokens (`hvs.`/`hvb.`/`s.` shapes), JWT-shaped values, `x-vault-token`/`x-openbao-token`/`vault_token`/`openbao_token`/`id_token` values, private-key marker lines, credentials, customer/person values, raw bodies, DB statements, e-mail addresses.
- Protected structured fields never redacted: `level event_family operation result error_code request_id correlation_id trace_id span_id deployment_sha`.
- Labels stay bounded (Loki `labelPolicy`; `neverStreamLabels` for correlation/trace ids, which live in structured metadata).
- No public endpoint delivery (`publicEndpointDelivery=false`).

Alerts driven from audit (Loki rules + OpenBao alerts): audit device unavailable, audit silence, auth-failure surge, policy-denial rate, lease-revocation surge, root-token use (must never occur outside a ceremony).

Runtime proof required (LogQL query result on the staging Loki showing the audit stream, and the Alloy target list showing the audit file source): **not collected** — staging deployment blocked. Source proof: Alloy validators PASS (corporate + staging-review), Loki `tests/test_loki_platform.py` 6 OK (`--require-cross-check` against the OpenBao checkout), Windows Alloy binary check deferred to CI (libssp-0.dll).
