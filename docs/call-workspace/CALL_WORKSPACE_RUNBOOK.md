# Call Workspace Runbook

## Safety first

Confirm `LIVE_PSTN_DIALING`, live call control, VICIdial writes, production callbacks, SMS, email and transcription are false. Certification is limited to tenant COD, campaign TEST_SYN, agent `synthetic.agent.test.syn.6101`, extension 6101 and echo 6000.

## Health checks

1. Verify internal workers resolve `odoo.internal.codestra.agency` to the isolated network and validate TLS with `ODOO_RESULTS_CA_FILE`.
2. Confirm that hostname is not publicly resolvable.
3. Verify Odoo health/module version and gateway `/healthz`, `/readyz`, `/metrics`.
4. Probe SIP WSS at `wss://wss.codestra.agency:8089/ws`; HTTP 101 is expected with a valid WebSocket upgrade.
5. Confirm active Asterisk calls and channels are zero before and after a canary.

## Popup delivery failures

Correlate `call_workspace_events_received_total`, `call_workspace_popup_deliveries_total`, `websocket_delivery_failures_total` and Odoo integration audits by correlation ID. Check subject/tenant/campaign/extension mapping before replaying an event. Keep broad delivery disabled.

## Event ingestion rejections

Inspect safe status counts and correlation ID. Validate signature freshness, schema version, canonical timestamp, tenant allowlist and agent/campaign/extension binding. Never log signatures or tokens.

## WebSocket failures

Check gateway readiness, database migration head, ticket consumption, allowed origin, active-session conflict, backpressure and reconnect replay. Do not bypass subject binding or expand allowed origins during diagnosis.

## Duplicate spike

Compare event IDs, call IDs and sequence. Identical replays should be suppressed. A changed payload with the same event ID must remain rejected. Do not delete uniqueness constraints.

## Canary reconciliation

For one inbound and one outbound internal PBX call, require one Odoo call, the expected unique lifecycle events, one popup, saved notes/disposition, no duplicate after replay and zero final Asterisk channels. Record event, persistence, socket and rendered timestamps for P50/P95/MAX evidence.
