# Call Workspace API

All browser endpoints are JSON-RPC `POST` requests using the authenticated Odoo session. Mutation requests carry a UUID idempotency key. Error envelopes contain a safe message and never a stack trace.

## Telephony event ingestion

`POST /codestra/api/v1/call-events` is the lifecycle and popup contract. It requires HMAC signature, timestamp and event-ID headers plus schema `1.0`, canonical identifiers, an ISO-8601 timestamp with timezone, a nonnegative sequence, tenant/campaign/agent/extension/Keycloak-subject binding, and a body no larger than 256 KiB. Identical replay is a duplicate; the same event ID with different evidence is a conflict.

This endpoint is not `/api/v1/integration/results`. Result delivery is an independent OAuth2 integration contract and is not a popup dependency.

## Agent endpoints

| Route | Purpose |
|---|---|
| `/codestra/call-control/v1/current` | Recover the authenticated agent's active call. |
| `/codestra/call-control/v1/match` | Normalize a phone and return exact, ambiguous or no-match candidates. |
| `/codestra/call-control/v1/calls/{call_id}/workspace` | Customer 360, lifecycle, notes, dispositions, callbacks and templates. |
| `/codestra/call-control/v1/calls/{call_id}/notes` | Debounced revisioned note autosave. Maximum 10,000 characters. |
| `/codestra/call-control/v1/calls/{call_id}/disposition` | Terminal-call disposition and campaign-scoped sub-disposition. |
| `/codestra/call-control/v1/calls/{call_id}/callbacks` | Schedule a prioritized CRM callback without automatic dialing. |
| `/codestra/call-control/v1/calls/{call_id}/callbacks/{callback_id}/{action}` | Reschedule, complete or cancel a callback. |
| `/codestra/call-control/v1/calls/{call_id}/tasks` | Create a tenant-scoped CRM follow-up activity. |
| `/codestra/call-workspace/v1/calls/{call_id}/recording/playback` | Request an audited, permission-bound, short-lived playback grant. |
| `/codestra/call-control/v1/calls/{call_id}/history` | Bounded related-call history. |

Call-control action routes exist but remain default-disabled by feature flag and TEST_SYN policy.

## Supervisor and QA endpoints

| Route | Required role | Purpose |
|---|---|---|
| `/codestra/call-workspace/v1/supervisor/dashboard` | Supervisor | Assigned-campaign agent and active-call state. |
| `/codestra/call-workspace/v1/calls/search` | Supervisor or QA | Tenant/campaign record-rule constrained call search, limit 100. |
| `/codestra/call-workspace/v1/calls/{call_id}/detail` | Supervisor or QA | Timeline, notes, recording metadata, QA and audit identifiers. |
| `/codestra/call-workspace/v1/calls/{call_id}/qa` | QA | Create a complete seven-category review. |
| `/codestra/call-workspace/v1/qa/{review_id}/coaching` | Supervisor or QA | Assign coaching to the call agent. |
| `/codestra/call-workspace/v1/coaching/{id}/acknowledge` | Assigned agent | Acknowledge an open coaching item. |

## Realtime

`POST /realtime-api/api/v1/realtime/sessions` validates Keycloak roles and mapping claims, then returns a short-lived single-use ticket. The browser authenticates to `/ws/agent` with the ticket and optional last-event cursor. Delivery is subject-, tenant-, business-unit-, campaign- and agent-bound. Cross-scope frames and duplicate active sessions are denied.

See `CALL_WORKSPACE_API_MATRIX.csv` for schemas, limits and status details.
