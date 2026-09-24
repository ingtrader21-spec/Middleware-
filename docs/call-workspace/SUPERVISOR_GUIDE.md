# Supervisor Guide

The Supervisor view is server-scoped to the signed-in user's tenant and assigned campaigns. It shows authoritative agent status and active-call context. Queue metrics explicitly show unavailable when no authoritative snapshot exists.

- Select an agent with an active call to open call detail.
- Search by normalized phone or use the API's date, agent, campaign, direction, disposition, call ID and recording filters.
- Call detail includes correlation identifiers, timeline, permitted notes, disposition, QA history and restricted recording metadata.
- Supervisors may create coaching from an accessible QA review. They cannot see calls from unassigned campaigns or another tenant.

Do not copy customer data into alerts or external tickets. Use call ID and correlation ID for incident handling.
