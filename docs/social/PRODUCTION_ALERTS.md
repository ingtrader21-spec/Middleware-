# Production social alerts

Critical alerts cover provider/authentication failure, worker or PostgreSQL loss, dead letters, duplicate prevention, unknown results, account disconnection, production failures, and any failover or dual-publish attempt. Warning alerts cover Redis loss, queue pressure, webhook rejection spikes, and n8n backlog.

The first response is containment: disable canary and publish switches, preserve PostgreSQL state, and do not retry an ambiguous provider result. Follow `monitoring/runbooks/social-production.md`. Alert installation and notification routing remain deployment tasks and are not claimed by this source-only phase.
