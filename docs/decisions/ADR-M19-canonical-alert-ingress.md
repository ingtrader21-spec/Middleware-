# Canonical internal Alertmanager ingress

The Codestra mission pack names `/internal/v1/alerts/alertmanager`; deployed
clients already use `/v1/integrations/alertmanager/events`. Register both paths
on the same handler in the observability alert application. Authentication,
tenant/source policy, durable incident identity, replay, and recovery remain
shared. Keep the older path during client migration.

This is an internal service route. It is not added to the public gateway.
Runtime URL-file rotation follows deployment of this receiver and a private
authentication/replay smoke test. The source change does not claim live Odoo
incident synchronization or enable notification/business write effects.

Rollback: revert the added alias after returning callers to the retained path.
No migration or stored-event changes are required.
