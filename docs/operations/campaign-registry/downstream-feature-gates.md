# Downstream feature gates

VICIdial writes, callbacks, transfers, WebRTC, n8n, email, and SMS each have an
independent per-campaign state, approval, policy hash, activation timestamp,
rollback procedure and kill switch. Campaign activation enables none of them.

Unknown or missing feature state is disabled. Parent/child campaigns do not
inherit enablement. A global kill switch overrides every campaign-local state.
