# Production social RBAC

`social.read`, `social.write`, `social.schedule`, `social.publish`, and `social.admin` remain distinct. Creating or editing a draft never implies permission to publish. The production publish endpoint requires `social.publish` or an explicitly governed `social.admin` identity before policy evaluation.

Machine authentication must use the platform bearer identity and protected provider secret files. The first canary requires a named human content approver recorded outside provider metadata. Production credentials, account tokens, and raw provider payloads must not enter API responses, audit metadata, events, logs, or metrics.
