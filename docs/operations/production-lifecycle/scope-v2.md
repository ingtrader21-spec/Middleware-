# Production lifecycle scope v2

Scope v2 binds each proposed registry campaign to a distinct extension block,
agent group and closed dialplan context. Eligibility requires campaign,
extension, group, direction, context, destination class, producer identity,
schema and post-activation boundary to match simultaneously.

Direction and destination classifications remain empty, so the policy cannot
activate. Each campaign needs separate business/privacy approval before those
arrays may be populated. Unknown scope fails closed. Fixture 6198 and extension
6110 remain excluded.

Only started, connected and ended schema-1 events are allowed. Delivery is
bounded to 25 one-attempt submissions in 30 minutes, with no retry and immediate
stop on unexpected failure. Campaign activation does not enable delivery or any
downstream feature.
