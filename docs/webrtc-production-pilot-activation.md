# WebRTC production pilot activation

Activation is separate from technical deployment. Keep dialing disabled until the scoped human approval manifest is complete.

Required signed selections and approvals: production campaign and business unit; pilot agent and supervisor; carrier production authorization; caller-ID ownership and campaign authorization; destination-owner consent; destination-local calling window; recording decision; and named telephony, security, compliance, and business owners.

The named security owner is Ralph Appolon (`appolon1908-hue`). This attribution is not an approval: the decision, timestamp, scope, evidence reference, protected source SHA, and immutable image digest must still be completed by that owner after the protected release exists.

Each approval must bind name, role, decision, scope, timestamp, evidence reference, approved release digest, campaign, and destination class. Once complete, run preflight and verify one-agent, one-extension, one-caller-ID, one-destination, one-window allowlisting with concurrent-call and attempt ceilings of one. Test the kill switch before any separately authorized pilot window.

No approval in this document authorizes Codex to register SIP or place a call.
