# Isolated-staging Security Owner governance

`kazan555` is the approval delegate for security-risk decisions scoped only to
Server A isolated staging. `appolon1908-hue` is the requestor and implementation
operator. The roles must remain separate.

The `security-owner-signing` environment enforces the delegate review, prevents
self-review, disables administrator bypass, and accepts protected-branch runs
only. Its approval is necessary but not sufficient: the resulting canonical
decision must also verify against the exact protected-main workflow identity,
GitHub Actions OIDC issuer, PR head, evidence hashes, image digests, findings,
scope, expiry, and negative authorizations.

Production, Server B, telephony, communications, customer data, public ingress,
and recording access are outside this delegation and remain blocked.
