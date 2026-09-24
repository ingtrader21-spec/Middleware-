# Security governance

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not include secrets, customer data, production credentials, or
recording references in public issues.

## Isolated-staging Security Owner

For Server A isolated-staging risk decisions only, `kazan555` is the delegated
Security Owner approval principal. The requestor and implementation operator is
`appolon1908-hue`; that principal cannot approve its own security decision.

This delegation grants no authority for production deployment or activation,
Server B, telephony, communications, customer data, or recordings. Those
permissions remain blocked and require separate governance.

An approval is valid only when enforced by the `security-owner-signing` GitHub
Environment, bound to an exact PR head and immutable evidence hashes, signed by
the protected-main OIDC workflow, unexpired, and independently verifiable.
