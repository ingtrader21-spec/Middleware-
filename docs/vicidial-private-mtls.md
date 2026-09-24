# VICIdial private mTLS application preparation

This change prepares the middleware application for the approved private API gateway. It does not create networking, DNS, certificates, secrets, firewall rules, or runtime configuration.

The client permits only these requests:

- `POST https://authorization.internal.codestra.agency:8443/api/v1/transfers/authorize`
- `POST https://edge.internal.codestra.agency:8443/v1/transfers/execute`

Authorization requires `TRANSFER_CONTROL_ENABLED=true` and `VICIDIAL_READ_ENABLED=true`. Execution additionally requires `VICIDIAL_WRITE_ENABLED=true` and `LIVE_WRITES_ENABLED=true`. All flags default to false.

Before a separately approved deployment:

1. Provision and validate the `10.42.0.0/24` private network.
2. Install the CA, client certificate, client key, and optional CRL beneath `/etc/codestra/secrets/vicidial-mtls/` without committing them.
3. Ensure the container user can read the mounted files while the client key remains inaccessible to other users.
4. Merge the prepared environment entries into the protected runtime environment file.
5. Validate DNS, hostname verification, client-certificate rejection, revocation, route denial, and firewall isolation with all feature flags false.
6. Enable a test-only authorization canary under a separate approval. Transfer execution and live writes require their own approval.

There is no public-IP, HTTP, direct-database, SSH-tunnel, or port `8095`/`8096` fallback.
