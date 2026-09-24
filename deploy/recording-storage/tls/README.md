# Staging recording API TLS

This directory documents the certificate contract only. CI must use synthetic
certificates; production keys and certificates must never be committed.

- Service DNS identity: `api.staging.internal.codestra.agency`
- Private address: `10.40.0.1`
- Server certificate SAN must contain the DNS identity.
- Raw-IP TLS is rejected as the primary identity.
- Client identity: `codestra-recording-exporter-server-b`
- Client environment: `staging`
- Client role: `recording-exporter`
- Expiration and revocation checks are mandatory and fail closed.
