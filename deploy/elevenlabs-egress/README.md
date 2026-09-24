# ElevenLabs controlled egress

This overlay gives the controller no direct Internet network. Its HTTPS client
uses an internal CONNECT proxy which accepts only the exact authority
`api.elevenlabs.io:443`. The gateway alone joins an external bridge and exposes
no host port. All other CONNECT authorities and every non-CONNECT method are
denied. TLS remains end-to-end between the controller and ElevenLabs, so the
controller verifies the public certificate and exact hostname.

Deploy the overlay only with the same immutable, attested middleware image used
by the controller. Keep `ELEVENLABS_PROVIDER_ENABLED=false` until gateway DNS,
TLS, unauthenticated 401/403, denied-destination, and unchanged-ingress probes
pass. If the provider redirects to another hostname, do not expand this policy;
disable the provider and request separate approval.

The gateway health check resolves the approved hostname, completes a verified
TLS handshake with that exact SNI name, and makes a credential-free `/v1/user`
request which must return 401 or 403. Any redirect or other status fails
readiness. Before mounting the provider credential, also send a CONNECT request
for an unapproved hostname through the internal proxy and require HTTP 403.

The gateway logs only a fixed outcome classification. It never logs authority
headers, provider credentials, request bodies, response bodies, or audio.

## Explicit IPAM

Server A exhausts Docker's automatically allocated IPv4 pools, so both overlay
networks use small explicit RFC1918 subnets. `10.254.41.0/29` is the internal
controller-to-proxy segment and `10.254.41.8/29` is the gateway egress segment.
Each provides six usable addresses and was selected after inventorying every
live Docker subnet, host address, and host route. They do not overlap the
Server A private VLAN (`10.40.0.0/24`), existing controlled segments
(`10.250.240.0/28`, `10.250.241.0/29`, and `10.254.40.0/28`), or any other live
route. Deployment must repeat the overlap check before network creation. Do not
change Docker daemon address pools, restart Docker, or delete another network.

Rollback removes this overlay, recreates only the controller on its prior
internal networks, removes the ephemeral ElevenLabs runtime secret, and leaves
the provider disabled.
