# Server A restricted agent candidate

This candidate is not enabled or started by repository installation. It is a
separate private ASGI service and must never be mounted into the public
Middleware app.

The Server D observer endpoint is `10.40.0.2:9444`. Port `9443` is reserved for
the existing private authorization gateway and must not be reused or modified.

## Network and certificates

- Bind exactly `10.40.0.1:9443`; publish no public listener or proxy route.
- Permit TCP 9443 only from the approved Controller private source address.
- Require a server certificate for the private name and a client certificate
  chaining to the approved controller client CA.
- The verified client leaf must contain
  `spiffe://codestra.internal/controller/middleware` as a URI SAN.
- The TLS ASGI adapter must expose the verified leaf DER as
  `scope["extensions"]["tls"]["client_cert"]`; HTTP identity headers are not
  trusted.
- Deliver the approval verification key through a root-projected, read-only
  file. Never place it in an environment variable or unit file.

Proposed firewall rule (do not apply until the Controller private address is
approved):

```text
allow tcp from <APPROVED_CONTROLLER_PRIVATE_IP>/32 to 10.40.0.1 port 9443
deny tcp from any to 10.40.0.1 port 9443
```

## Installation state and rollback

Install the application under `/opt/codestra/controller-agent`, create the
locked non-login account `codestra-agent-a`, and copy the reviewed unit to
`/etc/systemd/system/codestra-agent-a.service`. Keep both
`SERVER_A_AGENT_ENABLED=false` and the unit disabled/inactive until a separate
private-network activation approval.

Rollback stops and disables the unit, removes only the firewall rule scoped to
9443, restores the prior unit backup, and retains sanitized execution evidence.
It does not alter Middleware, Caddy, database, Docker, or activation flags.
