# Internal Odoo TLS proxy

This deployment replaces only the private Odoo routing formerly supplied by
the retired combined reverse proxy. It publishes no host ports and joins the
internal integration network (client side) and backend network (Odoo side).

The exposed application contract is intentionally limited to:

- `POST /api/v1/integration/results`
- `GET|HEAD /web/health` for non-mutating health verification

The Klyrow mail integration optionally permits `POST /jsonrpc` from one reserved
Middleware mail-worker address. Set `KLYROW_MAIL_RPC_CLIENT_IP` to the same unused
IPv4 address in `10.254.41.0/28` in both this proxy composition and
`deploy/klyrow/compose.server-a-receiver.yaml`. The default loopback value is
rejected by the outer integration-network policy, so the route stays closed
until explicitly configured. Other peers and methods cannot use that route.
The mail worker verifies this proxy with `KLYROW_MAIL_ODOO_CA_FILE`; Odoo still
authenticates a dedicated, restricted service account for every RPC operation.
Keep its API key in the mounted secret file and verify its Odoo model permissions
before enabling delivery. This RPC credential is separate from the existing
OAuth credential used by the results worker.

The certificate, private key, and internal CA remain host-managed files under
`/etc/codestra/pki/internal-integration`. The key is mounted read-only and is
never stored in this repository.

Deploy only this service from this directory:

```sh
docker compose -p codestra-odoo-internal-proxy \
  -f compose.internal-odoo.yaml up -d odoo-internal-proxy
```

`codestra-reverse-proxy-1` is retired and must not be restarted. Removal is a
separate operation after every former dependency has been independently
accounted for and rollback evidence no longer requires the stopped container.
