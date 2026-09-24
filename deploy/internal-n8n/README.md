# Internal n8n production route

This package defines the reviewed, private-only n8n integration boundary. It is
not a production activation manifest.

- `codestra-internal-integration` is an internal Docker network.
- The n8n hostname is a reverse-proxy network alias, not a public DNS record.
- Only attestation, health, readiness, and the exact event webhook are routed.
- The native n8n editor remains on its separately protected administrative
  hostname.
- Client secrets are external protected references. No secret value belongs in
  this repository or in workflow JSON.
- All production delivery flags and the Odoo result worker default to false.

Certificate issuance must use the existing Codestra private CA with an exact
`DNS:n8n.internal.codestra.agency` SAN. Apply this package only after exact-head
review, validation, backup, and a rollback rehearsal.
