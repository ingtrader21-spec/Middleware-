# Exporter–Middleware state mapping

The exporter owns only its local durable spool. Middleware owns reservation,
object verification, and Odoo-link state. State changes are transactional and
idempotent.

| Exporter state | Middleware observation | Permitted next state |
|---|---|---|
| `HASHED` | No reservation | `RESERVATION_CREATED` after a valid response |
| `RESERVATION_CREATED` | Reservation exists | `UPLOADING` |
| `UPLOADING` | Reservation exists | `UPLOADED` or `FAILED` |
| `UPLOADED` | Object pending verification | `SERVER_VERIFIED` or `QUARANTINED` |
| `SERVER_VERIFIED` | Checksum and object identity verified | `ODOO_LINKED` |
| `ODOO_LINKED` | Deterministic Odoo acknowledgement stored | `RETENTION_PENDING` |
| `QUARANTINED` | Conflict requires review | No automatic delivery retry |
| `FAILED` | Retryable operation exhausted | Operator-controlled retry only |

`RESERVED` maps to `RESERVATION_CREATED`; `VERIFIED` maps to
`SERVER_VERIFIED`. Unknown Middleware states fail closed. No state permits the
exporter to delete a recording.

The canonical nested event remains `recording-event-v1.json`. The separate
`recording-n8n-event-v1.json` schema is a flat metadata-only projection and
must not contain a raw filename, filesystem path, telephone number, storage
credential, upload URL, or internal object key.
