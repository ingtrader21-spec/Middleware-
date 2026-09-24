# n8n recording node contract

The generic ingress is `POST /webhook/v1/events` with binding
`n8n.events.ingest`. It is disabled by default and accepts only
`vicidial.recording.verified.v1` after object verification and Odoo
acknowledgement.

n8n is optional. It does not reserve uploads, receive audio, verify objects,
link Odoo records, authorize playback, or enforce retention.

The canonical PR-A event schema is vendored byte-for-byte. Its payload contains
the canonical recording metadata object; it contains no telephone number,
customer name, raw filename, filesystem path, object key, presigned URL,
credential, or audio binary.

Future transcription, QA, and compliance nodes remain absent/inactive. Email,
SMS, WhatsApp, calendar, appointment, and CRM-lead nodes remain disabled.
