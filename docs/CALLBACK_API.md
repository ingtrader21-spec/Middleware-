# Callback API v1

All calls require the platform bearer token plus Kong-validated `X-Codestra-Actor-ID`, `X-Codestra-Tenant-ID`, `X-Codestra-Campaigns`, `X-Codestra-Role` and optional `X-Codestra-Teams`. Mutation calls require `Idempotency-Key` and `X-Correlation-ID`.

- `POST /api/v1/control/callbacks`
- `GET /api/v1/callbacks` and `GET /api/v1/callbacks/{uuid}`
- `POST /api/v1/control/callbacks/{uuid}/snooze`
- `POST /api/v1/control/callbacks/{uuid}/reschedule`
- `POST /api/v1/control/callbacks/{uuid}/reassign`
- `POST /api/v1/control/callbacks/{uuid}/start`
- `POST /api/v1/control/callbacks/{uuid}/complete`
- `POST /api/v1/control/callbacks/{uuid}/cancel`

Dates must contain an explicit UTC offset matching `customer_timezone`. Updates carry `expected_version`; stale updates return 409. An idempotency key replay returns the prior logical result, while payload drift returns 409.
