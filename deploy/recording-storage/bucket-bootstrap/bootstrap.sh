#!/bin/sh
set -eu
test "${DEPLOYMENT_ENVIRONMENT:-staging}" != production ||
  test -n "${PRODUCTION_KMS_PROVIDER:-}" ||
  { echo "production blocked: external KMS provider required" >&2; exit 78; }
mc alias set private-storage https://minio:9000 \
  "$(cat "$MINIO_ROOT_USER_FILE")" "$(cat "$MINIO_ROOT_PASSWORD_FILE")"
mc mb --with-lock --ignore-existing "private-storage/${RECORDING_BUCKET}"
mc version enable "private-storage/${RECORDING_BUCKET}"
mc encrypt set sse-s3 "private-storage/${RECORDING_BUCKET}"
mc retention set --default GOVERNANCE "${DEFAULT_RETENTION_DAYS}d" \
  "private-storage/${RECORDING_BUCKET}"
for policy in /policies/*.json; do
  mc admin policy create private-storage "$(basename "$policy" .json)" "$policy"
done
