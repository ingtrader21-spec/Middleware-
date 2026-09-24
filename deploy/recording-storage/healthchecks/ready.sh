#!/bin/sh
exec curl --fail --silent --show-error --cacert /run/secrets/storage_ca.pem \
  https://127.0.0.1:9000/minio/health/ready
