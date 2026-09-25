#!/usr/bin/env bash
set -Eeuo pipefail

image="${1:?image reference required}"
expected_sha="${2:?source revision required}"
expected_version="${3:?source version required}"
expected_source="${4:-https://github.com/ingtrader21-spec/Middleware-}"
synthetic_marker="${5:-CODESTRA_SYNTHETIC_SECRET_MUST_NOT_APPEAR_7f4c2a}"

inspect="$(docker image inspect "$image")"
python3 -c '
import json, sys
document = json.load(sys.stdin)[0]
expected_sha, expected_version, expected_source = sys.argv[1:]
config = document["Config"]
labels = config.get("Labels") or {}
assert config.get("User") not in {"", "0", "0:0", "root"}, config.get("User")
assert labels.get("org.opencontainers.image.source") == expected_source
assert labels.get("org.opencontainers.image.revision") == expected_sha
assert labels.get("org.opencontainers.image.version") == expected_version
assert labels.get("org.opencontainers.image.created")
' "$expected_sha" "$expected_version" "$expected_source" <<<"$inspect"

if docker history --no-trunc "$image" | grep -F "$synthetic_marker"; then
  echo "synthetic secret marker found in image history" >&2
  exit 1
fi
if printf '%s' "$inspect" | grep -F "$synthetic_marker"; then
  echo "synthetic secret marker found in image configuration" >&2
  exit 1
fi

temp_root="${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}"
mkdir -p -- "$temp_root"
image_archive="$(mktemp -d "${temp_root%/}/middleware-image-verify.XXXXXX")"
trap 'rm -rf -- "$image_archive"' EXIT
docker save --output "$image_archive/image.tar" "$image"
if grep -aF "$synthetic_marker" "$image_archive/image.tar"; then
  echo "synthetic secret marker found in image filesystem/layers" >&2
  exit 1
fi

echo "CONTAINER_IMAGE_POLICY=PASS"
