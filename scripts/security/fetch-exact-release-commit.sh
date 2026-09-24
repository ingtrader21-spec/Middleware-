#!/usr/bin/env bash
set -euo pipefail

# The exact immutable fetch semantics are enforced here and mirrored in the
# Python implementation used for Windows compatibility.
# git fetch --no-tags --depth=1 "${remote}" "${release_sha}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if command -v python >/dev/null 2>&1; then
  exec python "${SCRIPT_DIR}/fetch-exact-release-commit.py" "$@"
fi
exec python3 "${SCRIPT_DIR}/fetch-exact-release-commit.py" "$@"
