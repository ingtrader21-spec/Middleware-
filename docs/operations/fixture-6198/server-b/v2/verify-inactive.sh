#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib/common.sh"
check_host; channels_zero; endpoint_absent; contact_absent
! "$ASTERISK_BIN" -rx 'dialplan show cs-synth-6198' 2>&1 | grep -q '\[ Context'
echo "fixture inactive"
