#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib/common.sh"
check_host
"$ASTERISK_BIN" -rx 'pjsip show endpoint endpoint-6198' | grep -q 'Endpoint:  endpoint-6198'
"$ASTERISK_BIN" -rx 'pjsip show aor 6198' | grep -q 'Aor:  6198'
"$ASTERISK_BIN" -rx 'pjsip show identify identify-6198' | grep -q '10.40.0.1/32'
"$ASTERISK_BIN" -rx 'dialplan show cs-synth-6198' | grep -Fq '*43'
echo "fixture active"
