#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib/common.sh"
EXECUTE=0; CHANGE_ID=
while (($#)); do case "$1" in --execute) EXECUTE=1;; --change-id) shift; CHANGE_ID="${1:-}";; *) die "unknown argument";; esac; shift; done
check_host
[[ "$EXECUTE" == 0 ]] && { echo "DRY-RUN: teardown prerequisites only"; exit 0; }
check_change; channels_zero; contact_absent
exec 9>"$LOCK_FILE"; flock -n 9 || die "lock contention"
if [[ ! -d "$STATE_ROOT" ]]; then "$DIR/verify-inactive.sh"; echo "already inactive"; exit 0; fi
(cd "$STATE_ROOT" && sha256sum -c SHA256SUMS)
atomic_replace "$STATE_ROOT/pjsip.conf" "$FIXTURE_ROOT/pjsip.conf"
atomic_replace "$STATE_ROOT/extensions.conf" "$FIXTURE_ROOT/extensions.conf"
rm -f -- "$FIXTURE_ROOT/pjsip-codestra-synthetic-6198.conf" "$FIXTURE_ROOT/extensions-codestra-synthetic-6198.conf"
reload_scopes
"$DIR/verify-inactive.sh"
rm -rf -- "$STATE_ROOT"
echo "teardown complete"
