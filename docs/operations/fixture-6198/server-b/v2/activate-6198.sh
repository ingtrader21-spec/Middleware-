#!/usr/bin/env bash
set -euo pipefail
umask 077
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/lib/common.sh"
EXECUTE=0; CHANGE_ID=; PACKAGE_SHA256=
while (($#)); do case "$1" in --execute) EXECUTE=1;; --change-id) shift; CHANGE_ID="${1:-}";; --package-sha256) shift; PACKAGE_SHA256="${1:-}";; *) die "unknown argument";; esac; shift; done
check_host
static_safety "$DIR/templates/pjsip-6198.conf.in" "$DIR/templates/extensions-6198.conf"
[[ "$EXECUTE" == 0 ]] && { echo "DRY-RUN: activation prerequisites only"; channels_zero; endpoint_absent; contact_absent; exit 0; }
check_change; [[ "$PACKAGE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid package checksum"
[[ "$(package_digest)" == "$PACKAGE_SHA256" ]] || die "package checksum mismatch"
channels_zero; endpoint_absent; contact_absent
safe_regular "${SIP_SECRET_FILE:?protected SIP_SECRET_FILE required}" || die "unsafe secret reference"
[[ "$(stat -c %a "$SIP_SECRET_FILE")" == 600 ]] || die "unsafe secret mode"
exec 9>"$LOCK_FILE"; flock -n 9 || die "lock contention"
[[ ! -e "$STATE_ROOT" ]] || die "activation state already exists"
mkdir -m 0700 -- "$STATE_ROOT"
cp -a -- "$FIXTURE_ROOT/pjsip.conf" "$FIXTURE_ROOT/extensions.conf" "$STATE_ROOT/"
sha256sum "$STATE_ROOT/pjsip.conf" "$STATE_ROOT/extensions.conf" >"$STATE_ROOT/SHA256SUMS"
rollback(){
  atomic_replace "$STATE_ROOT/pjsip.conf" "$FIXTURE_ROOT/pjsip.conf"
  atomic_replace "$STATE_ROOT/extensions.conf" "$FIXTURE_ROOT/extensions.conf"
  rm -f -- "$FIXTURE_ROOT/pjsip-codestra-synthetic-6198.conf" "$FIXTURE_ROOT/extensions-codestra-synthetic-6198.conf"
  reload_scopes || true
  rm -rf -- "$STATE_ROOT"
}
trap 'rollback' ERR
STAGE="$(mktemp -d /run/fixture-6198-v2.XXXXXX)"
"$DIR/render-fixture.py" --secret-file "$SIP_SECRET_FILE" --output-dir "$STAGE"
install -o "$FIXTURE_OWNER" -g "$FIXTURE_GROUP" -m 0640 "$STAGE/pjsip-6198.conf" "$FIXTURE_ROOT/pjsip-codestra-synthetic-6198.conf"
install -o "$FIXTURE_OWNER" -g "$FIXTURE_GROUP" -m 0640 "$STAGE/extensions-6198.conf" "$FIXTURE_ROOT/extensions-codestra-synthetic-6198.conf"
PJSIP_NEXT="$(mktemp "$STATE_ROOT/pjsip.next.XXXXXX")"
EXT_NEXT="$(mktemp "$STATE_ROOT/extensions.next.XXXXXX")"
cat "$FIXTURE_ROOT/pjsip.conf" >"$PJSIP_NEXT"; printf '%s\n' '#include pjsip-codestra-synthetic-6198.conf' >>"$PJSIP_NEXT"
cat "$FIXTURE_ROOT/extensions.conf" >"$EXT_NEXT"; printf '%s\n' '#include extensions-codestra-synthetic-6198.conf' >>"$EXT_NEXT"
atomic_replace "$PJSIP_NEXT" "$FIXTURE_ROOT/pjsip.conf"
atomic_replace "$EXT_NEXT" "$FIXTURE_ROOT/extensions.conf"
reload_scopes || { rollback; trap - ERR; die "reload failed and rollback completed"; }
"$DIR/verify-active.sh" || { rollback; trap - ERR; die "verification failed and rollback completed"; }
trap - ERR
echo "activation complete"
