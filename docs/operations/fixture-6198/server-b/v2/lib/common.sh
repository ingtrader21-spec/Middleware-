#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${FIXTURE_ROOT:=/etc/asterisk}"
: "${ASTERISK_BIN:=/usr/sbin/asterisk}"
: "${HOSTNAME_BIN:=/usr/bin/hostname}"
: "${LOCK_FILE:=/run/lock/codestra-fixture-6198-v2.lock}"
: "${STATE_ROOT:=/var/lib/codestra-fixture-6198-v2}"
: "${EXPECTED_HOST:=static}"
: "${FIXTURE_OWNER:=root}"
: "${FIXTURE_GROUP:=asterisk}"
: "${PACKAGE_ROOT:=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
check_host(){ [[ "$("$HOSTNAME_BIN" -f)" == "$EXPECTED_HOST" ]] || die "wrong host"; }
check_change(){ [[ "${CHANGE_ID:-}" =~ ^CHG-[A-Z0-9][A-Z0-9._-]{5,63}$ ]] || die "invalid CHANGE_ID"; }
channels_zero(){ "$ASTERISK_BIN" -rx 'core show channels count' | grep -q '^0 active channels' && "$ASTERISK_BIN" -rx 'core show channels count' | grep -q '^0 active calls'; }
endpoint_absent(){ ! "$ASTERISK_BIN" -rx 'pjsip show endpoint endpoint-6198' 2>&1 | grep -q 'Endpoint:  endpoint-6198'; }
contact_absent(){ ! "$ASTERISK_BIN" -rx 'pjsip show contacts' | grep -q 6198; }
safe_regular(){ [[ -f "$1" && ! -L "$1" ]]; }
reload_scopes(){ "$ASTERISK_BIN" -rx 'module reload res_pjsip.so'; "$ASTERISK_BIN" -rx 'dialplan reload'; }
package_digest(){
  find "$PACKAGE_ROOT" -type f ! -name fixture-manifest.yaml ! -path '*/__pycache__/*' -print0 |
    sort -z |
    while IFS= read -r -d '' file; do
      printf '%s  %s\n' "$(sha256sum "$file" | awk '{print $1}')" "${file#"$PACKAGE_ROOT"/}"
    done |
    sha256sum | awk '{print $1}'
}
atomic_replace(){
  local source=$1 destination=$2 temporary
  safe_regular "$source" || die "unsafe source file"
  [[ ! -L "$destination" ]] || die "symlink destination rejected"
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  trap 'rm -f -- "${temporary:-}"' RETURN
  cat -- "$source" >"$temporary"
  chmod --reference="$destination" "$temporary"
  chown --reference="$destination" "$temporary"
  sync -f "$temporary"
  mv -fT -- "$temporary" "$destination"
  sync -f "$(dirname -- "$destination")"
  trap - RETURN
}
static_safety(){
  local pjsip=$1 dialplan=$2 forbidden
  safe_regular "$pjsip" && safe_regular "$dialplan" || die "unsafe fixture source"
  forbidden='(Dial[[:space:]]*\(|Goto|Gosub|Macro|Queue|ConfBridge|VoiceMail|Transfer|firewall|campaign)'
  ! grep -Eiq "$forbidden" "$pjsip" "$dialplan" || die "unsupported route content"
  grep -qF 'permit=10.40.0.1/32' "$pjsip" || die "source allowlist missing"
  [[ "$(grep -Ec '^exten => ' "$dialplan")" == 2 ]] || die "unexpected destination count"
  grep -qF 'exten => *43,1,' "$dialplan" || die "echo destination missing"
}
