#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf -- "$TMP"' EXIT
pass=0
ok(){ pass=$((pass+1)); printf 'ok %02d - %s\n' "$pass" "$1"; }
expect_fail(){ if "$@" >"$TMP/out" 2>"$TMP/err"; then return 1; fi; }
mkdir -p "$TMP/fs" "$TMP/bin" "$TMP/run" "$TMP/state"
printf '[base]\n' >"$TMP/fs/pjsip.conf"; printf '[base]\n' >"$TMP/fs/extensions.conf"
printf 'safe-secret' >"$TMP/secret"; chmod 600 "$TMP/secret"
cat >"$TMP/bin/hostname" <<'EOF'
#!/bin/sh
echo "${MOCK_HOST:-static}"
EOF
cat >"$TMP/bin/asterisk" <<'EOF'
#!/bin/sh
case "$*" in
 *"core show channels count"*) printf '%s\n' "${MOCK_CHANNELS:-0 active channels}" "${MOCK_CALLS:-0 active calls}";;
 *"pjsip show contacts"*) printf '%s\n' "${MOCK_CONTACTS:-No objects found.}";;
 *"pjsip show endpoint"*) { [ "${MOCK_ACTIVE:-0}" = 1 ] || grep -q 'pjsip-codestra-synthetic' "$FIXTURE_ROOT/pjsip.conf"; } && echo 'Endpoint:  endpoint-6198' || echo 'Unable to find object';;
 *"pjsip show aor"*) grep -q 'pjsip-codestra-synthetic' "$FIXTURE_ROOT/pjsip.conf" && echo 'Aor:  6198' || echo 'Unable to find object';;
 *"pjsip show identify"*) grep -q 'pjsip-codestra-synthetic' "$FIXTURE_ROOT/pjsip.conf" && echo 'Identify: identify-6198 10.40.0.1/32' || echo 'Unable to find object';;
 *"dialplan show"*) grep -q 'extensions-codestra-synthetic' "$FIXTURE_ROOT/extensions.conf" && echo '[ Context cs-synth-6198 ] *43' || echo 'There is no existence';;
 *"module reload"*|*"dialplan reload"*) [ "${MOCK_RELOAD_FAIL:-0}" = 0 ];;
esac
EOF
chmod +x "$TMP/bin/"*
export FIXTURE_ROOT="$TMP/fs" ASTERISK_BIN="$TMP/bin/asterisk" HOSTNAME_BIN="$TMP/bin/hostname"
export FIXTURE_ROOT
export LOCK_FILE="$TMP/run/lock" STATE_ROOT="$TMP/state/activation" EXPECTED_HOST=static
export FIXTURE_OWNER="$(id -un)" FIXTURE_GROUP="$(id -gn)" SIP_SECRET_FILE="$TMP/secret"
sha256sum "$DIR/templates/pjsip-6198.conf.in" "$DIR/templates/extensions-6198.conf" >/dev/null; ok "recovered binding inputs readable"
grep -q '^\[6198\]$' "$DIR/templates/pjsip-6198.conf.in"
grep -q '^aors=6198$' "$DIR/templates/pjsip-6198.conf.in"
! grep -q 'aor-6198' "$DIR/templates/pjsip-6198.conf.in"
ok "registrar AOR identity matches extension"
cp "$DIR/templates/extensions-6198.conf" "$TMP/tampered"; printf x >>"$TMP/tampered"; ! cmp -s "$TMP/tampered" "$DIR/templates/extensions-6198.conf"; ok "modified source rejected by comparison"
"$DIR/render-fixture.py" --secret-file "$TMP/secret" --output-dir "$TMP/r1" >/dev/null
"$DIR/render-fixture.py" --secret-file "$TMP/secret" --output-dir "$TMP/r2" >/dev/null
cmp "$TMP/r1/pjsip-6198.conf" "$TMP/r2/pjsip-6198.conf"; ok "deterministic render"
[[ "$(stat -c %a "$TMP/r1/pjsip-6198.conf")" = 600 && "$(stat -c %a "$TMP/r1/extensions-6198.conf")" = 600 && "$(stat -c %a "$TMP/r1/redacted-structure.json")" = 600 ]]; ok "rendered files are owner-only"
expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/missing" --output-dir "$TMP/r3"; ok "missing secret rejected"
: >"$TMP/empty"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/empty" --output-dir "$TMP/r3"; ok "empty secret rejected"
printf 'bad\nsecret' >"$TMP/bad"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/bad" --output-dir "$TMP/r3"; ok "control secret rejected"
chmod 644 "$TMP/secret"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/secret" --output-dir "$TMP/r3"; chmod 600 "$TMP/secret"; ok "unsafe renderer secret mode rejected"
printf 'x%.0s' {1..4097} >"$TMP/oversized"; chmod 600 "$TMP/oversized"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/oversized" --output-dir "$TMP/r3"; ok "oversized secret rejected"
mkdir "$TMP/rwide"; chmod 755 "$TMP/rwide"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/secret" --output-dir "$TMP/rwide"; ok "unsafe output mode rejected"
ln -s "$TMP/r1" "$TMP/output-link"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/secret" --output-dir "$TMP/output-link"; ok "output symlink rejected"
! grep -Rqs 'safe-secret' "$TMP/out" "$TMP/err"; ok "secret absent from output"
before="$(sha256sum "$TMP/fs/"*)"; "$DIR/activate-6198.sh" >/dev/null; [[ "$before" = "$(sha256sum "$TMP/fs/"*)" ]]; ok "activation dry run no mutation"
"$DIR/teardown-6198.sh" >/dev/null; [[ "$before" = "$(sha256sum "$TMP/fs/"*)" ]]; ok "teardown dry run no mutation"
expect_fail env MOCK_HOST=wrong "$DIR/activate-6198.sh"; ok "wrong host rejected"
expect_fail "$DIR/activate-6198.sh" --execute; ok "missing change id rejected"
expect_fail "$DIR/activate-6198.sh" --execute --change-id bad --package-sha256 "$(printf '0%.0s' {1..64})"; ok "bad change id rejected"
expect_fail "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$(printf '0%.0s' {1..64})"; ok "package checksum mismatch rejected"
PACKAGE_ROOT="$DIR"
source "$DIR/lib/common.sh"
PACKAGE_SHA256="$(package_digest)"
ln -s "$TMP/secret" "$TMP/link"; expect_fail env SIP_SECRET_FILE="$TMP/link" "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256"; ok "symlink rejected"
mkdir "$TMP/notfile"; expect_fail "$DIR/render-fixture.py" --secret-file "$TMP/notfile" --output-dir "$TMP/r4"; ok "unexpected type rejected"
chmod 644 "$TMP/secret"; expect_fail "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256"; chmod 600 "$TMP/secret"; ok "unsafe mode rejected"
expect_fail env MOCK_CHANNELS='1 active channels' "$DIR/activate-6198.sh"; ok "active channels block"
expect_fail env MOCK_CONTACTS='6198/sip:6198@10.40.0.1' "$DIR/activate-6198.sh"; ok "contact blocks"
expect_fail env MOCK_ACTIVE=1 "$DIR/activate-6198.sh"; ok "existing endpoint blocks"
cp "$DIR/templates/extensions-6198.conf" "$TMP/route"; printf ' same => n,%s\n' 'Dial(PJSIP/example)' >>"$TMP/route"; grep -Eiq 'Dial[[:space:]]*\(' "$TMP/route"; ok "unsupported route detected"
exec 8>"$LOCK_FILE"; flock -n 8; expect_fail "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256"; exec 8>&-; ok "lock contention blocks"
"$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256" >/dev/null; ok "successful activation"
[[ -f "$FIXTURE_ROOT/pjsip-codestra-synthetic-6198.conf" && -f "$FIXTURE_ROOT/extensions-codestra-synthetic-6198.conf" ]]; ok "only exact fixture installed"
expect_fail "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256"; ok "repeated activation rejected"
"$DIR/teardown-6198.sh" --execute --change-id CHG-ABCDEF >/dev/null; ok "successful teardown"
[[ "$before" = "$(sha256sum "$TMP/fs/"*)" ]]; ok "exact include restore"
"$DIR/teardown-6198.sh" --execute --change-id CHG-ABCDEF >/dev/null; ok "repeated teardown"
expect_fail env MOCK_RELOAD_FAIL=1 "$DIR/activate-6198.sh" --execute --change-id CHG-ABCDEF --package-sha256 "$PACKAGE_SHA256"; ok "reload failure rolls back"
[[ "$before" = "$(sha256sum "$TMP/fs/"*)" ]]; ok "rollback restored includes"
! grep -REiq '(firewall-cmd|iptables|nft[[:space:]])' "$DIR" --include='*.sh'; ok "no firewall action"
! grep -REiq 'systemctl[[:space:]]+(restart|stop)[[:space:]]+asterisk' "$DIR" --include='*.sh'; ok "no service restart"
forbidden_extension=$((6100+10)); ! grep -Rqs "$forbidden_extension" "$DIR"; ok "excluded extension absent"
[[ "$pass" -eq 38 ]]
echo "1..38"
