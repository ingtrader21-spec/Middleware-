#!/bin/sh
set -eu

# Templates only. Do not execute without the later controlled-call approval.
BARESIP_BIN=/usr/bin/baresip
SERVER_A_TEST_IP=10.40.0.1
SERVER_B_SIP_IP=10.40.0.2
SIP_RUNTIME_DIR=/run/codestra-fixture-6198
SIP_EVIDENCE_DIR=/var/log/codestra-fixture-6198

# The later operator creates a private config directory containing:
#   config   (from this directory)
#   accounts (mode 0600, based on accounts.example)
#
# Registration-only template (the account registers on startup):
# timeout 30s runuser -u codestra-siptest -- \
#   "$BARESIP_BIN" -f "$SIP_RUNTIME_DIR" \
#   >"$SIP_EVIDENCE_DIR/registration.log" 2>&1
#
# One-call template. The fixed stdin contains exactly one dial instruction:
# { printf '%s\n' '/dial sip:*43@10.40.0.2'; sleep 5;
#   printf '%s\n' '/hangup' '/quit'; } |
#   timeout 30s runuser -u codestra-siptest -- \
#   "$BARESIP_BIN" -f "$SIP_RUNTIME_DIR" \
#   >"$SIP_EVIDENCE_DIR/call.log" 2>&1

# Cleanup template:
# pkill -u codestra-siptest -x baresip || true
# shred -u "$SIP_RUNTIME_DIR/accounts"
