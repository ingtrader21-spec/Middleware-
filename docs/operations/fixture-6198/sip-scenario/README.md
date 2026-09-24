# baresip future-run templates

These files are inert preparation artifacts. Do not execute them during
contract review.

The reviewed Ubuntu repository did not offer SIPp or pjsua. The selected
non-GUI client is baresip 1.0.0. The future operator must run it as an
unprivileged account, bind only the approved Server A test address, target only
`10.40.0.2`, enforce one process and one `/dial` command under a 30-second
outer timeout, and store the SIP password in a mode-0600 accounts file outside
the repository. No audio is recorded.

`accounts.example` contains placeholders only. Copy it to a protected runtime
path and replace the placeholder during the separately authorized test. Never
place the password in shell history or command-line arguments.

Before starting the client, a privileged operator must create
`/run/codestra-fixture-6198` with mode `0700` and ownership set to the dedicated
unprivileged test identity. Run `generate-test-tone.py` as that identity; do
not run the generator or Baresip as root. The script creates a mode-`0600`,
non-copyrighted 1000 Hz, 8 kHz, mono, 16-bit PCM WAV used by the installed
`aufile` module. The account is explicitly limited to `PCMU/8000/1`; received
media is consumed by the ALSA null sink and is not recorded.
