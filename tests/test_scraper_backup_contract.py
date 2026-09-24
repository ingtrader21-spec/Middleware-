from pathlib import Path


SCRIPT = Path("deploy/scraper/scraper-middleware-offserver.sh")


def test_offhost_backup_uses_dedicated_writable_authority_without_sudo() -> None:
    source = SCRIPT.read_text()
    assert "remote_root=/srv/codestra-backups/server-a/middleware" in source
    assert "codestra-vicidial:${remote_dir}/" in source
    assert "chmod 0700 '${remote_root}' '${remote_dir}'" in source
    assert "chmod 0600 '${remote_dir}/codestra_middleware.dump.gpg'" in source
    assert "sha256sum -c SHA256SUMS" in source
    assert "sudo" not in source


def test_offhost_backup_records_checksum_readback_and_encryption() -> None:
    source = SCRIPT.read_text()
    assert "gpg --homedir" in source
    assert "REMOTE-SHA256SUMS" in source
    assert "LOCAL_ENCRYPTED_CHECKSUM=PASS" in source
    assert "OFFSERVER_COPY=PASS" in source
    assert "REMOTE_CHECKSUM_READBACK=PASS" in source
