#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_root=/opt/codestra/backups/scraper-middleware-scheduled
stamp=$(date -u +%Y%m%dT%H%M%SZ)
final_dir=${backup_root}/${stamp}
install -d -m 0700 "${backup_root}"
work_dir=$(mktemp -d "${backup_root}/.work-${stamp}.XXXXXX")
remote_root=/srv/codestra-backups/server-a/middleware
remote_dir=${remote_root}/${stamp}

cleanup() {
  case "${work_dir}" in
    "${backup_root}"/.work-20*T*Z.*)
      if [[ -d "${work_dir}" && ! -L "${work_dir}" ]]; then
        find "${work_dir}" -xdev -type f -exec shred -u -- {} +
        rmdir "${work_dir}"
      fi
      ;;
    *)
      printf 'refusing unsafe work directory: %s\n' "${work_dir}" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

install -d -m 0700 "${final_dir}"
docker exec codestra-postgres-1 \
  pg_dump -U postgres -Fc codestra_middleware \
  > "${work_dir}/codestra_middleware.dump"
gpg --homedir /etc/codestra/backup-gpg --batch --yes --trust-model always \
  --recipient 'Codestra Backup Recipient' \
  --output "${final_dir}/codestra_middleware.dump.gpg" \
  --encrypt "${work_dir}/codestra_middleware.dump"
(
  cd "${final_dir}"
  sha256sum codestra_middleware.dump.gpg > SHA256SUMS
  sha256sum -c SHA256SUMS
)
ssh -o BatchMode=yes codestra-vicidial \
  "install -d -m 0700 '${remote_root}' '${remote_dir}'"
scp -q "${final_dir}/codestra_middleware.dump.gpg" \
  "${final_dir}/SHA256SUMS" \
  "codestra-vicidial:${remote_dir}/"
ssh -o BatchMode=yes codestra-vicidial \
  "chmod 0700 '${remote_root}' '${remote_dir}' &&
   chmod 0600 '${remote_dir}/codestra_middleware.dump.gpg' '${remote_dir}/SHA256SUMS' &&
   cd '${remote_dir}' && sha256sum -c SHA256SUMS"
ssh -o BatchMode=yes codestra-vicidial \
  "cd '${remote_dir}' && sha256sum codestra_middleware.dump.gpg" \
  > "${final_dir}/REMOTE-SHA256SUMS"
diff -u \
  <(sort "${final_dir}/SHA256SUMS") \
  <(sort "${final_dir}/REMOTE-SHA256SUMS")
cat > "${final_dir}/STATUS.txt" <<EOF
BACKUP_UTC=${stamp}
DATABASE=codestra_middleware
PRODUCTION_SERVICES_PAUSED=NO
LOCAL_ENCRYPTED_CHECKSUM=PASS
OFFSERVER_COPY=PASS
REMOTE_CHECKSUM_READBACK=PASS
EOF
chmod 0600 "${final_dir}"/*

# Keep 14 successful local encrypted snapshots. This never touches database,
# Docker, evidence, or off-server data.
mapfile -t old_snapshots < <(
  find "${backup_root}" -mindepth 1 -maxdepth 1 -type d \
    -name '20??????T??????Z' -printf '%f\n' | sort -r | tail -n +15
)
for old_name in "${old_snapshots[@]}"; do
  old_path=${backup_root}/${old_name}
  [[ "${old_path}" == "${backup_root}"/20??????T??????Z ]]
  [[ -d "${old_path}" && ! -L "${old_path}" ]]
  find "${old_path}" -xdev -type f -exec shred -u -- {} +
  rmdir "${old_path}"
done

printf '%s\n' "${final_dir}"
