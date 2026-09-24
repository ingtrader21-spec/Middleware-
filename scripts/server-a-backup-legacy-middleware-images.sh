#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${MIDDLEWARE_AUTHORITY_CATALOG:-${ROOT_DIR}/config/middleware-authority-convergence.v1.json}"
STATE_ROOT="${MIDDLEWARE_AUTHORITY_BACKUP_ROOT:-/var/lib/codestra-middleware/authority-backups}"
REGISTRY_AUTH_FILE="${REGISTRY_AUTH_FILE:-/root/.config/containers/auth.json}"
EXPECTED_HOST="65.109.65.169"
EXPECTED_LOCAL_FAMILIES=11
MODE="${1:-status}"
RUN_STAMP="$(date -u +'%Y%m%dT%H%M%SZ')-$$"
RUN_ROOT="${STATE_ROOT}/${RUN_STAMP}"
ROWS_FILE=""

fail() {
  printf 'MIDDLEWARE_LEGACY_BACKUP=FAIL\n' >&2
  printf 'FAILURE_REASON=%s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [[ -n "${ROWS_FILE:-}" ]]; then
    rm -f -- "$ROWS_FILE"
  fi
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing_command_$1"
}

validate_private_file() {
  local path="$1" label="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "${label}_missing_or_symlink"
  [[ "$(stat -c '%u' "$path")" -eq 0 ]] || fail "${label}_not_root_owned"
  if find "$path" -perm /077 -print -quit | grep -q .; then
    fail "${label}_permissions_too_broad"
  fi
}

[[ "$(id -u)" -eq 0 ]] || fail "root_required"

case "$MODE" in
  status|archive|mirror|all) ;;
  *) fail "usage_status_archive_mirror_or_all" ;;
esac

for command in python3 docker gzip sha256sum tar realpath stat ip hostname mktemp; do
  require_command "$command"
done

[[ -f "$CATALOG" && ! -L "$CATALOG" ]] ||
  fail "catalog_missing_or_symlink"
python3 "${ROOT_DIR}/scripts/validate_middleware_authority_convergence.py" \
  "$CATALOG" >/dev/null ||
  fail "catalog_validation_failed"

catalog_host="$(
  python3 - "$CATALOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
print(value["serverA"]["host"])
PY
)"
[[ "$catalog_host" == "$EXPECTED_HOST" ]] || fail "catalog_host_mismatch"

if ! ip -o -4 addr show scope global |
    awk '{print $4}' |
    cut -d/ -f1 |
    grep -Fxq "$EXPECTED_HOST"; then
  fail "server_a_host_identity_mismatch"
fi

[[ "$STATE_ROOT" == /* && "$STATE_ROOT" != "/" && "$STATE_ROOT" != *"/../"* ]] ||
  fail "unsafe_state_root"
install -d -m 0700 -o root -g root "$STATE_ROOT"
[[ -d "$STATE_ROOT" && ! -L "$STATE_ROOT" ]] ||
  fail "state_root_missing_or_symlink"
[[ "$(realpath "$STATE_ROOT")" == "$STATE_ROOT" ]] ||
  fail "state_root_not_canonical"
[[ "$(stat -c '%u' "$STATE_ROOT")" -eq 0 ]] ||
  fail "state_root_not_root_owned"
if find "$STATE_ROOT" -maxdepth 0 -perm /077 -print -quit | grep -q .; then
  fail "state_root_permissions_too_broad"
fi

docker info >/dev/null 2>&1 || fail "docker_daemon_unavailable"

catalog_rows() {
  python3 - "$CATALOG" <<'PY'
from __future__ import annotations

import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)

selected = 0
for family in value["runtimeImageFamilies"]:
    backup = family["backup"]
    if backup["method"] != "server-a-archive-and-config-digest-mirror":
        continue
    fields = [
        family["id"],
        family["digest"],
        family["runtimeReference"],
        backup["destinationTag"],
        ",".join(family["workloads"]),
    ]
    if any("\t" in str(field) or "\n" in str(field) for field in fields):
        raise SystemExit("catalog contains unsafe tab/newline data")
    if not fields[4]:
        raise SystemExit(f"catalog family {fields[0]} has no workloads")
    print("\t".join(fields))
    selected += 1

if selected != 11:
    raise SystemExit(f"expected 11 local backup families, got {selected}")
PY
}

verify_image_and_workloads() {
  local family_id="$1" expected_id="$2" runtime_reference="$3" workload_csv="$4"
  local actual_image_id workload actual state
  local seen=0
  local -a workloads

  actual_image_id="$(
    docker image inspect --format '{{.Id}}' "$expected_id" 2>/dev/null
  )" || fail "MISSING_IMAGE_${family_id}"
  [[ "$actual_image_id" == "$expected_id" ]] ||
    fail "IMAGE_ID_MISMATCH_${family_id}"

  IFS=',' read -r -a workloads <<<"$workload_csv"
  [[ "${#workloads[@]}" -gt 0 ]] ||
    fail "MISSING_EXPECTED_WORKLOADS_${family_id}"

  for workload in "${workloads[@]}"; do
    docker container inspect "$workload" >/dev/null 2>&1 ||
      fail "MISSING_EXPECTED_WORKLOADS_${family_id}_${workload}"

    actual="$(
      docker container inspect --format '{{.Image}}' "$workload"
    )"
    state="$(
      docker container inspect --format '{{.State.Status}}' "$workload"
    )"
    [[ "$actual" == "$expected_id" ]] ||
      fail "RUNTIME_IMAGE_ID_MISMATCH_${family_id}_${workload}"

    printf 'family=%s workload=%s status=MATCH state=%s image_id=%s reference=%s\n' \
      "$family_id" "$workload" "$state" "$actual" "$runtime_reference"
    seen=$((seen + 1))
  done

  [[ "$seen" -eq "${#workloads[@]}" ]] ||
    fail "MISSING_EXPECTED_WORKLOADS_${family_id}"

  printf 'family=%s image_status=MATCH observed_workloads=%s expected_workloads=%s\n' \
    "$family_id" "$seen" "${#workloads[@]}"
}

capture_workload_metadata() {
  local output="$1" expected_id="$2" workload_csv="$3"
  python3 - "$output" "$expected_id" "$workload_csv" <<'PY'
from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

output, expected_id, workload_csv = sys.argv[1:]
records: list[dict[str, object]] = []

for name in workload_csv.split(","):
    document = json.loads(
        subprocess.check_output(
            ["docker", "container", "inspect", name],
            text=True,
        )
    )
    if not isinstance(document, list) or len(document) != 1:
        raise SystemExit(f"unexpected docker inspect result for {name}")
    container = document[0]
    image_id = container.get("Image")
    if image_id != expected_id:
        raise SystemExit(
            f"container {name} image mismatch: expected {expected_id}, "
            f"got {image_id!r}"
        )

    config = container.get("Config") or {}
    state = container.get("State") or {}
    health = state.get("Health") or {}
    labels = config.get("Labels") or {}
    mounts = [
        {
            "type": mount.get("Type"),
            "destination": mount.get("Destination"),
            "read_only": not bool(mount.get("RW")),
        }
        for mount in container.get("Mounts") or []
    ]

    def digest_json(value: object) -> str:
        encoded = json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    records.append(
        {
            "name": name,
            "image_id": image_id,
            "state": state.get("Status"),
            "health": health.get("Status"),
            "entrypoint_sha256": digest_json(config.get("Entrypoint") or []),
            "command_sha256": digest_json(config.get("Cmd") or []),
            "compose": {
                "project": labels.get("com.docker.compose.project"),
                "service": labels.get("com.docker.compose.service"),
                "working_dir": labels.get(
                    "com.docker.compose.project.working_dir"
                ),
                "config_files": labels.get(
                    "com.docker.compose.project.config_files"
                ),
            },
            "mounts": sorted(
                mounts,
                key=lambda value: (
                    str(value.get("destination")),
                    str(value.get("type")),
                ),
            ),
        }
    )

value = {
    "schema_version": 1,
    "captured_at": datetime.now(UTC).isoformat(),
    "environment_values_captured": False,
    "mount_sources_captured": False,
    "mount_destinations_captured": True,
    "containers": records,
}
Path(output).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

verify_docker_save_archive() {
  local archive="$1" expected_id="$2" output="$3"
  python3 - "$archive" "$expected_id" "$output" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive_path, expected_id, output_path = sys.argv[1:]
expected_hex = expected_id.removeprefix("sha256:")
if len(expected_hex) != 64:
    raise SystemExit("expected Docker image ID is malformed")

with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    names = [member.name for member in members]
    if len(names) != len(set(names)):
        raise SystemExit("docker save archive contains duplicate members")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe Docker archive member: {name!r}")

    try:
        manifest_member = archive.getmember("manifest.json")
    except KeyError as exc:
        raise SystemExit("docker save archive is missing manifest.json") from exc
    manifest_stream = archive.extractfile(manifest_member)
    if manifest_stream is None:
        raise SystemExit("docker save manifest is not a regular file")
    manifest = json.load(manifest_stream)
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise SystemExit(
            "docker save archive must contain exactly one image manifest"
        )

    record = manifest[0]
    config_name = record.get("Config")
    layers = record.get("Layers")
    if not isinstance(config_name, str) or not config_name:
        raise SystemExit("docker save manifest has no config object")
    if not isinstance(layers, list) or not layers:
        raise SystemExit("docker save manifest has no layers")
    if len(layers) != len(set(layers)):
        raise SystemExit("docker save manifest contains duplicate layers")

    try:
        config_member = archive.getmember(config_name)
    except KeyError as exc:
        raise SystemExit("docker save config object is missing") from exc
    config_stream = archive.extractfile(config_member)
    if config_stream is None:
        raise SystemExit("docker save config object is not a regular file")
    actual_config_digest = hashlib.sha256(config_stream.read()).hexdigest()
    if actual_config_digest != expected_hex:
        raise SystemExit(
            "docker save config digest mismatch: "
            f"expected sha256:{expected_hex}, "
            f"got sha256:{actual_config_digest}"
        )

    layer_records = []
    for layer_name in layers:
        if not isinstance(layer_name, str) or not layer_name:
            raise SystemExit(
                "docker save manifest contains an invalid layer name"
            )
        path = PurePosixPath(layer_name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe Docker layer member: {layer_name!r}")
        try:
            layer = archive.getmember(layer_name)
        except KeyError as exc:
            raise SystemExit(
                f"docker save layer is missing: {layer_name}"
            ) from exc
        if not layer.isfile():
            raise SystemExit(
                f"docker save layer is not a regular file: {layer_name}"
            )
        layer_records.append(
            {"name": layer_name, "size": layer.size}
        )

value = {
    "schema_version": 1,
    "format": "docker-save",
    "image_count": 1,
    "expected_config_digest": expected_id,
    "verified_config_digest": f"sha256:{actual_config_digest}",
    "layer_count": len(layer_records),
    "layers": layer_records,
    "archive_structure_verified": True,
    "isolated_restore_performed": False,
    "isolated_restore_required_before_cutover": True,
    "verification": "PASS",
}
Path(output_path).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

archive_family() {
  local family_id="$1" expected_id="$2" runtime_reference="$3"
  local destination_tag="$4" workload_csv="$5"
  local family_dir archive archive_digest machine_id_digest

  family_dir="${RUN_ROOT}/${family_id}"
  archive="${family_dir}/image.tar.gz"
  install -d -m 0700 -o root -g root "$family_dir"

  verify_image_and_workloads \
    "$family_id" "$expected_id" "$runtime_reference" "$workload_csv" \
    >"${family_dir}/runtime-identity.txt"

  capture_workload_metadata \
    "${family_dir}/workload-metadata.json" \
    "$expected_id" "$workload_csv"

  docker image inspect --format \
    '{"id":{{json .Id}},"repo_tags":{{json .RepoTags}},"repo_digests":{{json .RepoDigests}},"created":{{json .Created}},"os":{{json .Os}},"architecture":{{json .Architecture}}}' \
    "$expected_id" >"${family_dir}/image-metadata.json"

  docker image save "$expected_id" | gzip -n -9 >"$archive"
  gzip -t "$archive"
  archive_digest="sha256:$(sha256sum "$archive" | awk '{print $1}')"
  verify_docker_save_archive \
    "$archive" "$expected_id" "${family_dir}/archive-structure.json"

  machine_id_digest="UNAVAILABLE"
  if [[ -f /etc/machine-id && ! -L /etc/machine-id ]]; then
    machine_id_digest="sha256:$(
      sha256sum /etc/machine-id | awk '{print $1}'
    )"
  fi

  python3 - "${family_dir}/backup-evidence.json" \
    "$family_id" "$expected_id" "$runtime_reference" "$destination_tag" \
    "$archive" "$archive_digest" "$workload_csv" "$EXPECTED_HOST" \
    "$(hostname)" "$machine_id_digest" <<'PY'
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import sys

(
    output,
    family_id,
    image_id,
    runtime_reference,
    destination_tag,
    archive,
    archive_digest,
    workloads,
    expected_host,
    hostname,
    machine_id_digest,
) = sys.argv[1:]

value = {
    "schema_version": 1,
    "captured_at": datetime.now(UTC).isoformat(),
    "family_id": family_id,
    "docker_image_id": image_id,
    "runtime_reference": runtime_reference,
    "workloads": workloads.split(","),
    "server_a_expected_address": expected_host,
    "server_hostname": hostname,
    "server_machine_id_sha256": machine_id_digest,
    "archive": archive,
    "archive_sha256": archive_digest,
    "planned_appolon_backup_tag": destination_tag,
    "environment_values_captured": False,
    "mount_sources_captured": False,
    "archive_structure_verified": True,
    "isolated_restore_performed": False,
    "isolated_restore_required_before_cutover": True,
    "container_restart_performed": False,
    "compose_changed": False,
    "traffic_changed": False,
    "verification": "PASS",
}
Path(output).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

  printf 'family=%s archive=%s archive_digest=%s config_digest=%s status=PASS\n' \
    "$family_id" "$archive" "$archive_digest" "$expected_id"
}

mirror_family() {
  local family_id="$1" expected_id="$2" runtime_reference="$3"
  local destination_tag="$4" workload_csv="$5"

  require_command skopeo
  validate_private_file "$REGISTRY_AUTH_FILE" "registry_auth_file"
  python3 -m json.tool "$REGISTRY_AUTH_FILE" >/dev/null ||
    fail "registry_auth_file_invalid_json"

  verify_image_and_workloads \
    "$family_id" "$expected_id" "$runtime_reference" "$workload_csv" \
    >/dev/null

  (
    set -Eeuo pipefail
    local short temp_ref destination_digest evidence_dir

    short="${expected_id#sha256:}"
    short="${short:0:12}"
    temp_ref="localhost/codestra-middleware-legacy:${family_id}-${short}-$$"
    evidence_dir="${RUN_ROOT}/${family_id}/registry-mirror"
    install -d -m 0700 -o root -g root "$evidence_dir"

    cleanup_temp_tag() {
      docker image rm "$temp_ref" >/dev/null 2>&1 || true
    }
    trap cleanup_temp_tag EXIT

    docker image tag "$expected_id" "$temp_ref"
    skopeo copy \
      --all \
      --dest-authfile "$REGISTRY_AUTH_FILE" \
      "docker-daemon:${temp_ref}" \
      "docker://${destination_tag}"

    skopeo inspect \
      --authfile "$REGISTRY_AUTH_FILE" \
      --raw "docker://${destination_tag}" \
      >"${evidence_dir}/destination-manifest.json"
    destination_digest="$(
      skopeo inspect \
        --authfile "$REGISTRY_AUTH_FILE" \
        --format '{{.Digest}}' \
        "docker://${destination_tag}"
    )"
    [[ "$destination_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
      fail "destination_manifest_digest_invalid"

    python3 - "${evidence_dir}/destination-manifest.json" \
      "$expected_id" <<'PY'
from __future__ import annotations

import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
expected = sys.argv[2]
actual = manifest.get("config", {}).get("digest")
if actual != expected:
    raise SystemExit(
        "destination OCI config digest mismatch: "
        f"expected {expected}, got {actual!r}"
    )
PY

    python3 - "${evidence_dir}/mirror-evidence.json" \
      "$family_id" "$expected_id" "$runtime_reference" \
      "$destination_tag" "$destination_digest" <<'PY'
from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import sys

(
    output,
    family_id,
    image_id,
    source,
    destination,
    destination_digest,
) = sys.argv[1:]
value = {
    "schema_version": 1,
    "mirrored_at": datetime.now(UTC).isoformat(),
    "family_id": family_id,
    "source_runtime_reference": source,
    "source_docker_image_id": image_id,
    "destination_tag": destination,
    "destination_manifest_digest": destination_digest,
    "destination_config_digest": image_id,
    "temporary_local_tag_created": True,
    "temporary_local_tag_removed_on_exit": True,
    "runtime_mutated": False,
    "container_restart_performed": False,
    "verification": "PASS",
}
Path(output).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

    printf 'family=%s destination=%s destination_digest=%s config_digest=%s status=PASS\n' \
      "$family_id" "$destination_tag" "$destination_digest" "$expected_id"
  )
}

write_run_checksums() {
  [[ -d "$RUN_ROOT" ]] || fail "evidence_root_missing"
  (
    set -Eeuo pipefail
    cd "$RUN_ROOT"
    find . -type f ! -name SHA256SUMS -print0 |
      sort -z |
      xargs -0 -r sha256sum >SHA256SUMS
    test -s SHA256SUMS
    sha256sum --check --strict SHA256SUMS >/dev/null
  )
}

ROWS_FILE="$(mktemp)"
catalog_rows >"$ROWS_FILE" || fail "catalog_rows_failed"
[[ "$(wc -l <"$ROWS_FILE")" -eq "$EXPECTED_LOCAL_FAMILIES" ]] ||
  fail "local_image_family_count_mismatch"

if [[ "$MODE" != "status" ]]; then
  install -d -m 0700 -o root -g root "$RUN_ROOT"
fi

processed=0
while IFS=$'\t' read -r family_id expected_id runtime_reference \
    destination_tag workload_csv; do
  case "$MODE" in
    status)
      verify_image_and_workloads \
        "$family_id" "$expected_id" "$runtime_reference" "$workload_csv"
      ;;
    archive)
      archive_family \
        "$family_id" "$expected_id" "$runtime_reference" \
        "$destination_tag" "$workload_csv"
      ;;
    mirror)
      mirror_family \
        "$family_id" "$expected_id" "$runtime_reference" \
        "$destination_tag" "$workload_csv"
      ;;
    all)
      archive_family \
        "$family_id" "$expected_id" "$runtime_reference" \
        "$destination_tag" "$workload_csv"
      mirror_family \
        "$family_id" "$expected_id" "$runtime_reference" \
        "$destination_tag" "$workload_csv"
      ;;
  esac
  processed=$((processed + 1))
done <"$ROWS_FILE"

[[ "$processed" -eq "$EXPECTED_LOCAL_FAMILIES" ]] ||
  fail "processed_image_family_count_mismatch"

if [[ "$MODE" != "status" ]]; then
  write_run_checksums
fi

printf 'MIDDLEWARE_LEGACY_BACKUP=PASS\n'
printf 'MODE=%s\n' "$MODE"
if [[ "$MODE" != "status" ]]; then
  printf 'EVIDENCE_ROOT=%s\n' "$RUN_ROOT"
fi
printf 'SERVER_A_RUNTIME_MUTATED=NO\n'
printf 'CONTAINERS_RESTARTED=0\n'
printf 'ENVIRONMENT_VALUES_CAPTURED=NO\n'
printf 'CODESTRA_BACKUP_RETAINED=true\n'
