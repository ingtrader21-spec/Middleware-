#!/usr/bin/env bash
# Collect source/deployment provenance for an unknown staging migration revision.
# This script never queries or mutates the database and never changes containers.
set -Eeuo pipefail

fail() {
  printf 'EVIDENCE_ERROR=%s\n' "$*" >&2
  exit 1
}

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATION_REVISION="${MIGRATION_REVISION:-0053_callback_worker_grants}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/codestra-migration-evidence-$(date -u +%Y%m%dT%H%M%SZ)}"
SEARCH_ROOTS="${SEARCH_ROOTS:-}"
DEEP_GIT_SEARCH="${DEEP_GIT_SEARCH:-0}"

[[ "$MIGRATION_REVISION" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "MIGRATION_REVISION contains unsupported characters"
[[ "$DEEP_GIT_SEARCH" == "0" || "$DEEP_GIT_SEARCH" == "1" ]] || fail "DEEP_GIT_SEARCH must be 0 or 1"

command -v docker >/dev/null 2>&1 || fail "docker is not installed or not in PATH"
docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

umask 077
mkdir -p "$OUTPUT_DIR"
: >"$OUTPUT_DIR/file-hits.tsv"
: >"$OUTPUT_DIR/git-history-hits.tsv"
: >"$OUTPUT_DIR/deep-git-hits.tsv"

exec > >(tee "$OUTPUT_DIR/report.txt") 2>&1

printf 'EVIDENCE_STARTED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'MIGRATION_REVISION=%s\n' "$MIGRATION_REVISION"
printf 'OUTPUT_DIR=%s\n' "$OUTPUT_DIR"
printf 'HOSTNAME=%s\n' "$(hostname 2>/dev/null || printf unknown)"
printf 'KERNEL=%s\n' "$(uname -sr 2>/dev/null || printf unknown)"

select_container() {
  local requested="${MIDDLEWARE_CONTAINER:-}"
  local candidate=""
  if [[ -n "$requested" ]]; then
    docker inspect "$requested" >/dev/null 2>&1 || fail "MIDDLEWARE_CONTAINER does not resolve: $requested"
    printf '%s\n' "$requested"
    return 0
  fi
  candidate="$(
    docker ps --format '{{.ID}}\t{{.Label "com.docker.compose.service"}}\t{{.Names}}\t{{.Image}}' |
      awk 'tolower($0) ~ /middleware/ && tolower($0) !~ /postgres|redis|database|backup/ {print $1; exit}'
  )"
  [[ -n "$candidate" ]] || fail "middleware container not found; set MIDDLEWARE_CONTAINER explicitly"
  printf '%s\n' "$candidate"
}

container="$(select_container)"
container_id="$(docker inspect "$container" --format '{{.Id}}')"
container_name="$(docker inspect "$container" --format '{{.Name}}')"
container_name="${container_name#/}"
configured_image="$(docker inspect "$container" --format '{{.Config.Image}}')"
image_id="$(docker inspect "$container" --format '{{.Image}}')"
compose_workdir="$(docker inspect "$container" --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}')"
compose_files="$(docker inspect "$container" --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}')"

printf '\nRUNTIME_DISCOVERY\n'
printf 'MIDDLEWARE_CONTAINER_ID=%s\n' "$container_id"
printf 'MIDDLEWARE_CONTAINER_NAME=%s\n' "$container_name"
printf 'MIDDLEWARE_CONFIGURED_IMAGE=%s\n' "$configured_image"
printf 'MIDDLEWARE_IMAGE_ID=%s\n' "$image_id"
printf 'COMPOSE_WORKING_DIR=%s\n' "${compose_workdir:-NOT_RECORDED}"
printf 'COMPOSE_CONFIG_FILES=%s\n' "${compose_files:-NOT_RECORDED}"

if [[ -x "$ROOT_DIR/scripts/discover_middleware_runtime.sh" ]]; then
  "$ROOT_DIR/scripts/discover_middleware_runtime.sh" >"$OUTPUT_DIR/runtime-discovery.txt" 2>&1 || true
  printf 'RUNTIME_DISCOVERY_FILE=%s\n' "$OUTPUT_DIR/runtime-discovery.txt"
fi

printf '\nIMAGE_PROVENANCE\n'
docker image inspect "$image_id" --format 'IMAGE_SOURCE={{index .Config.Labels "org.opencontainers.image.source"}}' 2>/dev/null || true
docker image inspect "$image_id" --format 'IMAGE_REVISION={{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true
docker image inspect "$image_id" --format 'IMAGE_VERSION={{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || true
docker image inspect "$image_id" --format 'IMAGE_CREATED_LABEL={{index .Config.Labels "org.opencontainers.image.created"}}' 2>/dev/null || true
docker image inspect "$image_id" --format 'IMAGE_CREATED={{.Created}}' 2>/dev/null || true
docker image inspect "$image_id" --format '{{range .RepoDigests}}IMAGE_REPO_DIGEST={{.}}{{println}}{{end}}' 2>/dev/null || true

printf '\nCOMPOSE_FILE_HASHES\n'
if [[ -n "$compose_workdir" && -n "$compose_files" ]]; then
  IFS=',' read -r -a configured_files <<<"$compose_files"
  for configured in "${configured_files[@]}"; do
    configured="${configured# }"
    [[ -n "$configured" ]] || continue
    if [[ "$configured" = /* ]]; then
      candidate="$configured"
    else
      candidate="$compose_workdir/$configured"
    fi
    if [[ -f "$candidate" ]]; then
      printf 'COMPOSE_FILE=%s\t' "$candidate"
      sha256sum "$candidate"
    else
      printf 'COMPOSE_FILE_MISSING=%s\n' "$candidate"
    fi
  done
else
  printf 'COMPOSE_FILE_HASHES=UNAVAILABLE\n'
fi

append_search_root() {
  local root="$1"
  [[ -n "$root" && -d "$root" ]] || return 0
  case ":${roots_joined}:" in
    *":${root}:"*) return 0 ;;
  esac
  roots+=("$root")
  roots_joined="${roots_joined:+$roots_joined:}$root"
}

roots=()
roots_joined=""
append_search_root "$compose_workdir"
if [[ -n "$SEARCH_ROOTS" ]]; then
  IFS=':' read -r -a extra_roots <<<"$SEARCH_ROOTS"
  for root in "${extra_roots[@]}"; do
    append_search_root "$root"
  done
fi

printf '\nSEARCH_ROOTS\n'
if ((${#roots[@]} == 0)); then
  printf 'SEARCH_ROOTS=NONE\n'
else
  printf '%s\n' "${roots[@]}"
fi

search_working_tree() {
  local root="$1"
  find "$root" -xdev -type f \
    \( -name '*.py' -o -name '*.sql' -o -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.toml' -o -name '*.txt' -o -name '*.md' \) \
    -not -path '*/.git/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/.venv/*' \
    -not -path '*/venv/*' \
    -not -path '*/data/*' \
    -print0 2>/dev/null |
    while IFS= read -r -d '' file; do
      if grep -IlF -- "$MIGRATION_REVISION" "$file" >/dev/null 2>&1; then
        digest="$(sha256sum "$file" | awk '{print $1}')"
        printf '%s\t%s\n' "$digest" "$file" | tee -a "$OUTPUT_DIR/file-hits.tsv"
      fi
    done
}

append_git_repository() {
  local repository="$1"
  [[ -n "$repository" && -d "$repository" ]] || return 0
  git -C "$repository" rev-parse --git-dir >/dev/null 2>&1 || return 0
  case ":${repositories_joined}:" in
    *":${repository}:"*) return 0 ;;
  esac
  repositories+=("$repository")
  repositories_joined="${repositories_joined:+$repositories_joined:}$repository"
}

discover_git_repositories() {
  local root="$1"
  local marker=""
  local repository=""
  append_git_repository "$root"
  while IFS= read -r -d '' marker; do
    repository="${marker%/.git}"
    append_git_repository "$repository"
  done < <(
    find "$root" -xdev \
      \( -path '*/node_modules' -o -path '*/.venv' -o -path '*/venv' -o -path '*/data' \) -prune -o \
      \( -type d -name .git -o -type f -name .git \) -print0 2>/dev/null
  )
}

repositories=()
repositories_joined=""
for root in "${roots[@]}"; do
  discover_git_repositories "$root"
done

printf '\nGIT_REPOSITORIES\n'
if ((${#repositories[@]} == 0)); then
  printf 'GIT_REPOSITORIES=NONE\n'
else
  printf '%s\n' "${repositories[@]}"
fi

search_git_history() {
  local root="$1"
  local matches=""
  local grep_status=0

  printf '\nGIT_REPOSITORY=%s\n' "$root"
  printf 'GIT_HEAD=%s\n' "$(git -C "$root" rev-parse HEAD 2>/dev/null || printf UNAVAILABLE)"
  printf 'GIT_BRANCH=%s\n' "$(git -C "$root" symbolic-ref --short -q HEAD 2>/dev/null || printf DETACHED_OR_UNAVAILABLE)"
  status_count="$(git -C "$root" status --porcelain=v1 --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')"
  printf 'GIT_TRACKED_WORKTREE_CHANGE_COUNT=%s\n' "$status_count"

  git -C "$root" log --all --fixed-strings -S"$MIGRATION_REVISION" \
    --format='%H%x09%cI%x09%s' -- . 2>/dev/null |
    while IFS= read -r row; do
      [[ -n "$row" ]] || continue
      printf '%s\t%s\n' "$root" "$row" | tee -a "$OUTPUT_DIR/git-history-hits.tsv"
    done

  if [[ "$DEEP_GIT_SEARCH" == "1" ]]; then
    while IFS= read -r commit; do
      [[ -n "$commit" ]] || continue
      if matches="$(
        git -C "$root" grep -IlF -- "$MIGRATION_REVISION" "$commit" -- \
          '*.py' '*.sql' '*.json' '*.yaml' '*.yml' '*.toml' '*.txt' '*.md' 2>/dev/null
      )"; then
        :
      else
        grep_status=$?
        if [[ "$grep_status" -ne 1 ]]; then
          fail "git grep failed for repository=$root commit=$commit status=$grep_status"
        fi
        matches=""
      fi
      if [[ -n "$matches" ]]; then
        while IFS= read -r object_path; do
          [[ -n "$object_path" ]] || continue
          printf '%s\t%s\t%s\n' "$root" "$commit" "$object_path" | tee -a "$OUTPUT_DIR/deep-git-hits.tsv"
        done <<<"$matches"
      fi
    done < <(git -C "$root" rev-list --all 2>/dev/null)
  fi
}

printf '\nWORKING_TREE_REVISION_HITS\n'
for root in "${roots[@]}"; do
  search_working_tree "$root"
done

printf '\nGIT_HISTORY_REVISION_HITS\n'
for repository in "${repositories[@]}"; do
  search_git_history "$repository"
done

file_hits="$(wc -l <"$OUTPUT_DIR/file-hits.tsv" | tr -d ' ')"
git_hits="$(wc -l <"$OUTPUT_DIR/git-history-hits.tsv" | tr -d ' ')"
deep_hits="$(wc -l <"$OUTPUT_DIR/deep-git-hits.tsv" | tr -d ' ')"

if ((file_hits > 0 || git_hits > 0 || deep_hits > 0)); then
  recovery_state="CANDIDATE_SOURCE_FOUND"
else
  recovery_state="NOT_FOUND_IN_APPROVED_SEARCH_ROOTS"
fi

cat >"$OUTPUT_DIR/summary.env" <<EOF
MIGRATION_REVISION=$MIGRATION_REVISION
FILE_HITS=$file_hits
GIT_HISTORY_HITS=$git_hits
DEEP_GIT_HITS=$deep_hits
RECOVERY_STATE=$recovery_state
DATABASE_QUERIES=NO
CONTAINERS_CHANGED=NO
CONTAINER_FILES_CHANGED=NO
NETWORK_CHANGED=NO
EOF

printf '\nEVIDENCE_SUMMARY\n'
printf 'FILE_HITS=%s\n' "$file_hits"
printf 'GIT_HISTORY_HITS=%s\n' "$git_hits"
printf 'DEEP_GIT_HITS=%s\n' "$deep_hits"
printf 'RECOVERY_STATE=%s\n' "$recovery_state"
printf 'SUMMARY_FILE=%s\n' "$OUTPUT_DIR/summary.env"
printf 'DATABASE_QUERIES=NO\n'
printf 'CONTAINERS_CHANGED=NO\n'
printf 'CONTAINER_FILES_CHANGED=NO\n'
printf 'EVIDENCE_OUTPUT_ONLY=YES\n'
printf 'EVIDENCE_COMPLETED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
