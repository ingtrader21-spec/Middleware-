#!/usr/bin/env bash
# Read-only discovery for the Docker-based Codestra middleware runtime.
set -Eeuo pipefail

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "docker is not installed or not in PATH"
docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"

select_container() {
  local requested="${MIDDLEWARE_CONTAINER:-}"
  local candidate=""

  if [[ -n "$requested" ]]; then
    docker inspect "$requested" >/dev/null 2>&1 || \
      fail "MIDDLEWARE_CONTAINER does not resolve: $requested"
    [[ "$(docker inspect "$requested" --format '{{.State.Running}}')" == "true" ]] || \
      fail "requested middleware container is not running: $requested"
    printf '%s\n' "$requested"
    return 0
  fi

  candidate="$(
    docker ps --format '{{.ID}}\t{{.Label "com.docker.compose.service"}}' |
      awk 'tolower($2) ~ /middleware/ {print $1; exit}'
  )"

  if [[ -z "$candidate" ]]; then
    candidate="$(
      docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}' |
        awk '
          tolower($0) ~ /middleware/ &&
          tolower($0) !~ /postgres|redis|database|backup/ {
            print $1
            exit
          }
        '
    )"
  fi

  [[ -n "$candidate" ]] || \
    fail "running middleware container was not found; set MIDDLEWARE_CONTAINER explicitly"
  printf '%s\n' "$candidate"
}

middleware_container="$(select_container)"
middleware_container_id="$(docker inspect "$middleware_container" --format '{{.Id}}')"
container_name="$(docker inspect "$middleware_container" --format '{{.Name}}')"
container_name="${container_name#/}"
container_image="$(docker inspect "$middleware_container" --format '{{.Config.Image}}')"

printf 'MIDDLEWARE_CONTAINER_ID=%s\n' "$middleware_container_id"
printf 'MIDDLEWARE_CONTAINER_NAME=%s\n' "$container_name"
printf 'MIDDLEWARE_IMAGE=%s\n' "$container_image"
docker inspect "$middleware_container" --format 'MIDDLEWARE_IMAGE_ID={{.Image}}'
docker inspect "$middleware_container" --format 'CONTAINER_USER={{if .Config.User}}{{.Config.User}}{{else}}DEFAULT_IMAGE_USER{{end}}'
docker inspect "$middleware_container" --format 'CONTAINER_STATUS={{.State.Status}}'
docker inspect "$middleware_container" --format 'CONTAINER_STARTED_AT={{.State.StartedAt}}'
docker inspect "$middleware_container" --format 'CONTAINER_RESTART_COUNT={{.RestartCount}}'
docker inspect "$middleware_container" --format 'CONTAINER_HEALTH={{if .State.Health}}{{.State.Health.Status}}{{else}}NO_HEALTHCHECK{{end}}'
docker inspect "$middleware_container" --format 'PRIVILEGED={{.HostConfig.Privileged}}'
docker inspect "$middleware_container" --format 'READONLY_ROOTFS={{.HostConfig.ReadonlyRootfs}}'

printf '\nCOMPOSE_METADATA\n'
docker inspect "$middleware_container" --format 'COMPOSE_PROJECT={{index .Config.Labels "com.docker.compose.project"}}'
docker inspect "$middleware_container" --format 'COMPOSE_SERVICE={{index .Config.Labels "com.docker.compose.service"}}'
docker inspect "$middleware_container" --format 'COMPOSE_WORKING_DIR={{index .Config.Labels "com.docker.compose.project.working_dir"}}'
docker inspect "$middleware_container" --format 'COMPOSE_CONFIG_FILES={{index .Config.Labels "com.docker.compose.project.config_files"}}'

printf '\nIMAGE_DIGESTS\n'
docker image inspect "$container_image" --format \
  '{{if .RepoDigests}}{{range .RepoDigests}}{{println .}}{{end}}{{else}}NO_REPOSITORY_DIGEST_RECORDED{{end}}' \
  2>/dev/null || printf 'IMAGE_NOT_AVAILABLE_BY_CONFIGURED_NAME\n'

printf '\nMOUNTS\n'
docker inspect "$middleware_container" --format \
  '{{range .Mounts}}{{printf "%s\t%s -> %s\tRW=%t\n" .Type .Source .Destination .RW}}{{end}}'

printf '\nPUBLISHED_PORTS\n'
docker port "$middleware_container" 2>/dev/null || printf 'NO_PUBLISHED_PORTS\n'

printf '\nNETWORKS\n'
docker inspect "$middleware_container" --format \
  '{{range $name, $network := .NetworkSettings.Networks}}{{printf "%s\tIP=%s\tGateway=%s\n" $name $network.IPAddress $network.Gateway}}{{end}}'

printf '\nSAFE_RUNTIME_CONTROLS\n'
safe_controls="$(
  docker inspect "$middleware_container" --format '{{range .Config.Env}}{{println .}}{{end}}' |
    awk -F= '
      $1 ~ /^(APP_ENV|ENVIRONMENT|LOG_LEVEL|LIVE_ADVERTISING_ENABLED|EXTERNAL_DELIVERY_ENABLED|SOCIAL_PUBLISHING_ENABLED|EXTERNAL_MODEL_CALLS_ENABLED|N8N_EXTERNAL_PROVIDER_WRITES|SEND_EVENTS|ENABLE_EXTERNAL_DELIVERY|LIVE_WRITE|LIVE_WRITES|ODOO_WRITE|CALLBACK_DISPATCH|N8N_DELIVERY_ENABLED|VICIDIAL_WRITES_ENABLED|EXTERNAL_DIAL_ENABLED|PRODUCTION_CALLBACKS_ENABLED|N8N_PRODUCTION_WORKFLOWS_ENABLED|PRODUCTION_DIALING)$/ {
        print
      }
    ' | sort
)"
if [[ -n "$safe_controls" ]]; then
  printf '%s\n' "$safe_controls"
else
  printf 'NO_ALLOWLISTED_SAFETY_CONTROLS_FOUND\n'
fi

printf '\nCOMPOSE_PROJECTS\n'
docker compose ls 2>/dev/null || true

printf '\nRELATED_RUNNING_CONTAINERS\n'
docker ps --format 'table {{.Names}}\t{{.Label "com.docker.compose.service"}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' |
  awk '
    NR == 1 ||
    tolower($0) ~ /middleware|callback|worker|redis|postgres|n8n|odoo|keycloak|kong|caddy/
  '

printf '\nDISCOVERY_GUARANTEES\n'
printf '%s\n' \
  'READ_ONLY_DISCOVERY=PASS' \
  'CONTAINER_ENVIRONMENT_FULL_DUMP=NOT_PRINTED' \
  'DATABASE_PASSWORDS=NOT_READ' \
  'CONTAINERS_CHANGED=NO' \
  'FILES_CHANGED=NO' \
  'NETWORK_CHANGED=NO'
