#!/usr/bin/env bash
# Turns on WebDAV and the files portal on an existing smb-share-manager install, without
# editing your docker-compose.yml. Run it on the server, in the compose project folder
# (where docker-compose.yml and .env are):
#
#   scripts/remote-access.sh setup                         interactive; safe to run again
#   scripts/remote-access.sh verify https://files.example.org
#                                                          spoof test, then switch the portal on
#   scripts/remote-access.sh doctor                        why requests are being refused
#   scripts/remote-access.sh status
#
# What setup changes, and nothing else:
#   - .env: backed up to .env.bak-<time>, then COMPOSE_FILE, COMPOSE_PROFILES and the DAV_*
#     and PORTAL_* settings are set (existing values are offered as defaults).
#   - compose.remote.yml (new): the smb-dav and smb-portal services, the bridge volume and
#     one line per exposed share folder. COMPOSE_FILE in .env makes `docker compose` read it
#     after docker-compose.yml, so `docker compose pull && docker compose up -d` keep working.
#   - through the admin API: Remote access and the sign-in e-mail for the users you pick.
#
# Non-interactive use (CI): set RA_YES=1 and answer with RA_SHARES, RA_PORTAL_HOST,
# RA_DAV_HOST, RA_PROXIES, RA_USERS ("name=email,name2=email2"; email may be empty).
# RA_NO_PULL=1 skips `docker compose pull` (CI tests a locally built image).
set -euo pipefail

DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAW="https://raw.githubusercontent.com/codemastervy/smb-share-manager/main/scripts"
MAIN=smb-share-manager
REMOTE_FILE=compose.remote.yml

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1 || sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    die "docker is not usable by this user (and sudo docker failed)"
  fi
fi
compose() { "${DOCKER[@]}" compose --project-directory "$DIR" "$@"; }

[[ -f "$DIR/docker-compose.yml" ]] || die "run this in the folder that holds docker-compose.yml"
[[ -f "$DIR/.env" ]] || die "no .env in $DIR"

# --- .env helpers -----------------------------------------------------------------------

env_get() { # env_get KEY -> value of the last KEY= line, or nothing
  awk -v k="$1" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' \
    "$DIR/.env"
}

env_set() { # env_set KEY VALUE: replace every KEY= line, or append one
  local tmp
  tmp="$(mktemp "$DIR/.env.XXXXXX")"
  K="$1" V="$2" awk '
    BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
    index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 }; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$DIR/.env" >"$tmp"
  chmod --reference="$DIR/.env" "$tmp" 2>/dev/null || chmod 600 "$tmp"
  mv "$tmp" "$DIR/.env"
}

backup_env() {
  local b
  b="$DIR/.env.bak-$(date +%Y%m%d-%H%M%S)"
  cp -p "$DIR/.env" "$b"
  say "backed up .env to $b"
}

ask() { # ask VAR "question" "default"
  local __var="$1" q="$2" def="${3:-}" ans
  if [[ "${RA_YES:-}" == 1 ]]; then
    printf -v "$__var" '%s' "$def"
    return
  fi
  if [[ -n "$def" ]]; then read -r -p "$q [$def]: " ans; else read -r -p "$q: " ans; fi
  printf -v "$__var" '%s' "${ans:-$def}"
}

# --- containers -------------------------------------------------------------------------

health() {
  "${DOCKER[@]}" inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null || true
}

wait_healthy() { # wait_healthy NAME [seconds]
  local name="$1" t="${2:-180}" s=""
  for ((i = 0; i < t / 3; i++)); do
    s="$(health "$name")"
    [[ "$s" == "running healthy" ]] && { say "  $name: healthy"; return 0; }
    sleep 3
  done
  say "  $name: '$s' after ${t}s; last log lines:"
  "${DOCKER[@]}" logs --tail 30 "$name" 2>&1 | sed 's/^/    /'
  return 1
}

pyexec() { # run Python inside the main container (the host may not have it)
  "${DOCKER[@]}" exec -i "$MAIN" /opt/venv/bin/python -c "$1"
}

# --- compose.remote.yml -----------------------------------------------------------------

base_has() { grep -Eq "^  $1:" "$DIR/docker-compose.yml"; }

# Kept identical to the smb-dav and smb-portal services in docker-compose.yml
# (tests/unit/test_compose.py checks it).
services_yaml() {
  cat <<'YAML'
# BEGIN SERVICES
  smb-dav:
    image: ghcr.io/codemastervy/smb-share-manager:latest
    container_name: smb-dav
    profiles: [dav]
    restart: unless-stopped
    depends_on:
      smb-share-manager:
        condition: service_healthy
    entrypoint: ["/usr/bin/tini", "--"]
    command: ["/opt/venv/bin/python", "-m", "ssm.dav.main"]
    user: "${DAV_UID:-2999}:3000"
    environment:
      DAV_EXPOSED_SHARES: ${DAV_EXPOSED_SHARES:-}
      VOLUMES: ${VOLUMES:-}
      TRUSTED_PROXIES: ${DAV_TRUSTED_PROXIES:-${TRUSTED_PROXIES:-}}
      DAV_REAL_IP_HEADER: ${DAV_REAL_IP_HEADER:-x-forwarded-for}
      DAV_MAX_UPLOAD_MB: ${DAV_MAX_UPLOAD_MB:-${MAX_UPLOAD_MB:-4096}}
      DAV_AUTH_CACHE_S: ${DAV_AUTH_CACHE_S:-300}
      DAV_BIND_ADDR: ${DAV_BIND_ADDR:-0.0.0.0}
      DAV_ALLOW_HTTP: ${DAV_ALLOW_HTTP:-false}
      NTFY_URL: ${NTFY_URL:-}
      NTFY_TOKEN: ${NTFY_TOKEN:-}
      PUID: ${PUID:-1000}
      TZ: ${TZ:-UTC}
    ports:
      - "${DAV_BIND_ADDR:-0.0.0.0}:${DAV_PORT:-8094}:8094"
    volumes:
      - dav-bridge:/run/ssm-dav:ro
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:mode=1777,size=16m
    healthcheck:
      test: ["CMD", "/opt/venv/bin/python", "/usr/local/bin/healthcheck.py", "--dav"]
      interval: 30s
      timeout: 5s
      start_period: 20s
      retries: 3
    stop_grace_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
  smb-portal:
    image: ghcr.io/codemastervy/smb-share-manager:latest
    container_name: smb-portal
    profiles: [portal]
    restart: unless-stopped
    depends_on:
      smb-share-manager:
        condition: service_healthy
    entrypoint: ["/usr/bin/tini", "--"]
    command: ["/opt/venv/bin/python", "-m", "ssm.portal.main"]
    user: "${PORTAL_UID:-2998}:3000"
    environment:
      PORTAL_HOSTS: ${PORTAL_HOSTS:-}
      PORTAL_EXPOSED_SHARES: ${PORTAL_EXPOSED_SHARES:-${DAV_EXPOSED_SHARES:-}}
      PORTAL_TRUSTED_PROXIES: ${PORTAL_TRUSTED_PROXIES:-${DAV_TRUSTED_PROXIES:-${TRUSTED_PROXIES:-}}}
      PORTAL_PROXY_SECRET: ${PORTAL_PROXY_SECRET:-}
      PORTAL_IDENTITY_HEADER: ${PORTAL_IDENTITY_HEADER:-remote-email}
      PORTAL_HEADER_VERIFIED: ${PORTAL_HEADER_VERIFIED:-false}
      PORTAL_MAX_UPLOAD_MB: ${PORTAL_MAX_UPLOAD_MB:-${DAV_MAX_UPLOAD_MB:-${MAX_UPLOAD_MB:-4096}}}
      VOLUMES: ${VOLUMES:-}
      PUID: ${PUID:-1000}
      DAV_UID: ${DAV_UID:-2999}
      TZ: ${TZ:-UTC}
    ports:
      - "${PORTAL_BIND_ADDR:-0.0.0.0}:${PORTAL_PORT:-8096}:8096"
    volumes:
      - dav-bridge:/run/ssm-dav:ro
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:mode=1777,size=16m
    healthcheck:
      test: ["CMD", "/opt/venv/bin/python", "/usr/local/bin/healthcheck.py", "--portal"]
      interval: 30s
      timeout: 5s
      start_period: 20s
      retries: 3
    stop_grace_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
# END SERVICES
YAML
}

write_remote_file() { # write_remote_file "host:container lines, one per line"
  local mounts="$1" tmp
  tmp="$(mktemp "$DIR/$REMOTE_FILE.XXXXXX")"
  {
    say "# Written by scripts/remote-access.sh: WebDAV and the files portal."
    say "# Read after docker-compose.yml (COMPOSE_FILE in .env). Re-run the script to change it."
    say "services:"
    if base_has smb-dav; then
      # docker-compose.yml already defines the services: only add the share folders.
      for svc in smb-dav smb-portal; do
        say "  $svc:"
        say "    volumes:"
        say "      - __SHARES__"
      done
    else
      say "  $MAIN:"
      say "    volumes:"
      say "      - dav-bridge:/run/ssm-dav"
      services_yaml | grep -v '^# \(BEGIN\|END\) SERVICES$' |
        awk '{ print } $0 == "      - dav-bridge:/run/ssm-dav:ro" { print "      - __SHARES__" }'
      say "volumes:"
      say "  dav-bridge:"
    fi
  } >"$tmp"
  # Replace each __SHARES__ line with one line per share folder (or nothing).
  MOUNTS="$mounts" awk '
    BEGIN { n = split(ENVIRON["MOUNTS"], m, "\n") }
    $0 == "      - __SHARES__" {
      for (i = 1; i <= n; i++) if (m[i] != "") print "      - \"" m[i] "\""
      next
    }
    { print }
  ' "$tmp" >"$tmp.2"
  mv "$tmp.2" "$DIR/$REMOTE_FILE"
  rm -f "$tmp"
  # A service whose only "volumes:" entries were share lines must not end up empty.
  if base_has smb-dav && [[ -z "$mounts" ]]; then
    printf 'services: {}\n' >"$DIR/$REMOTE_FILE"
  fi
  local files="docker-compose.yml"
  [[ -f "$DIR/docker-compose.override.yml" ]] && files="$files:docker-compose.override.yml"
  env_set COMPOSE_FILE "$files:$REMOTE_FILE"
  compose config -q || die "docker compose rejects the generated $REMOTE_FILE"
}

# --- admin API --------------------------------------------------------------------------

admin_url() {
  local bind port
  bind="$(env_get BIND_ADDR)"
  port="$(env_get WEB_PORT)"
  [[ -z "$bind" || "$bind" == 0.0.0.0 ]] && bind=127.0.0.1
  printf 'http://%s:%s' "$bind" "${port:-8095}"
}

ADMIN_JAR=""
ADMIN_CSRF=""
admin_login() {
  local url pw pre esc
  url="$(admin_url)"
  ADMIN_JAR="$(mktemp)"
  pw="$(env_get ADMIN_PASSWORD)"
  if [[ -z "$pw" ]]; then
    [[ "${RA_YES:-}" == 1 ]] && die "ADMIN_PASSWORD is not in .env"
    read -r -s -p "Admin password for the web UI: " pw
    echo
  fi
  pre="$(curl -fsS -c "$ADMIN_JAR" -b "$ADMIN_JAR" "$url/api/auth/status" |
    sed -n 's/.*"csrf": *"\([^"]*\)".*/\1/p')"
  esc=${pw//\\/\\\\}
  esc=${esc//\"/\\\"}
  # The password goes to curl on stdin, never on the command line.
  ADMIN_CSRF="$(printf '{"password": "%s"}' "$esc" |
    curl -fsS -c "$ADMIN_JAR" -b "$ADMIN_JAR" -H "Origin: $url" -H "X-CSRF-Token: $pre" \
      -H 'Content-Type: application/json' --data-binary @- "$url/api/auth/login" |
    sed -n 's/.*"csrf": *"\([^"]*\)".*/\1/p')"
  [[ -n "$ADMIN_CSRF" ]] || die "could not sign in to the admin API at $url"
}

admin_patch_user() { # admin_patch_user NAME JSON
  local url
  url="$(admin_url)"
  curl -fsS -o /dev/null -c "$ADMIN_JAR" -b "$ADMIN_JAR" -X PATCH -H "Origin: $url" \
    -H "X-CSRF-Token: $ADMIN_CSRF" -H 'Content-Type: application/json' \
    --data-binary "$2" "$url/api/users/$1"
}

# --- reading users, shares and mounts -----------------------------------------------------

snapshot_tsv() { # lines: "share<TAB>name<TAB>path" and "user<TAB>name<TAB>remote<TAB>email"
  pyexec '
import json
d = json.load(open("/run/ssm-dav/acl.json"))
for s in d["shares"]:
    print("share", s["name"], s["path"], sep="\t")
for n, u in sorted(d["users"].items()):
    print("user", n, "yes" if u.get("remote") else "no", u.get("email", ""), sep="\t")
'
}

host_path_for() { # host_path_for CONTAINER_PATH -> host path, from the main container mounts
  local cpath="$1"
  "${DOCKER[@]}" inspect -f '{{range .Mounts}}{{.Destination}}|{{.Source}}{{println}}{{end}}' "$MAIN" |
    awk -F'|' -v p="$cpath" '
      $1 != "" && (p == $1 || index(p, $1 "/") == 1) && length($1) > best {
        best = length($1); out = $2 substr(p, length($1) + 1)
      }
      END { if (best) print out }'
}

detect_proxies() { # subnets of the networks the traefik container is on
  local c
  c="$("${DOCKER[@]}" ps --format '{{.Names}}' | grep -Ex 'traefik|pangolin-traefik|.*traefik.*' | head -1 || true)"
  [[ -z "$c" ]] && return 0
  "${DOCKER[@]}" inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c" |
    tr ' ' '\n' | grep -v '^$' | while read -r net; do
      "${DOCKER[@]}" network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net"
    done | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9.]+/[0-9]+$' | paste -sd, -
}

# --- commands ---------------------------------------------------------------------------

cmd_setup() {
  step "1/7 Back up .env and update the image"
  backup_env
  if [[ -n "$(env_get COMPOSE_FILE)" && "$(env_get COMPOSE_FILE)" != *"$REMOTE_FILE"* ]]; then
    die "COMPOSE_FILE is already set in .env to something else; add $REMOTE_FILE to it by hand"
  fi
  write_remote_file ""
  [[ "${RA_NO_PULL:-}" == 1 ]] || compose pull -q
  compose up -d
  wait_healthy "$MAIN" || die "$MAIN is not healthy"
  for _ in $(seq 1 20); do
    "${DOCKER[@]}" exec "$MAIN" test -s /run/ssm-dav/acl.json && break
    sleep 1
  done
  "${DOCKER[@]}" exec "$MAIN" test -s /run/ssm-dav/acl.json ||
    die "the running image doesn't write /run/ssm-dav/acl.json: is the WebDAV release merged and published?"

  step "2/7 Shares to offer from outside"
  local tsv volumes
  tsv="$(snapshot_tsv)"
  volumes=",$(env_get VOLUMES),"
  say "Shares (a share that is a whole volume can't be offered):"
  awk -F'\t' '$1 == "share" { print "  " $2 "  (" $3 ")" }' <<<"$tsv"
  local cur shares
  cur="$(env_get DAV_EXPOSED_SHARES)"
  ask shares "Share names to offer, comma-separated" "${RA_SHARES:-$cur}"
  shares="$(tr -d ' ' <<<"$shares")"
  [[ -n "$shares" ]] || die "no shares chosen"
  local mounts="" name path host
  IFS=',' read -r -a picked <<<"$shares"
  for name in "${picked[@]}"; do
    path="$(awk -F'\t' -v n="$name" '$1 == "share" && tolower($2) == tolower(n) { print $3 }' <<<"$tsv")"
    [[ -n "$path" ]] || die "there is no share called $name"
    [[ "$volumes" == *",$path,"* ]] && die "$name is a whole volume ($path); share a folder inside it instead"
    host="$(host_path_for "$path")"
    [[ -n "$host" ]] || die "can't find where $path comes from on the host"
    say "  $name: $host -> $path"
    mounts+="$host:$path"$'\n'
  done

  step "3/7 Addresses"
  local dav_host portal_host proxies
  ask dav_host "WebDAV host name (for the instructions)" "${RA_DAV_HOST:-}"
  ask portal_host "Files portal host name, e.g. files.example.org" "${RA_PORTAL_HOST:-$(env_get PORTAL_HOSTS)}"
  [[ "$portal_host" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "not a host name: $portal_host"
  local detected
  detected="$(detect_proxies || true)"
  local def_proxies="${RA_PROXIES:-$(env_get DAV_TRUSTED_PROXIES)}"
  [[ -z "$def_proxies" ]] && def_proxies="$detected"
  ask proxies "Trusted proxy addresses/networks (Traefik)" "$def_proxies"
  [[ -n "$proxies" ]] || die "no trusted proxy given and no traefik container found"
  say "  trusted proxies: $proxies"

  step "4/7 Write .env and $REMOTE_FILE"
  local secret
  secret="$(env_get PORTAL_PROXY_SECRET)"
  if [[ ${#secret} -lt 32 ]]; then
    secret="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  env_set COMPOSE_PROFILES dav,portal
  env_set DAV_EXPOSED_SHARES "$shares"
  env_set DAV_TRUSTED_PROXIES "$proxies"
  env_set PORTAL_HOSTS "$(tr '[:upper:]' '[:lower:]' <<<"$portal_host")"
  env_set PORTAL_TRUSTED_PROXIES "$proxies"
  env_set PORTAL_PROXY_SECRET "$secret"
  [[ "$(env_get PORTAL_HEADER_VERIFIED)" == true ]] || env_set PORTAL_HEADER_VERIFIED false
  write_remote_file "$mounts"
  say "  done"

  step "5/7 Who may get in"
  admin_login
  local users answer email
  users="$(awk -F'\t' '$1 == "user" { print $2 "\t" $3 "\t" $4 }' <<<"$tsv")"
  if [[ "${RA_YES:-}" == 1 ]]; then
    IFS=',' read -r -a pairs <<<"${RA_USERS:-}"
    for pair in "${pairs[@]}"; do
      [[ -z "$pair" ]] && continue
      name="${pair%%=*}"
      email="${pair#*=}"
      admin_patch_user "$name" "{\"remote_access\": true, \"email\": \"$email\"}" ||
        die "could not update $name"
      say "  $name: remote access on${email:+, e-mail $email}"
    done
  else
    say "For each user: remote access (WebDAV + portal), and the e-mail they sign in to Pangolin with."
    say "Give remote users a password of 16+ random characters."
    while IFS=$'\t' read -r -u 4 name remote email; do
      [[ -z "$name" ]] && continue
      ask answer "  $name: allow from outside? (y/n)" "$([[ $remote == yes ]] && echo y || echo n)"
      if [[ "$answer" =~ ^[Yy] ]]; then
        ask email "  $name: sign-in e-mail (empty = WebDAV only)" "$email"
        [[ "$email" =~ ^[^\"\\[:space:]]*$ ]] || die "bad e-mail"
        admin_patch_user "$name" "{\"remote_access\": true, \"email\": \"$email\"}" ||
          die "could not update $name (e-mail already used by someone else?)"
      elif [[ $remote == yes ]]; then
        admin_patch_user "$name" '{"remote_access": false}' || die "could not update $name"
      fi
    done 4<<<"$users"
  fi

  step "6/7 Start WebDAV and the portal"
  compose up -d
  local ok=1
  wait_healthy smb-dav || ok=0
  wait_healthy smb-portal || ok=0
  [[ $ok == 1 ]] || die "a service did not become healthy (see above; 'scripts/remote-access.sh doctor' helps)"

  step "7/7 Smoke test"
  if [[ -x "$SCRIPT_DIR/smoke-test.sh" ]]; then
    (cd "$DIR" && SMB_USER="" "$SCRIPT_DIR/smoke-test.sh") || say "(the smoke test reported problems; see above)"
  else
    say "  skipped (scripts/smoke-test.sh not found next to this script)"
  fi

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat <<EOF

==============================================================================
Server side is done. Now in Pangolin (two resources):

  ${dav_host:-dav.<your domain>}
    target:          http://${ip:-<server LAN IP>}:$(env_get DAV_PORT | sed 's/^$/8094/')
    authentication:  OFF (WebDAV clients log in with their SMB username/password)

  $portal_host
    target:          http://${ip:-<server LAN IP>}:$(env_get PORTAL_PORT | sed 's/^$/8096/')
    authentication:  ON (SSO)
    custom header:   X-Portal-Proxy-Secret: $secret

The portal is in setup mode (no files) until you run, from any computer, after
signing in at https://$portal_host in a browser:

  scripts/remote-access.sh verify https://$portal_host

(on the server; it asks for the browser's Cookie header).
==============================================================================
EOF
}

cmd_verify() {
  local url="${1:-}"
  [[ "$url" =~ ^https:// ]] || die "usage: $0 verify https://files.example.org"
  local test="$SCRIPT_DIR/portal-spoof-test.sh"
  if [[ ! -f "$test" ]]; then
    test="$(mktemp)"
    curl -fsSL "$RAW/portal-spoof-test.sh" -o "$test" || die "could not download portal-spoof-test.sh"
  fi
  if bash "$test" "$url"; then
    backup_env
    env_set PORTAL_HEADER_VERIFIED true
    compose up -d smb-portal
    wait_healthy smb-portal
    say "The files portal is live at $url"
  else
    say "Not switched on. Fix what the test reports and run verify again."
    exit 1
  fi
}

cmd_doctor() {
  for c in "$MAIN" smb-dav smb-portal; do say "$c: $(health "$c")"; done
  step "Recent refusals (portal)"
  "${DOCKER[@]}" logs --since 24h smb-portal 2>&1 | grep -E '"portal_(refused|startup)"' | tail -15 || true
  step "Recent WebDAV logins"
  "${DOCKER[@]}" logs --since 24h smb-dav 2>&1 | grep -E '"dav_(auth|startup|share_refused)"' | tail -15 || true
  cat <<'EOF'

Reading it:
  reason untrusted_peer  the proxy connects from an address not in PORTAL_TRUSTED_PROXIES:
                         add the "peer" shown (or its network) and run setup again
  reason proxy_secret    Pangolin's X-Portal-Proxy-Secret header is missing or different
                         from PORTAL_PROXY_SECRET in .env
  reason not_linked      that e-mail isn't set on any user (admin UI, Users)
  reason not_remote      the user's Remote access is off
  dav "HTTPS required"   WebDAV request not from a trusted proxy (DAV_TRUSTED_PROXIES)
EOF
}

cmd_status() {
  for c in "$MAIN" smb-dav smb-portal; do say "$c: $(health "$c")"; done
  say "COMPOSE_PROFILES=$(env_get COMPOSE_PROFILES)"
  say "DAV_EXPOSED_SHARES=$(env_get DAV_EXPOSED_SHARES)"
  say "PORTAL_HOSTS=$(env_get PORTAL_HOSTS)"
  say "PORTAL_HEADER_VERIFIED=$(env_get PORTAL_HEADER_VERIFIED)"
}

case "${1:-}" in
  setup) cmd_setup ;;
  verify) shift; cmd_verify "$@" ;;
  doctor) cmd_doctor ;;
  status) cmd_status ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
