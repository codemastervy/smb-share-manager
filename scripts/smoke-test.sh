#!/bin/bash
# Post-update smoke test for smb-share-manager. Run it on the server after an update:
#
#   SMB_SHARE=Files SMB_USER=isherveer ./scripts/smoke-test.sh
#
# It asks for the SMB password if SMB_PASSWORD is not set. Prints OK, WARN or FAIL for each
# check and exits non-zero if anything failed.
#
# Settings (environment variables):
#   CONTAINER   container name (default smb-share-manager)
#   WEB_URL     web UI URL (default http://127.0.0.1:${WEB_PORT:-8095})
#   SMB_SHARE   share to test (required for the SMB check)
#   SMB_USER    SMB user that is a member of SMB_SHARE
#   SMB_PASSWORD
#   MAX_AGE_DAYS  warn if the image is older than this (default 14)
#
# WebDAV checks (only when the smb-dav container exists):
#   DAV_CONTAINER  default smb-dav
#   DAV_LOCAL_URL  the published port (default http://127.0.0.1:${DAV_PORT:-8094}); plain
#                  HTTP from here must be refused before any password is read
#   DAV_URL        optional, e.g. https://dav.example.org: log in as SMB_USER (who needs
#                  "Remote access") and check that DAV_SHARE is listed
#   DAV_SHARE      share expected in the WebDAV listing (default SMB_SHARE)

set -u
CONTAINER="${CONTAINER:-smb-share-manager}"
WEB_URL="${WEB_URL:-http://127.0.0.1:${WEB_PORT:-8095}}"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-14}"
failed=0

ok()   { printf 'OK    %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=1; }

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then DOCKER=(sudo docker); fi

# 1. Container running and healthy.
state=$("${DOCKER[@]}" inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CONTAINER" 2>/dev/null)
case "$state" in
  "running healthy") ok "container $CONTAINER is running and healthy" ;;
  running*) fail "container $CONTAINER is running but health is '${state#running }'" ;;
  "") fail "container $CONTAINER not found" ;;
  *) fail "container $CONTAINER is $state" ;;
esac

# 2. Which image is running (a failed monthly pull is silent: check the date here).
image=$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)
[[ -n "$image" ]] && ok "image $image"

# 3. Web UI health endpoint, version and build date.
health=$(curl -fsS --max-time 5 "$WEB_URL/healthz" 2>/dev/null)
if [[ "$health" == *'"status":"ok"'* ]]; then
  version=$(sed -E 's/.*"version":"([^"]*)".*/\1/' <<<"$health")
  built=$(sed -E 's/.*"build_date":"([^"]*)".*/\1/' <<<"$health")
  ok "web UI healthy at $WEB_URL (version $version, built $built)"
  if built_s=$(date -d "$built" +%s 2>/dev/null); then
    age=$(( ( $(date +%s) - built_s ) / 86400 ))
    if (( age > MAX_AGE_DAYS )); then
      warn "image is $age days old: the weekly rebuild or the monthly pull may have stopped (see docs/UPDATING.md)"
    else
      ok "image is $age days old"
    fi
  else
    warn "could not read the build date '$built'"
  fi
else
  fail "web UI health check at $WEB_URL/healthz"
fi

# 4. Security headers present.
headers=$(curl -fsSI --max-time 5 "$WEB_URL/" 2>/dev/null | tr -d "\r")
if grep -qi "^content-security-policy: default-src 'self'" <<<"$headers" \
   && grep -qi '^x-content-type-options: nosniff' <<<"$headers"; then
  ok "security headers present"
else
  fail "security headers missing on the web UI"
fi

# 5. Samba configuration is valid.
if "${DOCKER[@]}" exec "$CONTAINER" testparm -s --suppress-prompt /etc/samba/smb.conf >/dev/null 2>&1; then
  ok "Samba configuration valid (testparm)"
else
  fail "testparm reports an invalid Samba configuration"
fi

# 6. Anonymous access refused.
anon=$("${DOCKER[@]}" exec "$CONTAINER" smbclient -L //127.0.0.1 -N -m SMB3 2>&1)
if [[ $? -ne 0 || "$anon" == *NT_STATUS_ACCESS_DENIED* || "$anon" == *NT_STATUS_LOGON_FAILURE* ]]; then
  ok "anonymous access refused"
else
  fail "anonymous login was accepted"
fi

# 7. A real SMB login and directory listing on one share (against localhost in the container).
if [[ -n "${SMB_SHARE:-}" && -n "${SMB_USER:-}" ]]; then
  if [[ -z "${SMB_PASSWORD:-}" ]]; then
    read -r -s -p "SMB password for $SMB_USER: " SMB_PASSWORD; echo
  fi
  if out=$("${DOCKER[@]}" exec -e PASSWD="$SMB_PASSWORD" "$CONTAINER" \
        smbclient "//127.0.0.1/$SMB_SHARE" -U "$SMB_USER" -m SMB3 -c ls 2>&1) \
     && [[ "$out" != *NT_STATUS_* ]]; then
    ok "smbclient: $SMB_USER can list //localhost/$SMB_SHARE"
  else
    fail "smbclient: $SMB_USER cannot list //localhost/$SMB_SHARE: $(tail -n1 <<<"$out")"
  fi
else
  warn "SMB login check skipped (set SMB_SHARE and SMB_USER)"
fi

# 8. WebDAV service (optional).
DAV_CONTAINER="${DAV_CONTAINER:-smb-dav}"
DAV_LOCAL_URL="${DAV_LOCAL_URL:-http://127.0.0.1:${DAV_PORT:-8094}}"
dav_state() { "${DOCKER[@]}" inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$DAV_CONTAINER" 2>/dev/null; }
dstate=$(dav_state)
# Right after an update smb-dav waits for the main container: give it a minute.
for _ in $(seq 1 30); do [[ "$dstate" == "running starting" ]] || break; sleep 2; dstate=$(dav_state); done
if [[ -z "$dstate" ]]; then
  ok "WebDAV not enabled (no $DAV_CONTAINER container)"
else
  [[ "$dstate" == "running healthy" ]] && ok "container $DAV_CONTAINER is running and healthy" \
    || fail "container $DAV_CONTAINER is '$dstate'"
  hard=$("${DOCKER[@]}" inspect -f '{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapAdd}}|{{.HostConfig.CapDrop}}|{{.Config.User}}|{{.HostConfig.SecurityOpt}}' "$DAV_CONTAINER" 2>/dev/null)
  IFS='|' read -r ro capadd capdrop duser secopt <<<"$hard"
  if [[ "$ro" == true && ( "$capadd" == "[]" || "$capadd" == "<no value>" ) && "$capdrop" == *ALL* \
        && -n "$duser" && "${duser%%:*}" != 0 && "${duser%%:*}" != root && "$secopt" == *no-new-privileges* ]]; then
    ok "$DAV_CONTAINER: read-only, no capabilities, no-new-privileges, user $duser"
  else
    fail "$DAV_CONTAINER hardening: read_only=$ro cap_add=$capadd cap_drop=$capdrop user=$duser security_opt=$secopt"
  fi
  if "${DOCKER[@]}" exec "$DAV_CONTAINER" sh -c 'test -e /data || test -e /mnt/timenest || test -e /run/ssm' 2>/dev/null; then
    fail "$DAV_CONTAINER can see /data, /mnt/timenest or the admin socket"
  else
    ok "$DAV_CONTAINER has no /data, /mnt/timenest or admin socket"
  fi
  if "${DOCKER[@]}" exec "$DAV_CONTAINER" sh -c 'env | grep -q "^ADMIN_PASSWORD"' 2>/dev/null; then
    fail "$DAV_CONTAINER has ADMIN_PASSWORD in its environment"
  else
    ok "$DAV_CONTAINER does not get the admin password"
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X OPTIONS "$DAV_LOCAL_URL/")
  hdrs=$(curl -s -D - -o /dev/null --max-time 5 -X OPTIONS "$DAV_LOCAL_URL/" | tr -d '\r')
  if [[ "$code" == 403 ]] && ! grep -qi '^www-authenticate' <<<"$hdrs"; then
    ok "plain HTTP to $DAV_LOCAL_URL refused before any password is asked for"
  elif [[ "$code" == 401 ]]; then
    warn "plain HTTP to $DAV_LOCAL_URL asks for a password (DAV_ALLOW_HTTP=true? only for local testing)"
  else
    fail "unexpected answer $code from $DAV_LOCAL_URL"
  fi
  if grep -qiE '^server: .*[0-9]' <<<"$hdrs"; then
    fail "WebDAV Server header shows a version"
  fi
  admin=$(curl -s --max-time 5 "$DAV_LOCAL_URL/api/auth/status")
  if [[ "$admin" == *csrf* ]]; then
    fail "the admin API answers on the WebDAV port"
  else
    ok "the admin API is not served on the WebDAV port"
  fi
  if [[ -n "${DAV_URL:-}" && -n "${SMB_USER:-}" ]]; then
    if [[ -z "${SMB_PASSWORD:-}" ]]; then
      read -r -s -p "SMB password for $SMB_USER: " SMB_PASSWORD; echo
    fi
    esc_pw=${SMB_PASSWORD//\\/\\\\}; esc_pw=${esc_pw//\"/\\\"}
    share="${DAV_SHARE:-${SMB_SHARE:-}}"
    # Credentials go to curl on stdin, never on the command line.
    listing=$(printf 'user = "%s:%s"\n' "$SMB_USER" "$esc_pw" \
      | curl -s -K - --max-time 15 -X PROPFIND -H 'Depth: 1' -w '\n%{http_code}' "$DAV_URL/")
    lcode=${listing##*$'\n'}
    if [[ "$lcode" == 207 && ( -z "$share" || "$listing" == *"/$share/"* ) ]]; then
      ok "WebDAV: $SMB_USER can list $DAV_URL/${share:+ (sees $share)}"
    else
      fail "WebDAV: $SMB_USER listing $DAV_URL/ gave HTTP $lcode${share:+ or $share is missing} (is Remote access ticked for $SMB_USER?)"
    fi
    remote_admin=$(curl -s --max-time 10 "$DAV_URL/api/auth/status")
    [[ "$remote_admin" == *csrf* ]] && fail "the admin API answers on $DAV_URL" \
      || ok "the admin API is not reachable through $DAV_URL"
  else
    warn "WebDAV login check skipped (set DAV_URL and SMB_USER)"
  fi
fi

if (( failed )); then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: OK"
