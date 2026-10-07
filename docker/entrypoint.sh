#!/bin/bash
# Starts smbd (root), the root helper and the unprivileged web app, and exits as soon as
# any of them stops so that Docker's restart policy brings the whole container back.
set -euo pipefail

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
SMB_GID=3000

log() { printf '{"event":"entrypoint","msg":"%s"}\n' "$*"; }
die() { printf '{"event":"entrypoint","error":"%s"}\n' "$*" >&2; exit 1; }

[[ "$PUID" =~ ^[0-9]+$ && "$PGID" =~ ^[0-9]+$ ]] || die "PUID and PGID must be numbers"
[[ "$PUID" -ne 0 ]] || die "PUID must not be 0: the web app never runs as root"
[[ -n "${ADMIN_PASSWORD:-}" || -n "${ADMIN_PASSWORD_HASH:-}" ]] \
  || die "Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH in .env; refusing to start"

# Persistent state (bind mount ./data).
mkdir -p /data/app /data/samba/private /data/samba/state /data/extrausers
chown root:root /data/samba /data/samba/private /data/samba/state /data/extrausers
chmod 0755 /data/samba /data/extrausers
chmod 0700 /data/samba/private /data/samba/state
chown "$PUID:$PGID" /data/app
chmod 0700 /data/app
[[ -e /data/samba/shares.conf ]] || printf '# No shares yet.\n' > /data/samba/shares.conf

# Runtime state (tmpfs).
mkdir -p /run/samba/lock /run/samba/cache /run/samba/ncalrpc /run/ssm /tmp/ssm-helper
chmod 0700 /tmp/ssm-helper
chown "root:$PGID" /run/ssm
chmod 0750 /run/ssm

# The root processes never see the admin password.
ROOT_ENV=(env -u ADMIN_PASSWORD -u ADMIN_PASSWORD_HASH)

"${ROOT_ENV[@]}" /opt/venv/bin/python -m ssm.helper.server --init
testparm -s --suppress-prompt /etc/samba/smb.conf >/dev/null 2>/tmp/testparm.err \
  || { cat /tmp/testparm.err >&2; die "Samba configuration is invalid"; }

pids=()
"${ROOT_ENV[@]}" /usr/sbin/smbd --foreground --no-process-group --debug-stdout &
pids+=($!)
if [[ "${ENABLE_NMBD:-false}" == "true" ]]; then
  "${ROOT_ENV[@]}" /usr/sbin/nmbd --foreground --no-process-group --debug-stdout &
  pids+=($!)
fi
"${ROOT_ENV[@]}" /opt/venv/bin/python -m ssm.helper.server &
pids+=($!)

# Group-writable files and folders: SMB members share the smbusers group.
umask 0002
setpriv --reuid="$PUID" --regid="$PGID" --groups="$PGID,$SMB_GID" --no-new-privs \
  /opt/venv/bin/python -m ssm.web.main &
pids+=($!)

log "started smbd, helper and web (uid $PUID)"

shutdown() {
  log "stopping"
  kill -TERM "${pids[@]}" 2>/dev/null || true
  wait || true
  exit 0
}
trap shutdown TERM INT

set +e
wait -n "${pids[@]}"
status=$?
log "a process exited with status $status; stopping the container"
kill -TERM "${pids[@]}" 2>/dev/null
wait
exit "$status"
