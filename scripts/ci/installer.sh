#!/bin/bash
# CI: scripts/remote-access.sh on a pre-WebDAV install (the old docker-compose.yml, as on
# servers installed before WebDAV), unattended, then again after switching to the current
# docker-compose.yml. Checks that smb-dav and smb-portal come up healthy and serve the
# chosen shares to the chosen user.
#
#   scripts/ci/installer.sh <local image tag>
set -euo pipefail

IMAGE="$1"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
PW="ci-admin-password-$RANDOM$RANDOM"
APW="alice-password-0123456789"
PUB=ghcr.io/codemastervy/smb-share-manager:latest
docker tag "$IMAGE" "$PUB"

sudo mkdir -p /mnt/files/Family /mnt/files/Media
sudo chown -R 1000:3000 /mnt/files
sudo chmod -R 2775 /mnt/files

cp "$ROOT/tests/fixtures/docker-compose.pre-webdav.yml" "$WORK/docker-compose.yml"
cat > "$WORK/.env" <<ENV
ADMIN_PASSWORD=$PW
VOLUMES=/mnt/files
BIND_ADDR=127.0.0.1
WEB_PORT=8095
SMB_BIND_ADDR=127.0.0.1
SMB_PORT_445=1445
SMB_PORT_139=1139
PUID=1000
PGID=1000
ENV
dc() { docker compose --project-directory "$WORK" "$@"; }

cleanup() {
  for c in smb-share-manager smb-dav smb-portal; do
    echo "::group::$c logs"; docker logs "$c" 2>&1 | tail -n 100 || true; echo "::endgroup::"
  done
  (cd "$WORK" && dc down -v) || true
  sudo rm -rf "$WORK" /mnt/files || true
}
trap cleanup EXIT

wait_healthy() {
  for _ in $(seq 1 60); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" == healthy ]] && return 0
    sleep 3
  done
  echo "$1 not healthy"; return 1
}

echo "::group::old-style install with users and shares"
(cd "$WORK" && dc up -d)
wait_healthy smb-share-manager
uv run --frozen python - "$PW" "$APW" <<'PY'
import sys, httpx
pw, apw = sys.argv[1], sys.argv[2]
u = "http://127.0.0.1:8095"
c = httpx.Client(base_url=u)
pre = c.get("/api/auth/status").json()["csrf"]
r = c.post("/api/auth/login", json={"password": pw}, headers={"Origin": u, "X-CSRF-Token": pre})
h = {"Origin": u, "X-CSRF-Token": r.json()["csrf"]}
for name in ("alice", "bob"):
    r = c.post("/api/users", json={"username": name, "password": apw}, headers=h)
    assert r.status_code == 201, r.text
for share, members in (("Family", [("alice", "rw"), ("bob", "rw")]), ("Media", [("alice", "ro")])):
    r = c.post("/api/shares", headers=h, json={"name": share, "path": f"/files/{share}",
               "members": [{"username": m, "access": a} for m, a in members]})
    assert r.status_code < 300, r.text
PY
echo "::endgroup::"

run_installer() {
  (cd "$WORK" && RA_YES=1 RA_NO_PULL=1 RA_SHARES=Family,Media RA_PORTAL_HOST=files.ci.test \
    RA_DAV_HOST=dav.ci.test RA_PROXIES=172.16.0.0/12 RA_USERS="alice=alice@ci.test" \
    "$ROOT/scripts/remote-access.sh" setup)
}

check() {
  wait_healthy smb-dav
  wait_healthy smb-portal
  grep -q '^COMPOSE_FILE=docker-compose.yml:compose.remote.yml$' "$WORK/.env"
  grep -q '^PORTAL_HEADER_VERIFIED=false$' "$WORK/.env"
  secret="$(sed -n 's/^PORTAL_PROXY_SECRET=//p' "$WORK/.env")"
  [[ ${#secret} -ge 32 ]]
  uv run --frozen python - "$APW" "$secret" <<'PY'
import sys, httpx
apw, secret = sys.argv[1], sys.argv[2]
via_proxy = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"}
r = httpx.request("PROPFIND", "http://127.0.0.1:8094/", auth=("alice", apw),
                  headers={**via_proxy, "Depth": "1"})
assert r.status_code == 207, (r.status_code, r.text[:300])
assert "/Family/" in r.text and "/Media/" in r.text, r.text[:1000]
r = httpx.request("PROPFIND", "http://127.0.0.1:8094/", auth=("bob", apw),
                  headers={**via_proxy, "Depth": "1"})
assert r.status_code == 401, r.status_code  # bob was not given remote access
r = httpx.put("http://127.0.0.1:8094/Family/hello.txt", content=b"hi", auth=("alice", apw),
              headers=via_proxy)
assert r.status_code in (201, 204), r.status_code
h = {"Host": "files.ci.test", "X-Forwarded-Proto": "https", "X-Portal-Proxy-Secret": secret,
     "Remote-Email": "alice@ci.test"}
r = httpx.get("http://127.0.0.1:8096/api/portal/probe", headers=h)
assert r.status_code == 200 and r.json()["values"] == ["alice@ci.test"], r.text
assert httpx.get("http://127.0.0.1:8096/api/portal/me", headers=h).status_code == 503
print("installer checks passed")
PY
  test -f /mnt/files/Family/hello.txt
}

echo "::group::installer on the pre-WebDAV docker-compose.yml"
run_installer
cat "$WORK/compose.remote.yml"
check
echo "::endgroup::"

echo "::group::installer again (idempotent)"
run_installer
check
echo "::endgroup::"

echo "::group::after switching to the current docker-compose.yml"
cp "$ROOT/docker-compose.yml" "$WORK/docker-compose.yml"
run_installer
cat "$WORK/compose.remote.yml"
(cd "$WORK" && dc up -d)
check
(cd "$WORK" && "$ROOT/scripts/remote-access.sh" status)
echo "::endgroup::"
