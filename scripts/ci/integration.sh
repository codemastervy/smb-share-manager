#!/bin/bash
# CI integration harness: starts the built image the way docker-compose.yml does, on an
# exFAT (loop-mounted) or ext4 volume, with a real CasaOS-style import fixture, then runs
# tests/integration against it.
#
#   scripts/ci/integration.sh <image> <exfat|ext4>
set -euo pipefail

IMAGE="$1"
FS="${2:-ext4}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
VOLSRC=/mnt/ssm-files
export ADMIN_PW="ci-admin-password-$RANDOM$RANDOM"

echo "::group::volume ($FS)"
sudo mkdir -p "$VOLSRC"
if [[ "$FS" == exfat ]]; then
  truncate -s 512M "$WORK/exfat.img"
  mkfs.exfat "$WORK/exfat.img" >/dev/null
  # Same mount options as the NUC's fstab line.
  sudo mount -o loop,uid=1000,gid=3000,umask=0002 "$WORK/exfat.img" "$VOLSRC"
else
  sudo chown 1000:3000 "$VOLSRC"
  sudo chmod 2775 "$VOLSRC"
fi
findmnt -T "$VOLSRC" || true
echo "::endgroup::"

echo "::group::import fixture (real tdbsam passdb created by the shipped Samba)"
mkdir -p "$WORK/import/etc-samba" "$WORK/import/var-lib-samba/private"
docker run --rm --entrypoint /bin/bash -v "$WORK/import:/import" "$IMAGE" -euc '
  mkdir -p /tmp/s
  cat > /tmp/s/smb.conf <<CONF
[global]
	passdb backend = tdbsam:/import/var-lib-samba/private/passdb.tdb
	private dir = /tmp/s
	lock directory = /tmp/s
	state directory = /tmp/s
	cache directory = /tmp/s
	pid directory = /tmp/s
CONF
  useradd -M -s /usr/sbin/nologin isherveer
  useradd -M -s /usr/sbin/nologin jagdev
  printf "Isherveer-Old-Pass1\nIsherveer-Old-Pass1\n" | smbpasswd -c /tmp/s/smb.conf -a -s isherveer
  printf "Jagdev-Old-Pass-12\nJagdev-Old-Pass-12\n" | smbpasswd -c /tmp/s/smb.conf -a -s jagdev
  pdbedit -s /tmp/s/smb.conf -L
'
cat > "$WORK/import/etc-samba/smb.conf" <<'CONF'
[global]
   workgroup = WORKGROUP
   map to guest = bad user
include=/etc/samba/smb.casa.conf

[printers]
   path = /var/spool/samba
CONF
cat > "$WORK/import/etc-samba/smb.casa.conf" <<'CONF'
[Files]
comment = CasaOS share Files
public = Yes
path = /DATA/Files
read only = No
guest ok = Yes
force user = root

[Isherveer]
comment = CasaOS share Isherveer
path = /DATA/Isherveer
valid users = isherveer
read only = No

[Weird]
path = /DATA/Weird
comment = 100% \
  continued
valid users = jagdev
CONF
sudo chown -R root:root "$WORK/import"
sudo chmod 0700 "$WORK/import"
echo "::endgroup::"

echo "::group::start container"
cp "$ROOT/docker-compose.yml" "$WORK/docker-compose.yml"
cat > "$WORK/docker-compose.override.yml" <<YAML
services:
  smb-share-manager:
    image: $IMAGE
    volumes:
      - $VOLSRC:/mnt/files
      - ./import:/import:ro
YAML
cat > "$WORK/.env" <<ENV
ADMIN_PASSWORD=$ADMIN_PW
VOLUMES=/mnt/files
WEB_PORT=8095
BIND_ADDR=127.0.0.1
SMB_BIND_ADDR=127.0.0.1
SMB_PORT_445=1445
SMB_PORT_139=1139
SMB_SERVER_NAME=CI
PUID=1000
PGID=1000
ENV
COMPOSE="docker compose --project-directory $WORK -f $WORK/docker-compose.yml -f $WORK/docker-compose.override.yml"
$COMPOSE up -d
echo "::endgroup::"

cleanup() {
  echo "::group::container logs"
  docker logs smb-share-manager 2>&1 | tail -n 300 || true
  echo "::endgroup::"
  $COMPOSE down -v || true
  if [[ "$FS" == exfat ]]; then sudo umount "$VOLSRC" || true; fi
  sudo rm -rf "$WORK" || true
}
trap cleanup EXIT

SSM_URL=http://127.0.0.1:8095 SSM_PASSWORD="$ADMIN_PW" SSM_SMB_PORT=1445 SSM_FS="$FS" \
SSM_CONTAINER=smb-share-manager SSM_COMPOSE="$COMPOSE" \
  uv run --frozen pytest -v -p no:cacheprovider "$ROOT/tests/integration" -W ignore::DeprecationWarning
