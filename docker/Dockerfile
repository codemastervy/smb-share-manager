# smb-share-manager image. Base images are pinned by digest; Dependabot keeps them current.
# (Both Debian FROM lines name the same image; keep them in sync.)
# Debian packages are deliberately not version-pinned so that the weekly --pull --no-cache
# rebuild picks up Debian security updates.

FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

# ---- build stage: the React UI (npm ci from the lockfile, which pins sha512 integrity) ----
FROM node:24-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
# --ignore-scripts: no package install scripts run during the build.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- build stage: Python dependencies from the hash-locked uv.lock ----------------------
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt \
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps --only-binary :all: \
      -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip \
 && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

# ---- runtime ------------------------------------------------------------------------------
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
ARG APP_VERSION=dev
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="smb-share-manager" \
      org.opencontainers.image.description="Small web UI for managing Samba shares and SMB users" \
      org.opencontainers.image.source="https://github.com/codemastervy/smb-share-manager" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      samba smbclient libnss-extrausers tini python3 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log \
 # SMB unix accounts live in /data/extrausers (libnss-extrausers reads /var/lib/extrausers).
 && rm -rf /var/lib/extrausers && ln -s /data/extrausers /var/lib/extrausers \
 && sed -i -E 's/^(passwd|group|shadow):\s+(.*)$/\1: \2 extrausers/' /etc/nsswitch.conf \
 && grep -q 'passwd:.*extrausers' /etc/nsswitch.conf \
 # Debian's default config and state are replaced by ours.
 && rm -rf /etc/samba/* /var/lib/samba/* /var/cache/samba/* /var/log/samba/*

COPY --from=build /opt/venv /opt/venv
COPY src/ssm /opt/app/ssm
COPY --from=frontend /build/dist /opt/app/frontend
COPY docker/smb.conf /etc/samba/smb.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/healthcheck.py /usr/local/bin/healthcheck.py
RUN chmod 0644 /etc/samba/smb.conf \
 && chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.py \
 && /opt/venv/bin/python -m compileall -q /opt/app

ENV PATH=/opt/venv/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_VERSION=${APP_VERSION} \
    BUILD_DATE=${BUILD_DATE} \
    FRONTEND_DIR=/opt/app/frontend \
    PUID=1000 \
    PGID=1000 \
    VOLUMES=/mnt/files

EXPOSE 445 139 8095
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/opt/venv/bin/python", "/usr/local/bin/healthcheck.py"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
