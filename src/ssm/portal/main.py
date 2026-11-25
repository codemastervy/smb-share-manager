"""Entry point of the files portal container (python -m ssm.portal.main).

Same self-checks as the WebDAV container (not root, not PUID, no capabilities,
no-new-privileges, no /data, admin socket or whole volume mounted), plus: its uid must
differ from DAV_UID, so the helper's password-check socket never answers it.
"""

from __future__ import annotations

import os
import sys

import uvicorn

from ssm import audit
from ssm.dav.acl import AclStore, system_mountpoints
from ssm.dav.main import StartupError, proc_status, startup_checks, wait_for_snapshot
from ssm.portal.app import build_asgi
from ssm.portal.settings import PortalSettings, load_portal_settings
from ssm.settings import ConfigError

PORT = 8096


def portal_checks(settings: PortalSettings, store: AclStore, uid: int) -> None:
    if uid == settings.dav_uid:
        raise StartupError("refusing to run as DAV_UID: give smb-portal its own PORTAL_UID")
    status = proc_status()
    cap = status.get("CapEff")
    nnp = status.get("NoNewPrivs")
    startup_checks(
        settings,
        store,
        uid=uid,
        puid=settings.puid,
        cap_eff=int(cap, 16) if cap else None,
        mounts=system_mountpoints(),
        no_new_privs=None if nnp is None else nnp == "1",
        what="portal",
    )


def main() -> None:
    try:
        settings = load_portal_settings(os.environ)
    except ConfigError as e:
        sys.stderr.write(f"smb-portal: configuration error: {e}\n")
        sys.exit(2)
    os.umask(0o002)  # group smbusers can edit what portal users upload
    store = AclStore(
        os.path.join(settings.bridge_dir, "acl.json"), settings.exposed_shares, settings.volumes
    )
    wait_for_snapshot(store)
    try:
        portal_checks(settings, store, os.getuid())
    except StartupError as e:
        audit.event("portal_startup", ok=False, error=str(e))
        sys.stderr.write(f"smb-portal: {e}\n")
        sys.exit(2)
    audit.event(
        "portal_startup",
        ok=True,
        hosts=settings.hosts,
        exposed=settings.exposed_shares,
        trusted_proxies=settings.trusted_proxies,
        setup_mode=not settings.header_verified,
    )
    uvicorn.run(
        build_asgi(settings, store),
        host="0.0.0.0",  # noqa: S104  # nosec B104 - inside the container; see PORTAL_BIND_ADDR
        port=PORT,
        proxy_headers=False,  # the identity and client headers are judged by the app
        server_header=False,
        date_header=False,
        access_log=False,
        log_level="warning",
        timeout_keep_alive=5,
        limit_concurrency=64,
        h11_max_incomplete_event_size=16 * 1024,
    )


if __name__ == "__main__":
    main()
