"""Entry point of the WebDAV container (python -m ssm.dav.main).

Before serving anything it checks that the container is as narrow as intended and refuses
to start otherwise: not root, not PUID, no effective capabilities, no-new-privileges set,
no whole volume and no /data, /mnt/timenest or admin socket mounted, and no exposed share
that covers a whole volume.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from collections.abc import Callable
from typing import Any, Protocol

from cheroot import wsgi

from ssm import audit
from ssm.dav.acl import AclStore, is_volume_root, system_mountpoints
from ssm.dav.app import build_app
from ssm.dav.settings import load_dav_settings
from ssm.helper_client import VerifyClient
from ssm.settings import ConfigError

FORBIDDEN_PATHS = ("/data", "/mnt/timenest", "/run/ssm", "/import")
MAX_HEADER_BYTES = 16 * 1024


class StartupError(Exception):
    pass


class _HasVolumes(Protocol):
    @property
    def volumes(self) -> list[str]: ...


def proc_status() -> dict[str, str]:
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as f:
            return dict(
                (k.strip(), val.strip()) for k, _, val in (line.partition(":") for line in f) if k
            )
    except OSError:
        return {}


def startup_checks(
    settings: _HasVolumes,
    store: AclStore,
    uid: int,
    puid: int,
    cap_eff: int | None,
    mounts: set[str],
    exists: Callable[[str], bool] = os.path.lexists,
    no_new_privs: bool | None = None,
    what: str = "WebDAV",
) -> None:
    if uid == 0:
        raise StartupError("refusing to run as root; set user: DAV_UID:3000 in compose")
    if uid == puid:
        raise StartupError("refusing to run as PUID: DAV_UID must differ from PUID")
    if cap_eff:
        raise StartupError(f"refusing to run with capabilities ({cap_eff:#x}); use cap_drop: ALL")
    if no_new_privs is False:
        raise StartupError("refusing to run without no-new-privileges")
    for p in FORBIDDEN_PATHS:
        if p in mounts or exists(p):
            raise StartupError(f"{p} must not be mounted into the {what} container")
    for m in mounts:
        if is_volume_root(m, settings.volumes):
            raise StartupError(
                f"the whole volume {m} is mounted; mount only the exposed share folders"
            )
    whole = store.whole_volume_exposed()
    if whole:
        raise StartupError(
            f"exposed share(s) {', '.join(whole)} cover a whole volume and are refused"
        )


def wait_for_snapshot(store: AclStore, seconds: float = 60.0) -> None:
    deadline = time.monotonic() + seconds
    while store.current() is None and time.monotonic() < deadline:
        time.sleep(1)


def main() -> None:
    try:
        settings = load_dav_settings(os.environ)
    except ConfigError as e:
        sys.stderr.write(f"smb-dav: configuration error: {e}\n")
        sys.exit(2)
    os.umask(0o002)  # group smbusers can edit what WebDAV users create
    store = AclStore(
        os.path.join(settings.bridge_dir, "acl.json"), settings.exposed_shares, settings.volumes
    )
    wait_for_snapshot(store)
    status = proc_status()
    cap = status.get("CapEff")
    nnp = status.get("NoNewPrivs")
    try:
        startup_checks(
            settings,
            store,
            uid=os.getuid(),
            puid=settings.puid,
            cap_eff=int(cap, 16) if cap else None,
            mounts=system_mountpoints(),
            no_new_privs=None if nnp is None else nnp == "1",
        )
    except StartupError as e:
        audit.event("dav_startup", ok=False, error=str(e))
        sys.stderr.write(f"smb-dav: {e}\n")
        sys.exit(2)
    if not settings.exposed_shares:
        audit.event("dav_startup", ok=True, warning="DAV_EXPOSED_SHARES is empty: nothing served")

    app = build_app(settings, store, VerifyClient(settings.verify_socket))
    server: Any = wsgi.Server(
        ("0.0.0.0", settings.port),  # noqa: S104  # nosec B104 - published via DAV_BIND_ADDR
        app,
        numthreads=settings.threads,
        max=settings.threads,
        request_queue_size=64,
        timeout=int(settings.socket_timeout),
        server_name="WebDAV",
        shutdown_timeout=5,
    )
    server.max_request_header_size = MAX_HEADER_BYTES
    # Body size is enforced by the guard (Content-Length up front, then a byte count while
    # streaming), which answers 413. cheroot's own limit raises a bare IOError on chunked
    # bodies that would surface as 500, so it is left off.
    server.max_request_body_size = 0

    def stop(_sig: int, _frame: Any) -> None:
        server.stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    audit.event(
        "dav_startup",
        ok=True,
        port=settings.port,
        exposed=settings.exposed_shares,
        trusted_proxies=settings.trusted_proxies,
        allow_http=settings.allow_http,
    )
    try:
        server.start()
    finally:
        server.stop()


if __name__ == "__main__":
    main()
