"""Entry point for the unprivileged web process."""

from __future__ import annotations

import os
import sys
import threading
import time

import uvicorn

from ssm import audit
from ssm.helper_client import HelperClient, HelperError
from ssm.settings import ConfigError, load_settings
from ssm.web.app import create_app


def _sync_registry(app: object, client: HelperClient) -> None:
    """Push the registry to Samba once the helper is up (state lives only in ./data)."""
    registry = app.state.registry  # type: ignore[attr-defined]
    for _ in range(60):
        try:
            client.apply_shares(registry.list_shares())
        except HelperError as e:
            last = str(e)
            time.sleep(1)
            continue
        audit.event("startup_sync", ok=True, shares=len(registry.list_shares()))
        return
    audit.event("startup_sync", ok=False, error=last)


def main() -> None:
    try:
        settings = load_settings(os.environ)
        client = HelperClient(settings.helper_socket)
        app = create_app(settings, helper=client)
    except ConfigError as e:
        sys.stderr.write(f"smb-share-manager: configuration error: {e}\n")
        sys.exit(2)
    threading.Thread(target=_sync_registry, args=(app, client), daemon=True).start()
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104  # nosec B104 - inside the container; publish via BIND_ADDR
        port=8095,
        proxy_headers=False,  # X-Forwarded-* handled by the app, only from TRUSTED_PROXIES
        server_header=False,
        date_header=False,
        access_log=False,
        log_level="warning",
        timeout_keep_alive=5,
    )


if __name__ == "__main__":
    main()
