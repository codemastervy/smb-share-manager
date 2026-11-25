#!/opt/venv/bin/python
"""Container healthcheck.

Default (main container): the web app answers /healthz and smbd responds to a ping.
--dav (WebDAV container): the ACL snapshot is readable and an unauthenticated OPTIONS is
refused (401, or 403 "HTTPS required" for plain HTTP from a non-proxy). Never sends a
password.
--portal (files portal container): /healthz answers 200 (the ACL snapshot is loaded).
"""

import http.client
import os
import subprocess
import sys
import urllib.request


def dav() -> bool:
    if not os.access("/run/ssm-dav/acl.json", os.R_OK):
        return False
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8094, timeout=4)
        conn.request("OPTIONS", "/")
        status = conn.getresponse().status
        conn.close()
    except OSError:
        return False
    return status in (401, 403)


def portal() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8096/healthz", timeout=4) as r:
            return bool(r.status == 200)
    except OSError:
        return False


def main_container() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8095/healthz", timeout=4) as r:
            ok = r.status == 200
    except OSError:
        ok = False
    ping = subprocess.run(
        ["/usr/bin/smbcontrol", "smbd", "ping"], capture_output=True, timeout=4, check=False
    )
    return ok and ping.returncode == 0


args = sys.argv[1:]
check = dav if "--dav" in args else portal if "--portal" in args else main_container
sys.exit(0 if check() else 1)
