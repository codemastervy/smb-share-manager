#!/opt/venv/bin/python
"""Container healthcheck: web app answers /healthz and smbd responds to a ping."""

import subprocess
import sys
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:8095/healthz", timeout=4) as r:  # noqa: S310
        ok = r.status == 200
except OSError:
    ok = False
ping = subprocess.run(  # noqa: S603
    ["/usr/bin/smbcontrol", "smbd", "ping"], capture_output=True, timeout=4, check=False
)
sys.exit(0 if ok and ping.returncode == 0 else 1)
