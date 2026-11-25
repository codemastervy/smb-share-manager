"""docker-compose.yml: the internet-facing services stay as narrow as SECURITY.md says."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[2]


def services() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    return dict(data["services"])


def test_image_only_never_build() -> None:
    for name, svc in services().items():
        assert "build" not in svc, name
        assert svc["image"].startswith("ghcr.io/codemastervy/smb-share-manager:"), name


@pytest.mark.parametrize(
    ("name", "profile", "uid_var", "module"),
    [
        ("smb-dav", "dav", "DAV_UID", "ssm.dav.main"),
        ("smb-portal", "portal", "PORTAL_UID", "ssm.portal.main"),
    ],
)
def test_outside_facing_services_are_narrow(
    name: str, profile: str, uid_var: str, module: str
) -> None:
    svc = services()[name]
    assert svc["profiles"] == [profile]  # off unless enabled
    assert svc["command"][-1] == module
    assert svc["user"].startswith("${" + uid_var) and svc["user"].endswith(":3000")
    assert "env_file" not in svc  # never sees ADMIN_PASSWORD
    assert "ADMIN_PASSWORD" not in str(svc["environment"])
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["read_only"] is True
    assert "privileged" not in svc
    assert "network_mode" not in svc
    assert svc["volumes"] == ["dav-bridge:/run/ssm-dav:ro"]  # share folders are added by hand
    assert "healthcheck" in svc and svc["restart"] == "unless-stopped"


def test_portal_uid_default_differs() -> None:
    s = services()
    assert s["smb-portal"]["user"] == "${PORTAL_UID:-2998}:3000"
    assert s["smb-dav"]["user"] == "${DAV_UID:-2999}:3000"


def test_installer_services_match_compose() -> None:
    """scripts/remote-access.sh carries the service definitions for installs whose
    docker-compose.yml predates them; they must stay identical."""
    text = (ROOT / "scripts" / "remote-access.sh").read_text()
    block = text.split("# BEGIN SERVICES\n", 1)[1].split("# END SERVICES", 1)[0]
    embedded = yaml.safe_load(block)
    s = services()
    assert embedded == {"smb-dav": s["smb-dav"], "smb-portal": s["smb-portal"]}
