from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ssm.settings import Settings
from ssm.web.app import create_app
from tests.fakes import FakeHelper

PASSWORD = "correct horse battery"
ORIGIN = "http://testserver"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Env:
    tmp: Path
    volume: Path
    clock: Clock
    helper: FakeHelper
    settings: Settings
    make_client: Callable[..., TestClient]
    extra: dict[str, Any] = field(default_factory=dict)


def make_settings(tmp: Path, volume: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "admin_password": PASSWORD,
        "admin_password_hash": None,
        "volumes": [str(volume)],
        "data_dir": str(tmp / "data"),
        "trusted_proxies": [],
        "allowed_hosts": ["testserver"],
        "cookie_secure": "auto",
        "max_upload_bytes": 1024 * 1024,
        "helper_socket": str(tmp / "helper.sock"),
        "version": "test",
        "build_date": "2026-10-08",
        "import_dir": str(tmp / "import"),
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    volume = tmp_path / "files"
    volume.mkdir()
    (tmp_path / "data").mkdir()
    clock = Clock()
    helper = FakeHelper()
    settings = make_settings(tmp_path, volume)
    helper.import_dir = settings.import_dir

    def make_client(settings: Settings = settings, **kw: Any) -> TestClient:
        app = create_app(settings, helper=helper, clock=clock)
        return TestClient(app, base_url="http://testserver", follow_redirects=False, **kw)

    yield Env(tmp_path, volume, clock, helper, settings, make_client)


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html) or re.search(
        r'name="csrf-token" content="([^"]+)"', html
    )
    assert m, "no csrf token in page"
    return m.group(1)


def login(client: TestClient, password: str = PASSWORD) -> str:
    """Log in and return the session CSRF token."""
    page = client.get("/login")
    token = csrf_from(page.text)
    r = client.post(
        "/login",
        data={"password": password, "csrf_token": token},
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 303, r.text
    return csrf_from(client.get("/shares").text)


def post(client: TestClient, url: str, csrf: str, data: dict[str, Any] | None = None) -> Any:
    return client.post(url, data={**(data or {}), "csrf_token": csrf}, headers={"Origin": ORIGIN})


@pytest.fixture
def authed(env: Env) -> tuple[TestClient, str]:
    c = env.make_client()
    return c, login(c)
