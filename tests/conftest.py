from __future__ import annotations

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
INDEX_HTML = (
    '<!doctype html><html><head><script type="module" src="/assets/index-abc.js"></script>'
    "</head><body><div id=root></div></body></html>"
)


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
        "frontend_dir": str(tmp / "dist"),
        "server_name": "NAS",
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    volume = tmp_path / "files"
    volume.mkdir()
    (tmp_path / "data").mkdir()
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(INDEX_HTML)
    (dist / "assets" / "index-abc.js").write_text("console.log('app')")
    clock = Clock()
    helper = FakeHelper()
    settings = make_settings(tmp_path, volume)
    helper.import_dir = settings.import_dir

    def make_client(settings: Settings = settings, **kw: Any) -> TestClient:
        app = create_app(settings, helper=helper, clock=clock)
        return TestClient(app, base_url="http://testserver", follow_redirects=False, **kw)

    yield Env(tmp_path, volume, clock, helper, settings, make_client)


def prelogin(client: TestClient) -> str:
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    return str(r.json()["csrf"])


def login(client: TestClient, password: str = PASSWORD) -> str:
    """Log in like the SPA does and return the session CSRF token."""
    pre = prelogin(client)
    r = client.post(
        "/api/auth/login",
        json={"password": password},
        headers={"Origin": ORIGIN, "X-CSRF-Token": pre},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["csrf"])


def call(client: TestClient, method: str, url: str, csrf: str, **kw: Any) -> Any:
    headers = {"Origin": ORIGIN, "X-CSRF-Token": csrf, **kw.pop("headers", {})}
    return client.request(method, url, headers=headers, **kw)


@pytest.fixture
def authed(env: Env) -> tuple[TestClient, str]:
    c = env.make_client()
    return c, login(c)
