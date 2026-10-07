"""Vendored assets are pinned by hash; no external URLs anywhere in the UI."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[2] / "src" / "ssm" / "web"
HTMX_SHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"


def test_htmx_hash_pinned() -> None:
    digest = hashlib.sha256((WEB / "static" / "htmx.min.js").read_bytes()).hexdigest()
    assert digest == HTMX_SHA256
    assert HTMX_SHA256 in (WEB / "static" / "VENDORED.txt").read_text()


def test_no_external_urls_in_templates_or_assets() -> None:
    for p in [
        *list((WEB / "templates").glob("*.html")),
        WEB / "static" / "app.js",
        WEB / "static" / "app.css",
    ]:
        text = p.read_text()
        assert not re.search(r"(src|href)\s*=\s*[\"']?(https?:)?//", text), p.name
        assert "@import" not in text, p.name
