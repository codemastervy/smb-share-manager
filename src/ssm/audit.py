"""Structured audit log: one JSON object per line on stdout. Never pass secrets here."""

from __future__ import annotations

import json
import sys
import time
from typing import Any

# Keys that must never be logged, even by mistake.
_FORBIDDEN_KEYS = frozenset(
    {"password", "password2", "new_password", "token", "csrf_token", "hash"}
)


def event(name: str, /, **fields: Any) -> None:
    record: dict[str, Any] = {"ts": round(time.time(), 3), "event": name}
    for k, val in fields.items():
        if k in _FORBIDDEN_KEYS:
            raise ValueError(f"refusing to audit-log secret field {k!r}")
        record[k] = val
    sys.stdout.write(json.dumps(record, ensure_ascii=True, default=str) + "\n")
    sys.stdout.flush()
