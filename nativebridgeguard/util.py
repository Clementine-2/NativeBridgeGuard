from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def read_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, data: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def under_path(path: str | Path, parent: str | Path | None) -> bool | None:
    if not parent:
        return None
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except Exception:
        return False


def origin_to_extension_id(origin: str) -> str | None:
    prefix = "chrome-extension://"
    if not origin.startswith(prefix):
        return None
    rest = origin[len(prefix):]
    ext_id = rest.split("/", 1)[0].strip()
    return ext_id or None
