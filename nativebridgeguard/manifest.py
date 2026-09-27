from __future__ import annotations

import json
import os
from pathlib import Path

from .models import NativeHostManifest


def parse_host_manifest(path: str, fallback_name: str) -> NativeHostManifest | None:
    p = Path(os.path.expandvars(path)).expanduser()
    if not p.is_file():
        return None
    try:
        # utf-8-sig tolerates a leading BOM if one is present (some tooling/PS
        # versions emit one) and is identical to utf-8 otherwise. This is
        # defensive: the lab generators MUST still write UTF-8 without BOM.
        raw = json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    allowed = raw.get("allowed_origins", [])
    if not isinstance(allowed, list):
        allowed = []
    binary = raw.get("path")
    if binary:
        binary = os.path.expandvars(str(binary))
        if not os.path.isabs(binary):
            binary = str((p.parent / binary).resolve())
    return NativeHostManifest(
        name=str(raw.get("name", fallback_name)),
        description=raw.get("description"),
        manifest_path=str(p),
        binary_path=binary,
        allowed_origins=[str(x) for x in allowed],
        raw=raw,
    )
