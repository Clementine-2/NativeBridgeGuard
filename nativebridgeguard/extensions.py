from __future__ import annotations

import json
import os
from pathlib import Path

from .models import BrowserExtension


def _resolve_name(manifest: dict, version_dir: Path) -> str:
    name = str(manifest.get("name", ""))
    if name.startswith("__MSG_") and name.endswith("__"):
        key = name[6:-2]
        locale = manifest.get("default_locale")
        if locale:
            msg = version_dir / "_locales" / str(locale) / "messages.json"
            try:
                data = json.loads(msg.read_text(encoding="utf-8"))
                entry = data.get(key) or data.get(key.lower())
                if isinstance(entry, dict) and entry.get("message"):
                    return str(entry["message"])
            except Exception:
                pass
    return name or "(unnamed extension)"


def _latest_version_dir(ext_dir: Path) -> Path | None:
    dirs = [p for p in ext_dir.iterdir() if p.is_dir()]
    if not dirs:
        return None
    return sorted(dirs, key=lambda p: p.name, reverse=True)[0]


def _scan_browser(browser: str, user_data: Path) -> list[BrowserExtension]:
    out: list[BrowserExtension] = []
    if not user_data.is_dir():
        return out
    profiles = [p for p in user_data.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))]
    for profile in profiles:
        ext_root = profile / "Extensions"
        if not ext_root.is_dir():
            continue
        for ext_dir in ext_root.iterdir():
            if not ext_dir.is_dir():
                continue
            version_dir = _latest_version_dir(ext_dir)
            if not version_dir:
                continue
            manifest_path = version_dir / "manifest.json"
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            perms = manifest.get("permissions", [])
            if not isinstance(perms, list):
                perms = []
            out.append(BrowserExtension(
                browser=browser,
                profile=profile.name,
                extension_id=ext_dir.name,
                name=_resolve_name(manifest, version_dir),
                version=str(manifest.get("version", version_dir.name)),
                manifest_path=str(manifest_path),
                permissions=[str(x) for x in perms],
            ))
    return out


def collect_extensions() -> list[BrowserExtension]:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    localp = Path(local)
    targets = {
        "chrome": localp / "Google" / "Chrome" / "User Data",
        "edge": localp / "Microsoft" / "Edge" / "User Data",
    }
    out: list[BrowserExtension] = []
    for browser, path in targets.items():
        out.extend(_scan_browser(browser, path))
    return out


def _read_extension_settings(prefs_path: Path) -> dict:
    """Return ``extensions.settings`` from a Preferences / Secure Preferences
    file.

    Returns ``{}`` on any read or parse problem, so a single corrupt preference
    file never aborts the per-profile collector. This isolation is what lets the
    collector keep working from the *other* source when one is malformed.
    """
    try:
        text = prefs_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except Exception:
        return {}
    settings = (data.get("extensions") or {}).get("settings")
    return settings if isinstance(settings, dict) else {}


def _emit_unpacked(browser: str, profile_name: str,
                   ext_id: str, entry: dict) -> "BrowserExtension | None":
    """Resolve an unpacked entry's *real* manifest from disk and build a
    BrowserExtension. Returns ``None`` (and never raises) for malformed or
    missing entries, so one bad entry cannot take down the rest.

    The preference entry is used only to locate the unpacked directory via its
    ``path``; the authoritative extension info always comes from the real
    ``manifest.json`` on disk, never from the preferences-cached manifest.
    """
    path = entry.get("path")
    if not path:
        return None
    try:
        ext_dir = Path(path)
        if not ext_dir.is_dir():
            return None
        manifest_path = ext_dir / "manifest.json"
        if not manifest_path.is_file():
            return None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        perms = manifest.get("permissions", [])
        if not isinstance(perms, list):
            perms = []
        return BrowserExtension(
            browser=browser,
            profile=profile_name,
            extension_id=ext_id,
            name=_resolve_name(manifest, ext_dir),
            version=str(manifest.get("version", "")),
            manifest_path=str(manifest_path),
            permissions=[str(x) for x in perms],
        )
    except Exception:
        return None


def collect_unpacked_extensions(existing: set | None = None) -> list[BrowserExtension]:
    """Supplemental collector for extensions loaded via `Load unpacked`.

    The directory scan (collect_extensions) only sees extensions installed under
    `<profile>\\Extensions\\<id>\\<version>`. Chrome/Edge `Load unpacked`
    extensions live in an arbitrary external directory, so they never appear
    there. This collector reads each profile's `Preferences` **and** `Secure
    Preferences` JSON, resolves the `path` field (an absolute local directory)
    for extension IDs the directory scan did NOT already collect, reads the
    *real* manifest.json from disk (never the preferences-cached manifest), and
    emits a BrowserExtension.

    Why both files: modern Chrome/Edge store extension settings (including the
    unpacked `path`) in `Secure Preferences`, while `Preferences` is empty. The
    RC1.1 collector only read `Preferences` and therefore missed every
    Load-unpacked extension on current Chrome/Edge. This fix reads both.

    Merge / priority rules:
    - `Secure Preferences` takes priority over `Preferences`; an ID present in
      both resolves to the Secure Preferences entry (its `path` wins).
    - An ID present in both is processed exactly once (de-duplicated by
      extension_id within the profile).
    - If a Secure Preferences entry lacks a `path` while the `Preferences`
      entry has one, the path-bearing entry is kept (no silent downgrade).
    - Each preference source is isolated: a corrupt `Preferences` is ignored
      while `Secure Preferences` still works, and vice versa.

    Final de-duplication across the directory scan and this collector still
    happens by (browser, profile, extension_id) in the caller (merge_extensions).

    Design constraints (per project rules):
    - It does not rewrite or replace the directory scan.
    - A single bad/invalid entry must not crash the whole collector.
    - No new Chrome-internal model; it reuses BrowserExtension.
    """
    existing = existing or set()
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    localp = Path(local)
    targets = {
        "chrome": localp / "Google" / "Chrome" / "User Data",
        "edge": localp / "Microsoft" / "Edge" / "User Data",
    }
    out: list[BrowserExtension] = []
    for browser, user_data in targets.items():
        if not user_data.is_dir():
            continue
        profiles = [
            p for p in user_data.iterdir()
            if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))
        ]
        for profile in profiles:
            secure = _read_extension_settings(profile / "Secure Preferences")
            regular = _read_extension_settings(profile / "Preferences")
            # Combine both sources keyed by extension_id. `Preferences` is the
            # base; `Secure Preferences` overrides, but a path-bearing entry is
            # never downgraded to one that lacks a path.
            combined: dict = {}
            for ext_id, entry in regular.items():
                if isinstance(entry, dict):
                    combined[ext_id] = entry
            for ext_id, entry in secure.items():
                if not isinstance(entry, dict):
                    continue
                cur = combined.get(ext_id)
                if cur is None or entry.get("path"):
                    combined[ext_id] = entry
                # else: secure entry has no path -> keep the existing (possibly
                # path-bearing) regular entry.
            for ext_id, entry in combined.items():
                if (browser, profile.name, ext_id) in existing:
                    continue
                ext = _emit_unpacked(browser, profile.name, ext_id, entry)
                if ext is not None:
                    out.append(ext)
    return out


def merge_extensions(dir_exts: list[BrowserExtension],
                    unpacked_exts: list[BrowserExtension]) -> list[BrowserExtension]:
    """Combine directory and unpacked results, de-duplicating by
    (browser, profile, extension_id). Directory entries win on collision."""
    seen: set[tuple[str, str, str]] = set()
    merged: list[BrowserExtension] = []
    for e in list(dir_exts) + list(unpacked_exts):
        key = (e.browser, e.profile, e.extension_id)
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)
    return merged
