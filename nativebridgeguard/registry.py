from __future__ import annotations

import os
from typing import Iterable

from .models import BrowserPolicy, RegistryHost

try:
    import winreg  # type: ignore
except ImportError:  # non-Windows development/test environment
    winreg = None


HOST_ROOTS = {
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "chromium": r"Software\Chromium\NativeMessagingHosts",
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
}

POLICY_ROOTS = {
    "edge": r"Software\Policies\Microsoft\Edge",
    "chrome": r"Software\Policies\Google\Chrome",
}


def _enum_subkeys(hive, path: str, access: int) -> Iterable[str]:
    try:
        key = winreg.OpenKey(hive, path, 0, access)
    except OSError:
        return []
    names = []
    i = 0
    while True:
        try:
            names.append(winreg.EnumKey(key, i))
            i += 1
        except OSError:
            break
    winreg.CloseKey(key)
    return names


def _read_default(hive, path: str, access: int) -> str | None:
    try:
        key = winreg.OpenKey(hive, path, 0, access)
        value, _ = winreg.QueryValueEx(key, None)
        winreg.CloseKey(key)
        return str(value)
    except OSError:
        return None


def collect_registrations() -> list[RegistryHost]:
    if os.name != "nt" or winreg is None:
        return []
    out: list[RegistryHost] = []
    specs = [
        ("HKCU", winreg.HKEY_CURRENT_USER, "64", winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        ("HKCU", winreg.HKEY_CURRENT_USER, "32", winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, "32", winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, "64", winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
    ]
    seen: set[tuple] = set()
    for family, root in HOST_ROOTS.items():
        for scope, hive, view, access in specs:
            for host_name in _enum_subkeys(hive, root, access):
                key_path = root + "\\" + host_name
                manifest = _read_default(hive, key_path, access)
                if not manifest:
                    continue
                sig = (family, scope, host_name, os.path.normcase(os.path.expandvars(manifest)))
                if sig in seen:
                    continue
                seen.add(sig)
                out.append(RegistryHost(
                    browser_family=family,
                    scope=scope,
                    view=view,
                    host_name=host_name,
                    registry_key=f"{scope}\\{key_path}",
                    manifest_path=os.path.expandvars(manifest),
                ))
    return out


def _read_list_policy(hive, path: str, subkey: str) -> list[str]:
    values: list[str] = []
    full = path + "\\" + subkey
    try:
        key = winreg.OpenKey(hive, full, 0, winreg.KEY_READ)
    except OSError:
        return values
    i = 0
    while True:
        try:
            _name, value, _typ = winreg.EnumValue(key, i)
            values.append(str(value))
            i += 1
        except OSError:
            break
    winreg.CloseKey(key)
    return values


def _read_dword(hive, path: str, name: str) -> bool | None:
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return bool(value)
    except OSError:
        return None


def collect_policies() -> list[BrowserPolicy]:
    if os.name != "nt" or winreg is None:
        return []
    out: list[BrowserPolicy] = []
    for browser, path in POLICY_ROOTS.items():
        allow: list[str] = []
        block: list[str] = []
        user_level: bool | None = None
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            allow.extend(_read_list_policy(hive, path, "NativeMessagingAllowlist"))
            block.extend(_read_list_policy(hive, path, "NativeMessagingBlocklist"))
            v = _read_dword(hive, path, "NativeMessagingUserLevelHosts")
            if v is not None:
                user_level = v
        out.append(BrowserPolicy(
            browser=browser,
            allowlist=sorted(set(allow)),
            blocklist=sorted(set(block)),
            user_level_hosts_enabled=user_level,
        ))
    return out
