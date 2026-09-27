from __future__ import annotations

from collections import defaultdict

from .models import BrowserPolicy, RegistryHost


# Effective lookup order used by v0.1. The table is explicit so it can be
# reviewed/changed without rewriting collector logic.
EDGE_ORDER = [
    ("HKCU", "edge", None),
    ("HKCU", "chromium", None),
    ("HKCU", "chrome", None),
    ("HKLM", "edge", "32"),
    ("HKLM", "chromium", "32"),
    ("HKLM", "chrome", "32"),
    ("HKLM", "edge", "64"),
    ("HKLM", "chromium", "64"),
    ("HKLM", "chrome", "64"),
]
CHROME_ORDER = [
    ("HKCU", "chrome", None),
    ("HKLM", "chrome", "32"),
    ("HKLM", "chrome", "64"),
]


def _rank(browser: str, reg: RegistryHost) -> int:
    order = EDGE_ORDER if browser == "edge" else CHROME_ORDER
    for i, (scope, family, view) in enumerate(order):
        if reg.scope == scope and reg.browser_family == family and (view is None or reg.view == view):
            return i
    return 999


def resolve_effective(browser: str, registrations: list[RegistryHost]) -> dict[str, tuple[RegistryHost, list[RegistryHost]]]:
    groups: dict[str, list[RegistryHost]] = defaultdict(list)
    for r in registrations:
        if browser == "edge":
            if r.browser_family not in {"edge", "chromium", "chrome"}:
                continue
        elif browser == "chrome":
            if r.browser_family != "chrome":
                continue
        else:
            continue
        groups[r.host_name].append(r)

    out: dict[str, tuple[RegistryHost, list[RegistryHost]]] = {}
    for host, regs in groups.items():
        ranked = sorted(regs, key=lambda x: (_rank(browser, x), x.registry_key))
        if ranked:
            out[host] = (ranked[0], ranked[1:])
    return out


def policy_decision(browser: str, host_name: str, scope: str, policies: list[BrowserPolicy]) -> tuple[str, str | None]:
    policy = next((p for p in policies if p.browser == browser), None)
    if not policy:
        return "unknown", "no policy data"
    if scope == "HKCU" and policy.user_level_hosts_enabled is False:
        return "blocked", "user-level native messaging hosts disabled by policy"
    blocked = "*" in policy.blocklist or host_name in policy.blocklist
    explicitly_allowed = "*" in policy.allowlist or host_name in policy.allowlist
    if blocked and not explicitly_allowed:
        return "blocked", "host matched NativeMessagingBlocklist"
    if blocked and explicitly_allowed:
        return "allowed", "allowlist exception overrides blocklist match"
    return "allowed", None
