from __future__ import annotations

from typing import Any


def _esc(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_snapshot(snapshot: dict[str, Any]) -> str:
    lines = [
        "# NativeBridgeGuard Report",
        "",
        f"- Host: `{_esc(snapshot.get('host',''))}`",
        f"- Created: `{_esc(snapshot.get('created_at',''))}`",
        f"- Schema: `{_esc(snapshot.get('schema_version',''))}`",
        "",
        "## Summary",
        "",
        f"- Installed extension records: **{len(snapshot.get('extensions', []))}**",
        f"- Native host registrations: **{len(snapshot.get('registrations', []))}**",
        f"- Effective trust paths: **{len(snapshot.get('trust_paths', []))}**",
        f"- Findings: **{len(snapshot.get('findings', []))}**",
        "",
    ]
    errors = snapshot.get("collection_errors") or []
    if errors:
        lines += [
            "## Collection Health",
            "",
            "**WARNING:** one or more collectors failed. A lack of findings below does "
            "NOT mean the host is clean — it may mean collection was incomplete.",
            "",
        ]
        for e in errors:
            lines.append(f"- `{_esc(e)}`")
        lines.append("")
    lines += [
        "## Effective Trust Paths",
        "",
    ]
    for p in snapshot.get("trust_paths", []):
        reg = p.get("effective_registration", {})
        man = p.get("manifest") or {}
        binary = p.get("binary") or {}
        lines += [
            f"### {_esc(p.get('browser'))} / `{_esc(p.get('host_name'))}`",
            "",
            "```text",
            f"Browser: {_esc(p.get('browser'))}",
            f"  -> Host: {_esc(p.get('host_name'))}",
            f"     -> Effective registry: {_esc(reg.get('registry_key'))}",
            f"        -> Manifest: {_esc(man.get('manifest_path'))}",
            f"           -> Binary: {_esc(binary.get('path'))}",
            "```",
            "",
            f"- Policy status: **{_esc(p.get('policy_status'))}** {_esc(p.get('policy_reason') or '')}",
            f"- Allowed extension IDs: `{', '.join(p.get('allowed_extension_ids', [])) or '(none)'}`",
            f"- Installed allowed extensions: `{', '.join(e.get('name','') for e in p.get('installed_allowed_extensions', [])) or '(none)'}`",
            f"- Missing allowed extension IDs: `{', '.join(p.get('missing_allowed_extension_ids', [])) or '(none)'}`",
            f"- SHA256: `{_esc(binary.get('sha256') or '')}`",
            f"- Signature: `{_esc(binary.get('signature_status') or '')}` / `{_esc(binary.get('signer') or '')}`",
            f"- Owner: `{_esc(binary.get('owner') or '')}`",
            f"- Current-user writable hint: `{_esc(binary.get('current_user_writable_hint'))}`",
            "",
        ]
    lines += ["## Findings", ""]
    if not snapshot.get("findings"):
        lines.append("No rule-based findings were generated.")
    for f in snapshot.get("findings", []):
        lines += [
            f"### [{_esc(f.get('severity','')).upper()}] {_esc(f.get('rule_id'))} — {_esc(f.get('title'))}",
            "",
            f"Trust path: `{_esc(f.get('trust_key'))}`",
            "",
            "Evidence:",
        ]
        for e in f.get("evidence", []):
            lines.append(f"- `{_esc(e)}`")
        lines += ["", _esc(f.get("interpretation", "")), ""]
    lines += [
        "## Interpretation Boundary",
        "",
        "NativeBridgeGuard reports trust evidence and configuration drift. A finding is not a malware verdict or proof of exploitation; high-attention combinations should be manually verified.",
        "",
    ]
    return "\n".join(lines)


def render_events_md(events: list[dict[str, Any]]) -> str:
    """Human-readable presentation of monitor events (NDJSON is the machine interface)."""
    lines = ["# NativeBridgeGuard Trust-Drift Alert", ""]
    if not events:
        lines.append("No new trust-drift events in this cycle.")
        return "\n".join(lines)
    for e in events:
        lines += [
            f"## [{_esc(e.get('severity', '')).upper()}] {_esc(e.get('event_type'))}",
            "",
            f"- Timestamp: `{_esc(e.get('timestamp'))}`",
            f"- Trust path: `{_esc(e.get('trust_key'))}`",
            f"- Summary: {_esc(e.get('summary'))}",
        ]
        if e.get("before") is not None:
            lines.append(f"- Before: `{_esc(e.get('before'))}`")
        if e.get("after") is not None:
            lines.append(f"- After: `{_esc(e.get('after'))}`")
        for ev in e.get("evidence", []):
            lines.append(f"- Evidence: `{_esc(ev)}`")
        lines.append("")
    return "\n".join(lines)


def render_diff(changes: list[dict[str, Any]]) -> str:
    lines = ["# NativeBridgeGuard Trust Drift Report", ""]
    if not changes:
        lines.append("No semantic trust-path changes detected.")
        return "\n".join(lines)
    for c in changes:
        lines += [
            f"## [{_esc(c.get('severity','')).upper()}] {_esc(c.get('type'))}",
            "",
            f"- Trust path: `{_esc(c.get('key'))}`",
            f"- Summary: {_esc(c.get('summary'))}",
        ]
        for k, v in c.items():
            if k in {"severity", "type", "key", "summary"}:
                continue
            lines.append(f"- {_esc(k)}: `{_esc(v)}`")
        lines.append("")
    return "\n".join(lines)
