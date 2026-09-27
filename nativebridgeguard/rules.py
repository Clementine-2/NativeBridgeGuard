from __future__ import annotations

import os
from pathlib import Path

from .models import Finding, TrustPath


def _key(tp: TrustPath) -> str:
    return f"{tp.browser}:{tp.host_name}"


def _in_user_profile(path: str | None) -> bool:
    user = os.environ.get("USERPROFILE")
    if not path or not user:
        return False
    try:
        Path(path).resolve().relative_to(Path(user).resolve())
        return True
    except Exception:
        return False


def evaluate(tp: TrustPath) -> list[Finding]:
    out: list[Finding] = []
    key = _key(tp)
    reg = tp.effective_registration

    if tp.manifest is None:
        out.append(Finding(
            "NBG001", "high", "Native host manifest is missing or invalid", key,
            [f"registry={reg.registry_key}", f"manifest={reg.manifest_path}"],
            "The effective registration cannot be resolved to a readable host manifest."
        ))
        return out

    if reg.scope == "HKLM" and _in_user_profile(tp.manifest.manifest_path):
        out.append(Finding(
            "NBG002", "high", "Machine-level registration points into the user profile", key,
            [f"registration_scope={reg.scope}", f"manifest={tp.manifest.manifest_path}"],
            "A machine-level trust relation depends on a lower-trust user-profile path."
        ))

    if tp.binary is None or not tp.binary.exists:
        out.append(Finding(
            "NBG003", "high", "Native host binary is missing", key,
            [f"binary={tp.manifest.binary_path}"],
            "The manifest references a binary that is not present."
        ))
    else:
        if reg.scope == "HKLM" and tp.binary.under_user_profile:
            out.append(Finding(
                "NBG004", "high", "Machine-level host executes a binary under the user profile", key,
                [f"binary={tp.binary.path}"],
                "Machine-level registration combined with a user-profile executable expands tampering risk and should be reviewed."
            ))
        if tp.binary.signature_status and tp.binary.signature_status.lower() != "valid":
            out.append(Finding(
                "NBG005", "medium", "Native host binary is not validly Authenticode-signed", key,
                [f"signature_status={tp.binary.signature_status}", f"signer={tp.binary.signer}"],
                "Unsigned or invalidly signed binaries are not automatically malicious, but they weaken provenance evidence."
            ))
        if tp.binary.current_user_writable_hint:
            evidence_items = [f"binary={tp.binary.path}", "writable_hint=true"]
            if tp.binary.writable_hint_reason:
                evidence_items.append(f"writable_hint_reason={tp.binary.writable_hint_reason}")
            out.append(Finding(
                "NBG006", "medium",
                "ACL-based writable hint on host binary or parent (heuristic)", key,
                evidence_items,
                "Heuristic only: derived from parsing the DACL (Get-Acl AccessToString) for the current user and "
                "broad unprivileged principals (BUILTIN\\Users, Authenticated Users, Everyone). It flags Allow "
                "Write/Modify/FullControl ACEs and honors Deny ACEs, but it is NOT a full Windows Effective Access / "
                "AuthZ calculation (no group-membership or privilege resolution). Review the ACL evidence before "
                "concluding the binary is replaceable by an unprivileged user."
            ))

    if tp.missing_allowed_extension_ids:
        out.append(Finding(
            "NBG007", "low", "Host authorizes extension IDs that are not currently installed", key,
            ["missing_extensions=" + ",".join(tp.missing_allowed_extension_ids)],
            "The host manifest contains orphaned authorization edges. This can be legitimate after uninstall/upgrade, but should be visible."
        ))

    if reg.scope == "HKCU" and any(r.scope == "HKLM" for r in tp.shadowed_registrations):
        out.append(Finding(
            "NBG008", "medium", "User-level host registration shadows a machine-level registration", key,
            [f"effective={reg.registry_key}"] + [f"shadowed={r.registry_key}" for r in tp.shadowed_registrations if r.scope == "HKLM"],
            "The effective trust path is resolved from user scope while a machine-level registration of the same host name also exists."
        ))

    # NBG101 — user-controlled native host trust path (compound evidence).
    # High-attention *combination*, not a malware verdict: the effective trust
    # relation is resolved from the current user's registry scope, the host
    # binary lives under the user profile, the current user can write/replace
    # it (ACL heuristic), and it is not validly Authenticode-signed. Each alone
    # is common and benign; together they mean an unprivileged user can swap the
    # binary a trusted native-message relationship will execute.
    if (
        reg.scope == "HKCU"
        and tp.binary is not None
        and tp.binary.under_user_profile
        and tp.binary.current_user_writable_hint
        and (tp.binary.signature_status is None or tp.binary.signature_status.lower() != "valid")
    ):
        evidence_items = [
            f"effective_scope={reg.scope}",
            f"binary={tp.binary.path}",
            f"under_user_profile={tp.binary.under_user_profile}",
            f"current_user_writable_hint={tp.binary.current_user_writable_hint}",
            f"signature_status={tp.binary.signature_status}",
        ]
        out.append(Finding(
            "NBG101", "high", "User-controlled native host trust path", key,
            evidence_items,
            "Compound high-attention evidence: a user-scope (HKCU) native-message trust path "
            "resolves to a host binary under the user profile that the current user can write/replace "
            "(ACL heuristic) and is not validly Authenticode-signed. This does not prove compromise; "
            "it marks a trust path an unprivileged user can tamper with, and should be manually reviewed."
        ))

    if tp.policy_status == "blocked":
        out.append(Finding(
            "NBG009", "info", "Effective host registration is blocked by browser policy", key,
            [f"reason={tp.policy_reason}"],
            "The configured relationship exists, but enterprise browser policy prevents it from being active."
        ))
    return out
