from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from .models import BinaryEvidence
from .util import sha256_file, under_path


# ACE lines from Get-Acl AccessToString look like:
#   BUILTIN\Users Allow  ReadAndExecute, Synchronize
#   NT AUTHORITY\SYSTEM Allow  FullControl
# Identity references may contain spaces (e.g. "NT AUTHORITY\SYSTEM"), so we split
# on the standalone Allow/Deny token rather than on arbitrary whitespace.
_ACE_RE = re.compile(r"^(?P<identity>.*?)\s+(?P<type>Allow|Deny)\s+(?P<rights>.*)$")

# Broad, unprivileged principals whose Allow write rights would make a binary
# tamperable by an ordinary logged-in user.
_BROAD_PRINCIPALS = {"users", "authenticated users", "everyone"}

# Rights tokens that imply the ability to modify/replace the object.
_WRITE_RIGHTS = ("fullcontrol", "modify")


def _rights_grant_write(rights: str) -> bool:
    if not rights:
        return False
    for tok in rights.split(","):
        t = tok.strip().lower()
        if not t:
            continue
        # "write" also catches granular rights such as WriteData / WriteExtendedAttributes.
        if t in _WRITE_RIGHTS or "write" in t:
            return True
    return False


def _is_relevant_principal(identity: str, username: str | None, userdomain: str | None) -> bool:
    if not identity:
        return False
    low = identity.strip().lower()
    last = low.split("\\")[-1]
    if last in _BROAD_PRINCIPALS:
        return True
    if username:
        un = username.strip().lower()
        if low == un:
            return True
        if userdomain and low == f"{userdomain.strip().lower()}\\{un}":
            return True
    return False


def _acl_grants_writable(acl_text: str | None, username: str | None, userdomain: str | None):
    """Return (writable_hint, reason).

    Heuristic only: a relevant principal (current user or a broad unprivileged
    group) with an Allow ACE carrying Write/Modify/FullControl is treated as a
    writable signal. Any Deny ACE carrying write rights on a relevant principal
    overrides the Allow (Windows Deny precedence), so it is not ignored.

    This is NOT a full Windows Effective Access / AuthZ calculation: it does not
    resolve group membership, privilege elevation, or inherited-but-disabled ACEs.
    """
    if not acl_text:
        return False, ""
    matched_reasons: list[str] = []
    deny_relevant = False
    for line in acl_text.splitlines():
        m = _ACE_RE.match(line.strip())
        if not m:
            continue
        identity = m.group("identity").strip()
        actype = m.group("type")
        rights = m.group("rights").strip()
        if not _is_relevant_principal(identity, username, userdomain):
            continue
        if actype == "Deny":
            if _rights_grant_write(rights):
                deny_relevant = True
                matched_reasons.append(f"Deny({identity}: {rights})")
            continue
        if _rights_grant_write(rights):
            matched_reasons.append(f"Allow({identity}: {rights})")
    writable = bool(matched_reasons) and not deny_relevant
    return writable, "; ".join(matched_reasons)


def _powershell_json(script: str, target: str) -> dict | None:
    env = os.environ.copy()
    env["NBG_TARGET"] = target
    for exe in ("powershell.exe", "powershell"):
        try:
            cp = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                env=env,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if cp is None or cp.returncode != 0:
            continue
        raw = cp.stdout or b""
        try:
            stdout = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            stdout = ""
        if stdout:
            try:
                return json.loads(stdout)
            except (ValueError, json.JSONDecodeError):
                continue
    return None


def collect_binary_evidence(path: str | None) -> BinaryEvidence | None:
    if not path:
        return None
    p = Path(os.path.expandvars(path)).expanduser()
    exists = p.is_file()
    ev = BinaryEvidence(path=str(p), exists=exists)
    if not exists:
        return ev

    try:
        ev.sha256 = sha256_file(p)
    except OSError:
        pass

    username = os.environ.get("USERNAME")
    userdomain = os.environ.get("USERDOMAIN")
    ev.under_user_profile = under_path(p, os.environ.get("USERPROFILE"))

    sig_script = r'''
$p=$env:NBG_TARGET
$s=Get-AuthenticodeSignature -LiteralPath $p
[pscustomobject]@{
  status=$s.Status.ToString()
  signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null}
} | ConvertTo-Json -Compress
'''
    sig = _powershell_json(sig_script, str(p))
    if sig:
        ev.signature_status = sig.get("status")
        ev.signer = sig.get("signer")

    acl_script = r'''
$p=$env:NBG_TARGET
$a=Get-Acl -LiteralPath $p -ErrorAction SilentlyContinue
$parentAcl=$null
$parent=Split-Path -Parent $p
if($parent -and (Test-Path -LiteralPath $parent)){
  try { $parentAcl=(Get-Acl -LiteralPath $parent -ErrorAction SilentlyContinue).AccessToString } catch { $parentAcl=$null }
}
[pscustomobject]@{
  owner=if($a){$a.Owner}else{$null}
  acl=if($a){$a.AccessToString}else{$null}
  parent_acl=$parentAcl
} | ConvertTo-Json -Compress
'''
    acl = _powershell_json(acl_script, str(p))
    if acl:
        ev.owner = acl.get("owner")
        ev.acl = acl.get("acl")
        ev.parent_acl = acl.get("parent_acl")
        file_w, file_reason = _acl_grants_writable(ev.acl, username, userdomain)
        parent_w, parent_reason = _acl_grants_writable(ev.parent_acl, username, userdomain)
        ev.current_user_writable_hint = file_w or parent_w
        reasons = [r for r in (file_reason, parent_reason) if r]
        if ev.current_user_writable_hint:
            ev.writable_hint_reason = "; ".join(reasons)
        elif ev.acl is not None or ev.parent_acl is not None:
            ev.writable_hint_reason = (
                "No Allow Write/Modify/FullControl ACE for current user or broad principals "
                "(BUILTIN\\Users, Authenticated Users, Everyone); Deny ACEs override where present."
            )
        else:
            ev.writable_hint_reason = None
    return ev
