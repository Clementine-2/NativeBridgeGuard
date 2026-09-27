from __future__ import annotations

from typing import Any


def _paths(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for p in snapshot.get("trust_paths", []):
        out[f"{p.get('browser')}:{p.get('host_name')}"] = p
    return out


def _binary(p: dict[str, Any]) -> dict[str, Any]:
    return p.get("binary") or {}


def semantic_diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    a = _paths(before)
    b = _paths(after)
    changes: list[dict[str, Any]] = []

    for key in sorted(set(b) - set(a)):
        changes.append({"type":"trust_path_added","key":key,"severity":"medium","summary":"New effective native messaging trust path appeared."})
    for key in sorted(set(a) - set(b)):
        changes.append({"type":"trust_path_removed","key":key,"severity":"info","summary":"Effective native messaging trust path disappeared."})

    for key in sorted(set(a) & set(b)):
        old, new = a[key], b[key]
        old_reg = old.get("effective_registration", {})
        new_reg = new.get("effective_registration", {})
        if (old_reg.get("registry_key"), old_reg.get("manifest_path")) != (new_reg.get("registry_key"), new_reg.get("manifest_path")):
            changes.append({
                "type":"effective_registration_changed","key":key,"severity":"high",
                "summary":"Effective host registration changed.",
                "before":{"registry_key":old_reg.get("registry_key"),"manifest_path":old_reg.get("manifest_path")},
                "after":{"registry_key":new_reg.get("registry_key"),"manifest_path":new_reg.get("manifest_path")},
            })

        old_ids = set(old.get("allowed_extension_ids", []))
        new_ids = set(new.get("allowed_extension_ids", []))
        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        if added:
            changes.append({"type":"trust_surface_expanded","key":key,"severity":"medium","summary":"Native host authorization expanded to additional extension IDs.","added_extension_ids":added})
        if removed:
            changes.append({"type":"trust_surface_reduced","key":key,"severity":"info","summary":"Native host authorization removed extension IDs.","removed_extension_ids":removed})

        ob, nb = _binary(old), _binary(new)
        if ob.get("path") != nb.get("path"):
            changes.append({"type":"binary_path_changed","key":key,"severity":"high","summary":"Native host executable path changed.","before":ob.get("path"),"after":nb.get("path")})
        if ob.get("sha256") and nb.get("sha256") and ob.get("sha256") != nb.get("sha256"):
            changes.append({"type":"binary_identity_changed","key":key,"severity":"medium","summary":"Native host binary hash changed.","before":ob.get("sha256"),"after":nb.get("sha256")})
        if (ob.get("signature_status"), ob.get("signer")) != (nb.get("signature_status"), nb.get("signer")):
            changes.append({"type":"binary_signature_changed","key":key,"severity":"high","summary":"Native host signing evidence changed.","before":{"status":ob.get("signature_status"),"signer":ob.get("signer")},"after":{"status":nb.get("signature_status"),"signer":nb.get("signer")}})
        if (old.get("policy_status"), old.get("policy_reason")) != (new.get("policy_status"), new.get("policy_reason")):
            changes.append({"type":"policy_effect_changed","key":key,"severity":"medium","summary":"Browser policy changed the effective trust state.","before":{"status":old.get("policy_status"),"reason":old.get("policy_reason")},"after":{"status":new.get("policy_status"),"reason":new.get("policy_reason")}})
    return changes
