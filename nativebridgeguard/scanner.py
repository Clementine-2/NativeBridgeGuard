from __future__ import annotations

import platform
from datetime import datetime, timezone

from .extensions import (
    collect_extensions,
    collect_unpacked_extensions,
    merge_extensions,
)
from .manifest import parse_host_manifest
from .models import Snapshot, TrustPath
from .registry import collect_policies, collect_registrations
from .resolver import policy_decision, resolve_effective
from .rules import evaluate
from .util import origin_to_extension_id
from .windows_evidence import collect_binary_evidence


def scan() -> Snapshot:
    collection_errors: list[str] = []
    try:
        extensions = collect_extensions()
    except Exception as exc:  # defensive: a failing collector must not blank the whole scan
        extensions = []
        collection_errors.append(f"collect_extensions: {type(exc).__name__}: {exc}")
    try:
        existing = {(e.browser, e.profile, e.extension_id) for e in extensions}
        unpacked = collect_unpacked_extensions(existing)
        extensions = merge_extensions(extensions, unpacked)
    except Exception as exc:
        # Supplemental unpacked collector failed; keep the directory results.
        collection_errors.append(f"collect_unpacked_extensions: {type(exc).__name__}: {exc}")
    try:
        registrations = collect_registrations()
    except Exception as exc:
        registrations = []
        collection_errors.append(f"collect_registrations: {type(exc).__name__}: {exc}")
    try:
        policies = collect_policies()
    except Exception as exc:
        policies = []
        collection_errors.append(f"collect_policies: {type(exc).__name__}: {exc}")

    trust_paths: list[TrustPath] = []
    findings = []

    for browser in ("chrome", "edge"):
        installed = {e.extension_id: e for e in extensions if e.browser == browser}
        effective = resolve_effective(browser, registrations)
        for host_name, (reg, shadowed) in sorted(effective.items()):
            manifest = parse_host_manifest(reg.manifest_path, host_name)
            ids: list[str] = []
            if manifest:
                for origin in manifest.allowed_origins:
                    ext_id = origin_to_extension_id(origin)
                    if ext_id:
                        ids.append(ext_id)
            ids = sorted(set(ids))
            present = [installed[x] for x in ids if x in installed]
            missing = [x for x in ids if x not in installed]
            binary = collect_binary_evidence(manifest.binary_path if manifest else None)
            policy_status, policy_reason = policy_decision(browser, host_name, reg.scope, policies)
            tp = TrustPath(
                browser=browser,
                host_name=host_name,
                effective_registration=reg,
                shadowed_registrations=shadowed,
                manifest=manifest,
                binary=binary,
                allowed_extension_ids=ids,
                installed_allowed_extensions=present,
                missing_allowed_extension_ids=missing,
                policy_status=policy_status,
                policy_reason=policy_reason,
            )
            trust_paths.append(tp)
            findings.extend(evaluate(tp))

    return Snapshot(
        schema_version=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        host=platform.node(),
        extensions=extensions,
        registrations=registrations,
        policies=policies,
        trust_paths=trust_paths,
        findings=findings,
        collection_errors=collection_errors,
    )
