# Adversarial Validation Lab

This lab exists only to verify NativeBridgeGuard's trust model on **your own**
Windows machine. Everything stays under the single host name
`com.nativebridgeguard.lab` and the git-ignored `lab/runtime/` directory. No
real third-party Native Messaging host is touched, no command execution,
credential access, persistence, or remote contact is involved.

Every lab host is harmless: it reads a framed Native Messaging JSON message on
stdin and replies with a framed `pong` object that carries a `role`
(`machine`/`user`/`lab-c`), a `version`, and a `marker` (`A`/`B`). The launcher
`.bat` files set `role`/`marker` via environment variables. Scenario C reuses
that real launcher mechanism: the manifest points at the `.bat` (the exact path
Chromium executes), and only the launcher's `MARKER` env value differs between
states, so its bytes — and therefore its SHA-256 — change while ping/pong
semantics stay identical.

> The **Result** field of each scenario is intentionally left as `PENDING`. It is
> filled with `PASS` only after the steps are executed on a real Windows host
> with Chrome/Edge and the loaded lab extension. Do not pre-write PASS.

## Setup

```powershell
# 1. Prepare on-disk lab artifacts (no registry, no admin).
powershell -File lab\scripts\setup_lab.ps1

# 2. Load lab/extension_a/ and lab/extension_b/ as two unpacked extensions in
#    Chrome/Edge and copy their IDs. Use extension_a's ID as -ExtensionId and
#    extension_b's ID as -AddExtensionId (Scenario B widens authorization from
#    A to also include B).
```

Each scenario is self-contained: `*_apply.ps1` creates only its own
`com.nativebridgeguard.lab` registry entry and `lab/runtime` files; `*_cleanup.ps1`
removes exactly those. Run cleanup between scenarios. Scenario A writes HKLM and
therefore requires an **elevated** PowerShell; B and C use HKCU and need no
admin.

---

## Scenario A — User-Level Trust Shadowing

- **Threat assumption:** an unprivileged user (or low-privilege code running as
  the user) adds a user-scope Native Messaging registration that overrides a
  legitimate machine-scope registration for the same host name, redirecting the
  effective trust path.
- **Precondition:** Windows + Chrome/Edge; `setup_lab.ps1` already run; elevated
  PowerShell for the baseline phase (HKLM write).
- **Phase 1 — Baseline (elevated):** establishes the machine-level (HKLM) lab
  host A only and removes any pre-existing user shadow, so HKLM is authoritative.
  Effective host = A (`role=machine`).
  ```powershell
  powershell -File lab\scripts\scenario_shadow_apply.ps1 -Baseline -ExtensionId <id>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-a   # baseline scan
  ```
- **Phase 2 — Shadow (normal, no admin):** requires the HKLM baseline to already
  exist (errors otherwise), then registers the user-level (HKCU) lab host B which
  shadows it. HKLM is left untouched. Because the resolver prefers HKCU, the
  effective host becomes B (`role=user`).
  ```powershell
  powershell -File lab\scripts\scenario_shadow_apply.ps1 -ExtensionId <id>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-a   # drift scan
  ```
- **Expected browser behaviour:** after Phase 2, if the lab extension is loaded
  and you click its action, the native host replies with `pong` where
  `role == "user"` (proving the browser actually used the HKCU-registered host B,
  not the HKLM host A).
- **Expected NBG detection:** **NBG008** (user-level registration shadows a
  machine-level one of the same host name) during Phase 2, and a monitor
  `effective_registration_changed` event when Phase 2 is compared to the Phase 1
  baseline.
- **Evidence:** `events.ndjson` (via `monitor`) contains
  `effective_registration_changed`; the drift report shows effective registration
  moved from HKLM to HKCU for the same host name.
- **Cleanup:**
  ```powershell
  powershell -File lab\scripts\scenario_shadow_cleanup.ps1   # elevated
  ```
- **Result:** `PENDING — execute on a real Windows host.`

---

## Scenario B — Authorization Surface Expansion

- **Threat assumption:** a host manifest's `allowed_origins` is widened to
  authorize an additional extension ID, expanding what can drive the native host.
- **Precondition:** Windows + Chrome/Edge; `setup_lab.ps1` run; no admin needed
  (HKCU). Load the two real lab extensions `lab/extension_a/` (Extension A,
  `<idA>`) and `lab/extension_b/` (Extension B, `<idB>`) as unpacked extensions.
- **Baseline (step 1):** host authorizes Extension A only.
  ```powershell
  powershell -File lab\scripts\scenario_origin_expand_apply.ps1 -Baseline -ExtensionId <idA> -AddExtensionId <idB>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-b   # baseline scan
  ```
- **Action (step 2):** host now also authorizes Extension B.
  ```powershell
  powershell -File lab\scripts\scenario_origin_expand_apply.ps1 -ExtensionId <idA> -AddExtensionId <idB>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-b   # drift scan
  ```
- **Expected browser behaviour:** before the change, Extension B cannot reach
  the host (not in `allowed_origins`); after the change, Extension B can send a
  ping and receive a pong.
- **Expected NBG detection:** a `trust_surface_expanded` event whose evidence
  lists the newly added extension ID(s). (`trust_path_added` also appears on the
  first registration.)
- **Evidence:** `events.ndjson` line with `event_type=trust_surface_expanded` and
  `evidence` containing `added_extension_ids=[...]`.
- **Cleanup:**
  ```powershell
  powershell -File lab\scripts\scenario_origin_expand_cleanup.ps1
  ```
- **Result:** `PENDING — execute on a real Windows host.`

---

## Scenario C — Native Host Binary Replacement

- **Threat assumption:** the file a trusted native-message relationship executes
  is replaced with different bytes (same harmless semantics here), changing its
  hash without changing the registered path.
- **Precondition:** Windows + Chrome/Edge; `setup_lab.ps1` run; no admin needed
  (HKCU).
- **Baseline (step 1):** launcher (`lab_host_c.bat`, the path Chromium
  executes) sets `MARKER=A` (SHA-256 A). Same path, harmless ping/pong.
  ```powershell
  powershell -File lab\scripts\scenario_binary_replace_apply.ps1 -ExtensionId <id>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-c   # baseline scan
  ```
- **Action (step 2):** the launcher at the *same* path now sets `MARKER=B`
  (different bytes, SHA-256 B); the underlying host program is unchanged.
  ```powershell
  powershell -File lab\scripts\scenario_binary_replace_apply.ps1 -Replaced -ExtensionId <id>
  nativebridgeguard monitor --state-dir C:\lab\nbg-state-c   # drift scan
  ```
- **Expected browser behaviour:** the host still answers ping with pong (semantics
  unchanged); only the launcher's bytes/hash differ at the path the browser uses.
- **Expected NBG detection:** a `binary_identity_changed` event whose before/after
  carry the two SHA-256 values. If the lab file lives in a user-writable,
  unsigned location, NBG005/NBG006 may also appear — they are not hard-coded.
- **Evidence:** `events.ndjson` line with `event_type=binary_identity_changed`
  and `before`/`after` SHA-256 values.
- **Cleanup:**
  ```powershell
  powershell -File lab\scripts\scenario_binary_replace_cleanup.ps1
  ```
- **Result:** `PENDING — execute on a real Windows host.`

---

## Full cleanup

```powershell
powershell -File lab\scripts\cleanup_lab.ps1
```

Removes the `lab/runtime` directory and all `com.nativebridgeguard.lab`
registry keys (HKCU always; HKLM when run elevated).
