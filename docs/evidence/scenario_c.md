# Scenario C — Same-Path Binary Identity Replacement

**Result: PASS**

Sanitized record. Repository-relative lab paths are used; registry scopes,
semantic event names, and before/after hashes are preserved.

## Goal

Prove the hardest case for a path-based inventory: the host path does **not**
change, the registration does **not** change, and the authorization set does
**not** change — only the *bytes* behind the unchanged path are replaced. The
tool must still report this as a trust change, because a silent in-place
replacement of a native host is exactly the operation that turns a trusted host
into an untrusted one.

## Setup

| Item | Value |
|---|---|
| Host name | `com.nativebridgeguard.lab` |
| Scope | `HKCU` throughout (no elevation required) |
| Launcher path | `lab/runtime/lab_host_c.bat` (never changed) |
| Lab Extension A | `<LAB_EXTENSION_A_ID>` (authorized throughout) |

## Baseline

- Single `HKCU` registration pointing at a manifest whose `path` is
  `lab/runtime/lab_host_c.bat`.
- Baseline verification: binary `lab/runtime/lab_host_c.bat`,
  `sha256=cd09e3d8e82a…`, `collection_errors: 0`, **no NBG008**.
- The launcher carries a marker (`marker=A`) that it echoes back in its reply,
  so the identity of the *executing* binary can be confirmed independently by
  the browser.

**Browser proof (baseline):** the host replied with **`marker=A`**, matching the
baseline hash.

## Action

The file at the **same** path `lab/runtime/lab_host_c.bat` was overwritten with
a byte-different copy differing only in the marker it reports (`marker=B`). The
registry registration, the manifest path, the launcher path, and the
authorization set were all left untouched.

## Detection

The second monitor cycle reported `drift_detected` with **2 new events** (one
per browser family):

| Field | Value |
|---|---|
| `event_type` | `binary_identity_changed` |
| `severity` | medium |
| `trust_key` | `chrome:com.nativebridgeguard.lab` and `edge:com.nativebridgeguard.lab` |
| `before` | `cd09e3d8e82ad3fef3542ae418d9aee2ab300d0a9916ca35f4ad6fc02e644fc4` |
| `after` | `66d9df5ad83809706efb4cbff9b91c5877a754e25f3ca8741f7208b2fb598e58` |

Critically, **no** `binary_path_changed` event was emitted: the path genuinely
did not move. The drift was detected purely from the binary's cryptographic
identity, which is the property this scenario targets. No `NBG008` (single
`HKCU`, no `HKLM` counterpart) and no `trust_surface_expanded` (authorization
set unchanged) — the tool attributed the change to the correct dimension.

**Browser proof (after replacement):** the host replied with **`marker=B`**,
confirming that the replaced bytes are what actually executed, matching the
`after` hash.

## Cleanup

The `HKCU` lab registration was removed and the removal was **verified** by
re-reading the registry.
