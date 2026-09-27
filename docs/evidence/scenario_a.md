# Scenario A — User-Level Trust Shadowing (HKLM → HKCU)

**Result: PASS**

Sanitized record. Machine-specific absolute paths and user names are replaced
with repository-relative lab paths; registry scopes and semantic event names are
preserved verbatim.

## Goal

Prove that NativeBridgeGuard resolves the *effective* registration when two
scopes register the same Native Messaging host name, and that a user-scope
registration silently taking precedence over a machine-scope one is reported as
semantic drift rather than passing unnoticed.

## Setup

| Item | Value |
|---|---|
| Host name | `com.nativebridgeguard.lab` |
| Browser families observed | `chrome`, `edge` |
| Lab Extension A | `<LAB_EXTENSION_A_ID>` |
| Baseline manifest | `lab/runtime/manifest_a.json` |
| Baseline launcher | `lab/runtime/host_a.bat` |
| Shadow manifest | `lab/runtime/manifest_b.json` |
| Shadow launcher | `lab/runtime/host_b.bat` |

Baseline and shadow launchers differ only in the role/marker they report; both
are harmless ping/pong hosts.

## Baseline

- A **machine-scope** registration (`HKLM\Software\...\NativeMessagingHosts\com.nativebridgeguard.lab`)
  pointed at `lab/runtime/manifest_a.json`, which resolved to
  `lab/runtime/host_a.bat`.
- Baseline verification: effective scope `HKLM`, launcher `host_a.bat`,
  Extension A authorized **and** installed, `collection_errors: 0`,
  **no NBG008** (nothing was shadowing anything yet).
- Browser proof: the host answered `pong` with **`role=machine`**, confirming
  the machine-scope registration was the one the browser actually used.

## Action

A **user-scope** registration (`HKCU\Software\...\NativeMessagingHosts\com.nativebridgeguard.lab`)
was added for the same host name, pointing at `lab/runtime/manifest_b.json` →
`lab/runtime/host_b.bat`. No machine-scope entry was deleted. Writing HKCU does
not require elevation; the baseline HKLM write did, and was performed in an
elevated session.

## Detection

The second monitor cycle reported `drift_detected` with **6 new events**
(3 event types × 2 browser families):

| Event type | Severity | Before | After |
|---|---|---|---|
| `effective_registration_changed` | high | `HKLM\...\NativeMessagingHosts\com.nativebridgeguard.lab` → `lab/runtime/manifest_a.json` | `HKCU\...\NativeMessagingHosts\com.nativebridgeguard.lab` → `lab/runtime/manifest_b.json` |
| `binary_path_changed` | high | `lab/runtime/host_a.bat` | `lab/runtime/host_b.bat` |
| `binary_identity_changed` | medium | `0e5617566901ddad508875cb998720b0fbb7e92b8a7643ce55e68e001617c467` | `15501600a7f9ce517b98e1aec37b092dd85d2635a553c7bad60347cef8e8d8bf` |

**Finding rule:** **NBG008** (user-level registration shadowing a machine-level
registration of the same host name) was raised on the lab trust path for both
`chrome` and `edge`. It was absent at baseline and appeared only after the
shadow was installed — i.e. the rule fired on the real cause, not incidentally.

**Browser proof:** after the shadow, the same host name answered `pong` with
**`role=user`**. The browser independently confirms what the tool reported: the
user-scope registration won.

## Cross-family note (expected, not a defect)

The `edge` trust path reported `missing_allowed=[<Lab Extension A>]` at
baseline. Extension A was loaded in Chrome only; because the resolver's Edge
order also consults the Chrome registration family, the same HKLM registration
appears under both families. This is expected resolution behaviour, and the
verification script treats it as such rather than as a failure.

## Cleanup

Both registrations (HKCU host B and HKLM host A) were removed by the lab
cleanup script, and the removal was **verified** by re-reading the registry —
not assumed. The HKLM removal required an elevated session.
