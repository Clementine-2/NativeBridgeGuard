# Scenario B — Authorization Surface Expansion

**Result: PASS**

Sanitized record. Repository-relative lab paths are used; registry scopes,
extension IDs, and semantic event names are preserved.

## Goal

Prove that widening *who is allowed to talk to* an existing Native Messaging
host is reported as an authorization-surface change, even when the host binary
itself does not move and no re-registration occurs.

## Setup

| Item | Value |
|---|---|
| Host name | `com.nativebridgeguard.lab` |
| Scope | `HKCU` throughout (no elevation required) |
| Lab Extension A | `<LAB_EXTENSION_A_ID>` |
| Lab Extension B | `<LAB_EXTENSION_B_ID>` |
| Launcher | unchanged for the whole scenario |

## Baseline

- Single `HKCU` registration of the lab host.
- Host manifest authorized **only** Extension A.
- Baseline verification: `allowed=[<Lab Extension A>]`, Extension B **not**
  authorized, `collection_errors: 0`, **no NBG008** (a single user-scope
  registration with no machine-scope entry to shadow).
- Static findings present at baseline were `NBG005` and `NBG006` (plus
  `NBG007` on the `edge` family, where Extension A is not installed) — these
  describe the lab host's own properties and are unrelated to this scenario's
  change.

**Browser proof (baseline):** Extension A received `pong`. Extension B was
rejected by the browser with *"Access to the specified native messaging host is
forbidden"* — the browser enforcing `allowed_origins`, confirming B was genuinely
unauthorized rather than the tool merely failing to see it.

## Action

The host manifest's `allowed_origins` was extended to authorize Extension B
**in addition to** A. The registration, the manifest path, and the launcher path
were all left untouched. Only the authorized-ID set changed.

## Detection

The second monitor cycle reported `drift_detected` with **2 new events** (one
per browser family):

| Field | Value |
|---|---|
| `event_type` | `trust_surface_expanded` |
| `severity` | medium |
| `trust_key` | `chrome:com.nativebridgeguard.lab` and `edge:com.nativebridgeguard.lab` |
| `summary` | Native host authorization expanded to additional extension IDs |
| `evidence` | `added_extension_ids=['<LAB_EXTENSION_B_ID>']` |

No `NBG008`: the registration remained a single `HKCU` entry with no `HKLM`
counterpart, so the shadowing rule correctly did not fire. The expansion was
detected as an authorization-surface change, not as a registration change —
which is the distinction this scenario exists to demonstrate.

**Browser proof (after expansion):** Extension B now received `pong`. The
browser's own authorization decision changed in lockstep with the reported
event.

## Cleanup

The `HKCU` lab registration was removed and the removal was **verified** by
re-reading the registry.
