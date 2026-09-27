# Acceptance Summary — NativeBridgeGuard v0.1.5

**Validated on: Windows + Chrome/Edge.**

This document is a sanitized record of the v0.1.5 acceptance run. Raw,
machine-specific logs (absolute profile paths, host names, user names,
unrelated installed software) are deliberately **not** reproduced here; they
stay outside the repository. Only lab-controlled identifiers and semantic
results are retained.

- Version: v0.1.5
- Platform: Windows, non-administrator user
- Browsers: Chrome and Edge, both installed and both exercised
- Automated tests: **42 passing** (`py -m unittest discover -s tests`)
- Acceptance commits: `36c0b37` (Secure Preferences collector fix),
  `501d192` (Task Scheduler install script fix)

---

## Validated capabilities

- [x] **Live scan** — a real Windows machine scan completes with
      `collection_errors: 0` and produces a populated snapshot.
- [x] **Load-unpacked extension discovery** — locally loaded (unpacked) lab
      extensions are discovered from real browser state, not only from
      directory-installed extensions.
- [x] **Native Messaging ping/pong** — an end-to-end Native Messaging round
      trip through a registered lab host returns `pong` from the local host.
- [x] **HKLM→HKCU effective registration switch** — a user-scope registration
      shadowing a machine-scope registration is detected as
      `effective_registration_changed`, with **NBG008** raised.
- [x] **trust_surface_expanded** — adding a second authorized extension ID to
      the host manifest produces a `trust_surface_expanded` event naming the
      added ID.
- [x] **same-path binary_identity_changed** — replacing the bytes at an
      unchanged manifest path produces a `binary_identity_changed` event with
      before/after SHA-256, and no spurious path change.
- [x] **cleanup** — every scenario's registry changes were removed afterwards
      and the removal was verified, not assumed.
- [x] **Task Scheduler** — `scripts/install_monitor_task.ps1` registers a task
      whose action is `-m nativebridgeguard monitor`; a manually invoked run
      exits `0`, writes monitor state, reports no spurious drift, and
      `scripts/uninstall_monitor_task.ps1` removes the task.

---

## Test counts

| Layer | Result |
|---|---|
| Automated unit tests | 42 passed |
| Real Windows scenarios (A / B / C) | 3 / 3 passed |
| Task Scheduler install → run → uninstall | passed (after fix `501d192`) |

## Scenario overview

| Scenario | What changes | Expected semantic event | Result |
|---|---|---|---|
| A — user-level trust shadowing | HKCU registration shadows an existing HKLM registration of the same host | `effective_registration_changed` + NBG008 | PASS |
| B — authorization surface expansion | host manifest gains a second authorized extension ID | `trust_surface_expanded` | PASS |
| C — same-path binary replacement | bytes at the same launcher path are replaced | `binary_identity_changed` | PASS |

Details: [scenario_a.md](scenario_a.md), [scenario_b.md](scenario_b.md),
[scenario_c.md](scenario_c.md).

---

## Lab identifiers retained (non-sensitive, by design)

| Item | Value |
|---|---|
| Native Messaging host name | `com.nativebridgeguard.lab` |
| Lab Extension A ID | `<LAB_EXTENSION_A_ID>` |
| Lab Extension B ID | `<LAB_EXTENSION_B_ID>` |
| Lab launcher / manifest paths | `lab/runtime/...` (repository-relative) |
| Lab roles | `role=machine` (HKLM), `role=user` (HKCU) |
| Lab markers | `marker=A`, `marker=B` |

## What is deliberately absent from this record

- Windows user name, host name, and domain.
- Absolute user-profile paths.
- Unrelated installed software and unrelated third-party extension IDs that
  happened to be present on the test machine.
- Raw machine-wide scan dumps.

## Known limits carried by this acceptance

See [debugging_cases.md](debugging_cases.md) and the README
"Known limitations" section. In particular: the writable hint is an ACL
heuristic, not a Windows Effective Access / AuthZ computation, and the monitor
is schedule-driven rather than a real-time watcher.
