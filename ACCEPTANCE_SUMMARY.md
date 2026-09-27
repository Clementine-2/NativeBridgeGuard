# Acceptance Summary

Public summary of what was **actually verified** for NativeBridgeGuard v0.1.5.

This document is deliberately generalized. It records validation categories and
outcomes only — it does **not** contain host names, account names, real profile
paths, extension identifiers, or raw machine evidence. Those stay off-repo.
Detail lives in [`docs/evidence/`](docs/evidence/), which is written to the same
sanitization standard.

## Validation environment (categories only)

| Aspect | Value |
|---|---|
| Operating system | Windows |
| Privilege level | standard user-level Windows account (not elevated, except one lab setup step that requires it) |
| Browsers | Chrome **and** Edge, both installed and both exercised |
| Test host | a single Windows test host |

The exact host identity is intentionally not recorded here.

## Automated

| Item | Result |
|---|---|
| Unit test suite | **42 passing** |
| Whitespace / conflict-marker check | clean |

Test coverage includes registry resolution, manifest parsing, extension
collection (directory-installed and locally loaded), binary and ACL evidence,
static rules, semantic diffing, the monitor state machine, and compound
correlation.

## Blocks

| Block | Scope | Result |
|---|---|---|
| **Block 0** — preflight | clean tree, tests green, CLI subcommands present, lab generates its runtime, both example extension manifests valid | **PASS** |
| **Block 1** — locally loaded extension collection | live discovery of unpacked lab extensions from real browser state | **PASS** (after the `Secure Preferences` collector fix) |

## End-to-end Native Messaging

| Item | Result |
|---|---|
| Native Messaging ping/pong through a registered lab host | **PASS** — the browser received a real reply from the local host |
| Authorization enforcement observed in-browser | **PASS** — an unauthorized extension was rejected by the browser, confirming `allowed_origins` really was enforced |

## Scenarios

Each scenario used an independent monitor state directory and followed the same
cycle: baseline → action → detection → browser confirmation → cleanup, with
cleanup verified rather than assumed.

| Scenario | What was changed | Detected event | Result |
|---|---|---|---|
| **A** — user-level trust shadowing | a user-scope (`HKCU`) registration was added alongside an existing machine-scope (`HKLM`) registration of the same host name | `effective_registration_changed` + **NBG008** | **PASS** |
| **B** — authorization surface expansion | the host manifest was authorized for one additional extension | `trust_surface_expanded` | **PASS** |
| **C** — same-path binary replacement | the bytes at an unchanged launcher path were replaced | `binary_identity_changed` (no spurious path change) | **PASS** |

Each scenario also produced an **independent browser-side confirmation** that
the effective trust path really changed — the host's reported identity changed
accordingly in Scenarios A and C, and a previously-unauthorized extension began
receiving replies in Scenario B.

## Task Scheduler

| Item | Result |
|---|---|
| Install registers a scheduled task | **PASS** |
| Task action uses a resolved absolute interpreter path and runs `nativebridgeguard monitor` | **PASS** |
| State directory under the expected per-user location | **PASS** |
| Manual run exits successfully and actually invokes the monitor | **PASS** |
| A quiet machine produces no spurious drift across cycles | **PASS** |
| Uninstall removes the task (verified) | **PASS** |

A genuine defect was found here and fixed before release — see CHANGELOG.
This summary records only that the final run passed.

## Cleanup

Every scenario reverted its own changes, and each removal was **verified by
re-reading the configuration**, not assumed from the script's exit status.

## Overall

**ACCEPTANCE: PASS** — 42 automated tests, both validation blocks, end-to-end
Native Messaging, Scenarios A/B/C, Task Scheduler, and verified cleanup.

## Boundaries carried by this acceptance

Passing these checks does **not** imply the claims listed here, and none of
them are made:

- no malware detection or classification,
- no EDR capability,
- no automatic exploitation or compromise detection,
- no enterprise/fleet management,
- no full Windows Effective Access / AuthZ computation — the writable hint is
  a DACL heuristic,
- no real-time monitoring — the monitor is schedule-driven.

See the README's Known Limitations and `SECURITY.md`.
