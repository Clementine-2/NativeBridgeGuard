# Changelog

All notable changes to this project are recorded here. This file starts at
v0.1.5, the first released version; earlier development history is not
reconstructed here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v0.1.5]

### Added

- **Stateful trust-drift monitor** (`monitor`): runs one cycle per invocation,
  diffs against the remembered previous state, writes `events.ndjson` /
  `alert.md` / `meta.json`, and exits. Not a daemon and not a Windows Service.
- **Semantic trust-drift events**: `effective_registration_changed`,
  `binary_path_changed`, `binary_identity_changed`, `trust_surface_expanded` /
  `_reduced`, `trust_path_added` / `_removed`, `authenticode_changed`,
  `browser_policy_changed`.
- **Compound correlation**: NBG101 (user-controlled native host trust path,
  static compound) and NBG102 (compound trust-boundary expansion, emitted when
  a registration switch and surface expansion coincide in one cycle).
- **Windows Task Scheduler integration** via `scripts/install_monitor_task.ps1`
  and `scripts/uninstall_monitor_task.ps1`.
- **Harmless adversarial validation lab** (`lab/`): three repeatable scenarios
  proving effective-registry shadowing, authorization-surface expansion, and
  same-path binary replacement end-to-end through a real browser.
- **NBG008**: detects a user-scope (`HKCU`) registration shadowing a
  machine-scope (`HKLM`) registration of the same host name.

### Changed

- **Load-unpacked extension collection hardened.** The collector previously
  read only `Preferences`; current Chrome/Edge keep those extension settings in
  `Secure Preferences`, so locally loaded extensions were silently missed on
  real machines. Both sources are now read, `Secure Preferences` takes
  precedence, and each source is isolated so one corrupt file cannot blank the
  collector.
- **ACL writable hint hardened (NBG006).** The previous check used
  `os.access(path, os.W_OK)`, which is not a Windows ACL judgement and produced
  false positives on protected OS locations. Replaced with a DACL-parsing
  heuristic that considers the current user and broad unprivileged principals,
  honours `Deny` precedence, and also inspects the parent directory. Still a
  heuristic — see Known Limitations in the README.

### Fixed

- Scheduled-task installer used an out-of-range repetition duration
  (`[TimeSpan]::MaxValue`), so `Register-ScheduledTask` failed and no task was
  created while the script still printed success. Now uses a bounded duration,
  surfaces registration errors, and verifies the task exists before reporting
  success.

### Validated

Verified on real Windows with Chrome and Edge installed (non-administrator
account): live scan with no collection errors, unpacked-extension discovery,
Native Messaging ping/pong, and Scenarios A/B/C each detected and confirmed
in-browser. 42 unit tests. Details in `ACCEPTANCE_SUMMARY.md` and
`docs/evidence/`.
