# NativeBridgeGuard v0.1.5

## 1. One-line definition

A small Windows security engineering tool that reconstructs the **effective
trust path** between Chromium browser extensions and Native Messaging hosts, and
detects **trust drift** in that path over time as a stateful monitor.

NativeBridgeGuard correlates browser extension metadata, enterprise browser
policy, `NativeMessagingHosts` registry registrations, host manifests,
`allowed_origins`, and local binary trust evidence (path, SHA-256,
Authenticode, owner/ACL hints). It compares snapshots by *meaning* rather than
by raw field equality, and reports stable, machine-readable drift events.

It is **validated on real Windows + a real Chromium browser lab** (see
§9). It is not a product, not a service, and not an enterprise platform.

---

## Scope

NativeBridgeGuard is an **audit and trust-drift monitoring** tool. It answers
"what is the effective Native Messaging trust path right now, and how did it
change since the last snapshot?".

It is explicitly **not**:

- an **EDR**,
- a **malware detector**,
- an **automatic exploitation / compromise detector**,
- an **enterprise browser security platform**.

It does not evaluate exploitability, does not decide whether a binary is
malicious, and does not prove that an intrusion occurred. A finding is a
statement about *configured trust relationships and locally collected
evidence*, which a human must interpret. See §7 (rule / correlation boundary),
§10 (known limitations), and `SECURITY.md`.

**Supported surface:** live collection targets Chrome and Edge on Windows.
`report` and `diff` operate on snapshot files and are therefore
platform-independent; `scan` and `monitor` perform live collection and are
Windows-only.

---

## 2. Threat / problem

Chromium Native Messaging lets an extension launch and converse with a local
native binary. That is a legitimate and widely used capability — and it is also
a trust relationship that is easy to alter quietly.

The problem is that the trust relationship is **scattered**:

- the extension's `nativeMessaging` permission,
- browser enterprise policy,
- the registry registration the browser actually resolves,
- the host manifest's `path` and `allowed_origins`,
- and the integrity and provenance of the binary on disk.

No single one of these is alarming. *Combinations* are: for example, a
user-scope registration pointing at a user-writable, unsigned binary is a trust
path that any unprivileged process can rewrite, and the next time the extension
calls it, the extension is talking to different code.

The specific threat this tool addresses is **silent trust-path substitution**:
the host name, the manifest path, and the extension all stay the same, but the
*effective* registration, the authorized extension set, or the bytes behind the
binary change underneath you. Those changes produce no browser warning. They
are visible only if someone reconstructs and re-reconstructs the effective path.

NativeBridgeGuard makes that path explicit and makes changes to it observable.

---

## 3. Architecture

```text
Chrome / Edge
     │
     ├─ Extension manifests + nativeMessaging permission
     ├─ Enterprise Native Messaging policy
     │
     ▼
Effective Registry Resolution       (resolver.py)
     │
     ▼
Host Manifest ── allowed_origins ──► Extension IDs   (manifest.py)
     │
     ▼
Native Binary                                        (windows_evidence.py)
     ├─ path
     ├─ SHA-256
     ├─ Authenticode
     └─ owner / ACL / writable hint
     │
     ▼
Trust Graph + Findings                               (scanner.py, rules.py)
     │
     ├─ Snapshot  ─────────────►  report / markdown
     └─ Semantic Diff ─────────►  events.ndjson + alert.md
                                  (diffing.py, events.py, monitor.py)
```

**Commands**

| Command | Purpose |
|---|---|
| `scan` | Collect a point-in-time snapshot. Windows-only for live collection. |
| `report` | Render a snapshot as Markdown. Cross-platform. |
| `diff` | Compare two snapshots; emit semantic drift events. Cross-platform. |
| `monitor` | Run **one** cycle against remembered state; emit new events. |

---

## 4. Effective Trust Path

For one host name, several registrations can exist simultaneously — per browser
family, per registry scope (`HKCU` / `HKLM`), per registry view. The browser
resolves exactly **one** of them using vendor-defined precedence (for example,
`HKCU` wins over `HKLM` for the same host name).

The **Effective Trust Path** is that winning registration, followed through:

```text
registry registration → host manifest → allowed_origins → extension IDs → native binary
                                                                          (path, SHA-256, Authenticode, owner/ACL)
```

Resolution tables are explicit in `resolver.py` so they can be reviewed against
current vendor documentation, rather than being implicit in code.

Two consequences that matter in practice:

- **Shadowing.** Adding a user-scope registration can silently override a
  machine-scope one. Nothing is deleted; the effective path simply changes.
  This is rule **NBG008** and event `effective_registration_changed`.
- **Cross-family visibility.** A registration may appear under more than one
  browser family because the resolver for one family consults another's
  registration keys. A host authorized for an extension installed in only one
  browser can therefore legitimately show as "authorized but not installed" in
  the other.

---

## 5. Audit vs. Monitor

| | Audit (`scan` / `diff`) | Monitor (`monitor`) |
|---|---|---|
| Who runs it | You, on demand | Task Scheduler, repeatedly |
| State | You manage the snapshot files | Remembered in a state directory |
| Answers | "What is the effective state now, and how did it change between these two snapshots?" | "What changed since the last cycle?" |
| Process model | One-shot | **One cycle per invocation, then exits** |

The monitor is **not** a daemon, **not** a Windows Service, and **not** a
real-time watcher. It is a one-shot command that Windows Task Scheduler invokes
on a schedule; it detects drift *between* cycles, never within one.

State directory (default `%LOCALAPPDATA%\NativeBridgeGuard`) contains
`snapshot.json`, `events.ndjson`, `alert.md`, and `meta.json`.

---

## 6. Semantic Drift

`diff` and `monitor` compare snapshots by **meaning**, not by raw field
equality, and emit stable event names with before/after evidence:

| Event | Meaning |
|---|---|
| `effective_registration_changed` | The registration the browser resolves changed (e.g. `HKLM` → `HKCU`). |
| `trust_path_added` / `trust_path_removed` | A host appeared or disappeared. |
| `trust_surface_expanded` / `_reduced` | `allowed_origins` gained or lost an extension ID. |
| `binary_path_changed` | The manifest now points at a different path. |
| `binary_identity_changed` | Same path, different bytes (SHA-256 changed). |
| `authenticode_changed` | Signer or signature status changed. |
| `browser_policy_changed` | Enterprise policy altered the effective state. |
| `compound_trust_boundary_expansion` (NBG102) | Effective registration changed **and** surface expanded in the same cycle. |

The machine-readable form is one JSON object per line in `events.ndjson`. The
Markdown `alert.md` is a presentation layer only; automation should read the
NDJSON.

Note the deliberate separation of `binary_path_changed` from
`binary_identity_changed`: a replacement that keeps the same path must still be
reported, and must be reported as an *identity* change rather than a *path*
change.

---

## 7. Rule / correlation boundary

**Static rules** (`rules.py`) evaluate a single snapshot and describe the state
of one trust path. They raise findings such as:

- Missing or unreadable effective host manifest.
- Machine-level registration pointing into a user-profile path.
- Missing native host binary.
- Binary without a valid Authenticode signature (provenance signal).
- Current-user write-access **heuristic** on the binary or its parent.
- `allowed_origins` referencing extension IDs that are not installed.
- User-level registration shadowing a machine-level one (**NBG008**).
- Host relationship blocked by browser enterprise policy.

**Correlation findings** span more than one trust path or more than one point in
time, and are implemented in the diff/monitor layer, not as static rules:

- **NBG101 — user-controlled native host trust path (compound):** effective
  registration is `HKCU`, the binary is under the user profile, the current user
  can write/replace it (ACL heuristic), and it is not validly
  Authenticode-signed.
- **NBG102 — compound trust-boundary expansion (temporal):** emitted when
  `effective_registration_changed` and `trust_surface_expanded` occur for the
  same trust path in the same cycle.

A finding is **high-attention compound evidence, never a malware verdict and
never proof of exploitation**. High-attention combinations are meant to be
manually verified.

---

## 8. Harmless validation lab

`lab/` contains an intentionally harmless validation lab: a test extension sends
a JSON `ping`, and a local Python host returns `pong`. There is no command
execution, credential access, persistence, remote target access, or exploit
logic anywhere in it.

It uses only the host name `com.nativebridgeguard.lab` and never modifies real
third-party hosts. Steps that write `HKLM` require elevation, and the scripts
never request elevation silently.

Three repeatable scenarios:

| Scenario | Change | Expected detection |
|---|---|---|
| **A** — user-level trust shadowing | `HKCU` registration shadows an existing `HKLM` registration | `effective_registration_changed` + **NBG008** |
| **B** — authorization surface expansion | host manifest gains a second authorized extension ID | `trust_surface_expanded` |
| **C** — same-path binary replacement | bytes replaced at an unchanged launcher path | `binary_identity_changed` (no path change) |

Scenario A also produces browser-level proof: the host reports
`role=machine` before the shadow and `role=user` after, independently
confirming which registration the browser resolved.

See `docs/ADVERSARIAL_VALIDATION.md`, `docs/MONITORING.md`, and the sanitized
records in `docs/evidence/`.

---

## 9. Real Windows validation

Validated on **Windows with Chrome and Edge installed**, as a non-administrator
user. This section lists only what was actually executed and observed.

**Automated:** 42 unit tests passing.

**Real Windows:**

- [x] Live scan completes with `collection_errors: 0` and a populated snapshot.
- [x] Locally loaded (unpacked) extensions discovered from real browser state.
- [x] Native Messaging ping/pong round trip through a registered lab host.
- [x] Scenario A — `HKLM` → `HKCU` effective registration switch detected
      (`effective_registration_changed` + NBG008), confirmed in-browser.
- [x] Scenario B — `trust_surface_expanded` detected, confirmed in-browser
      (previously-unauthorized extension begins receiving replies).
- [x] Scenario C — same-path `binary_identity_changed` detected with
      before/after SHA-256, confirmed in-browser.
- [x] Cleanup verified for every scenario (registry re-read, not assumed).
- [x] Task Scheduler: install → manual run (exit `0`, state written, no spurious
      drift) → uninstall, with removal verified.

Evidence: `docs/evidence/acceptance_summary.md` (sanitized), plus per-scenario
records `scenario_a.md`, `scenario_b.md`, `scenario_c.md`, and
`debugging_cases.md`.

Two real defects were found by this validation and fixed — see
`debugging_cases.md`:

1. `os.access`-based writable detection produced false positives on Windows and
   was replaced with a DACL-parsing heuristic (still a heuristic — see §10).
2. The unpacked-extension collector read only `Preferences`; current browsers
   store those settings in `Secure Preferences`, so the collector silently
   returned nothing despite green unit tests.

---

## 10. Known limitations

- **Windows + Chrome/Edge only** for live collection. `diff`, `report`, and the
  event/monitor logic are cross-platform; `scan` is not.
- **ACL writable hint is a heuristic, not Effective Access.** It parses DACL
  text for the current user and broad principals and honours `Deny` precedence,
  but it does **not** resolve group membership, privileges, inheritance,
  `CREATOR OWNER`, or owner rights, and does **not** call the Windows AuthZ
  effective-access API. A "not writable" result is not proof the path is safe.
  This is the single most important limitation to understand before relying on
  NBG006/NBG101.
- **Not real-time.** The monitor is schedule-driven (Task Scheduler) and detects
  drift between cycles. A change made and reverted inside one interval can be
  missed entirely.
- **No malware detection, no EDR function.** No signature scanning, no YARA, no
  reputation lookup, no behavioural analysis, no network or process
  interception, no AI risk scoring, and no automatic remediation.
- **Not "enterprise ready".** There is no central management, fleet reporting,
  agent distribution, or multi-host aggregation. It is a single-machine
  engineering tool.
- **Extension discovery** focuses on `Default` and `Profile *` user profiles.
- **Browser internals dependency.** Extension/preference discovery reads
  on-disk Chromium state, which is an undocumented internal and can change
  between browser versions (this already happened once — see §9, defect 2).
- **`collection_errors` records collector failures** so "no findings" is never
  confused with "collection failed", but recovery is left to the operator.
- **Registry lookup rules can evolve**; resolver tables are explicit in
  `resolver.py` for review, not assumed permanent.

---

## 11. Installation & Quick start

Requires Windows 10/11 and Python 3.11+. There are no third-party runtime
dependencies.

### Installation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Verify the entrypoint:

```powershell
nativebridgeguard --help
```

### CLI overview

| Command | Purpose | Live collection? |
|---|---|---|
| `scan` | Collect a point-in-time snapshot | Yes — Windows only |
| `report` | Render a snapshot JSON as Markdown | No — works on any platform |
| `diff` | Compare two snapshots, emit semantic drift | No — works on any platform |
| `monitor` | Run one drift-detection cycle, then exit | Yes — Windows only |

### Quick start

```powershell
# Point-in-time audit
nativebridgeguard scan --output baseline.json --report baseline.md
```

Render Markdown from an existing snapshot without re-scanning:

```powershell
nativebridgeguard report baseline.json --output baseline.md
```

After a legitimate install, upgrade, or configuration change:

```powershell
nativebridgeguard scan --output current.json --report current.md
nativebridgeguard diff baseline.json current.json --output drift.md
```

Machine-readable diff instead of Markdown:

```powershell
nativebridgeguard diff baseline.json current.json --json --output drift.json
```

Stateful monitoring:

```powershell
# One cycle. The first run initialises a baseline and emits no drift.
nativebridgeguard monitor --state-dir C:\lab\nbg-state

# Or let Task Scheduler repeat the cycle (default 15 minutes):
powershell -ExecutionPolicy Bypass -File scripts\install_monitor_task.ps1
powershell -ExecutionPolicy Bypass -File scripts\uninstall_monitor_task.ps1

# Read machine-readable events:
Get-Content "$env:LOCALAPPDATA\NativeBridgeGuard\events.ndjson"
```

`diff` / `report` work on any platform; live `scan` is Windows-only.

See `docs/MONITORING.md` for the monitor's state machine and
`docs/ADVERSARIAL_VALIDATION.md` for running the lab.

---

## Privacy / Evidence handling

**A scan of your machine describes your machine.** Treat output as sensitive.

A NativeBridgeGuard snapshot contains locally collected trust evidence:
registry keys, absolute filesystem paths, binary SHA-256 hashes, Authenticode
signers, owner strings, DACL text, installed extension IDs, and browser policy
state. On a real machine that can identify installed software, local account
names, and parts of your directory layout.

Practical rules:

- **Do not paste raw `scan` output into public issues.** A snapshot is
  endpoint evidence, not a bug report. Reproduce the issue against the
  sanitized files in `examples/`, or attach a redacted excerpt.
- **Do not commit snapshots.** The default ignore rules exclude common local
  snapshot/report filenames and the monitor state directory. Review before
  committing anything ending in `.ndjson` or resembling a scan dump.
- **Monitor state is per-user by default** (`%LOCALAPPDATA%\NativeBridgeGuard`)
  and contains `events.ndjson` / `alert.md` describing changes on that host.
  It is intentionally never removed by uninstall — review or delete it
  yourself.
- **Findings need interpretation.** See §7 and §10: a finding describes
  configured trust relationships, not intent, malware, or exploitation.

See `SECURITY.md` for how to report a real issue without exposing endpoint
data.

---

## Tests

```bash
py -m unittest discover -s tests -v
py -m nativebridgeguard diff examples/before.json examples/after.json
```

## Repo layout

| Path | Purpose |
|---|---|
| `nativebridgeguard/` | Scanner, resolver, rules, diffing, events, monitor, CLI |
| `lab/` | Harmless ping/pong validation lab (extensions, hosts, scripts) |
| `scripts/` | Task Scheduler install / uninstall |
| `docs/` | Monitoring, adversarial validation, acceptance, evidence |
| `examples/` | Sanitized example snapshots for `diff` |

## Roadmap

Candidate directions, deliberately **not** started. None of these are implied
capabilities of v0.1:

- Real Windows effective-access computation (AuthZ) to replace the ACL
  heuristic.
- A real-time registry/file watcher that recomputes only affected trust paths.
- Browser policy precedence diagnostics.
- DOT/Mermaid export for larger trust graphs.
- Signed-baseline format.

## License

MIT — see [`LICENSE`](LICENSE).

Validation records summarizing what was actually verified are available in
[`ACCEPTANCE_SUMMARY.md`](ACCEPTANCE_SUMMARY.md) and [`docs/evidence/`](docs/evidence/).
