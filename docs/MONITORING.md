# NativeBridgeGuard Monitoring

NativeBridgeGuard v0.1.5 adds a **stateful trust-drift monitor**. This page
explains what it is, how to install it as a scheduled task, where its data
lives, and how to verify or remove it.

## Audit vs. Monitor (recap)

- **Audit** (`scan` / `diff`) is a point-in-time or on-demand comparison you run
  yourself. It answers "what is the effective trust state *now*, and how did it
  change *between these two snapshots*?".
- **Monitor** (`monitor`) is a repeatable *cycle* that remembers the last state
  for you. Each invocation scans once, diffs against the previous state, and
  emits machine-readable events for anything that changed. Task Scheduler runs
  it on a schedule.

The monitor is **not** a daemon and **not** a Windows Service. It performs one
cycle and exits; Windows Task Scheduler owns the cadence.

## How a monitor cycle works

1. If no previous snapshot exists in the state directory, the current scan is
   saved as the baseline. The cycle prints `baseline_initialized` and emits no
   drift events.
2. If a previous snapshot exists, `semantic_diff(previous, current)` is computed.
   - Any change becomes a stable `Event` appended to `events.ndjson`.
   - A human-readable `alert.md` is (re)written summarising new events.
   - The cycle prints `drift_detected` with `new_events=N`.
   - If nothing changed, it prints `no_drift` and writes no duplicate events.
3. The current snapshot **replaces** the previous one, becoming the next
   baseline.

**Drift-duplication guard.** Because the current state always becomes the next
baseline, a one-time change is reported exactly once. A stable environment
produces zero new events on subsequent runs — it will never alarm forever over
the same drift.

## State location

Default: `%LOCALAPPDATA%\NativeBridgeGuard`

Override with `--state-dir <dir>`. Contents:

| File | Purpose |
|------|---------|
| `snapshot.json` | Latest scan; also the baseline for the next cycle. |
| `events.ndjson` | Append-only machine-readable event log (one JSON object per line). |
| `alert.md` | Human-readable summary of the most recent cycle's new events. |
| `meta.json` | Cycle bookkeeping (`initialized_at`, `last_run`, `last_event_count`). |

`events.ndjson` is the authoritative machine interface. Do **not** parse the
Markdown for automation.

## Event schema

Every line of `events.ndjson` is a JSON object:

```json
{
  "schema_version": 1,
  "timestamp": "2026-09-26T10:38:44.041437+00:00",
  "event_type": "trust_surface_expanded",
  "severity": "medium",
  "trust_key": "edge:com.example.bridge",
  "summary": "Native host authorization expanded to additional extension IDs.",
  "before": null,
  "after": null,
  "evidence": ["added_extension_ids=['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']"]
}
```

`event_type` values mirror the semantic-diff signals (`trust_path_added`,
`trust_path_removed`, `effective_registration_changed`, `trust_surface_expanded`,
`trust_surface_reduced`, `binary_path_changed`, `binary_identity_changed`,
`binary_signature_changed`, `policy_effect_changed`) plus the temporal
correlation `compound_trust_boundary_expansion` (NBG102).

## Manual run

```powershell
# One cycle against the default state dir
nativebridgeguard monitor

# Explicit state dir + custom outputs
nativebridgeguard monitor --state-dir C:\lab\nbg-state --events events.ndjson --alert-report alert.md
```

First run prints `baseline_initialized`; later runs print `drift_detected` or
`no_drift`.

## Install as a scheduled task

From a Windows PowerShell prompt **in the project directory**:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_monitor_task.ps1
```

This:

- Derives the repository root from the script location (no hard-coded paths).
- Resolves the Python interpreter: project `.venv\Scripts\python.exe` if present,
  otherwise the `py` launcher.
- Creates a scheduled task **NativeBridgeGuard Monitor** that runs
  `python -m nativebridgeguard monitor --state-dir "%LOCALAPPDATA%\NativeBridgeGuard"`
  every **15 minutes**.
- Is idempotent: re-running recreates the task (prints a notice).

Creating a per-user scheduled task does **not** require administrator rights,
and the script never requests elevation silently. If registration fails for
permission reasons, the error is surfaced for you to resolve.

### Verify

```powershell
Start-ScheduledTask -TaskName 'NativeBridgeGuard Monitor'
Get-ScheduledTaskInfo -TaskName 'NativeBridgeGuard Monitor'
# Confirm events appeared:
Get-Content "$env:LOCALAPPDATA\NativeBridgeGuard\events.ndjson"
```

### Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File scripts\uninstall_monitor_task.ps1
```

This removes **only** the `NativeBridgeGuard Monitor` task. It does **not**
delete your other scheduled tasks, and it does **not** delete the state
directory, so historical events remain available for review.
