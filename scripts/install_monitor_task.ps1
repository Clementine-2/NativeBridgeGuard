<#
.SYNOPSIS
    Install (or recreate) a Windows Task Scheduler task that runs the
    NativeBridgeGuard monitor on a fixed cadence.

.DESCRIPTION
    NativeBridgeGuard's `monitor` command runs ONE cycle and exits; it is not a
    daemon. This script registers a scheduled task so Windows Task Scheduler
    invokes the monitor repeatedly (default: every 15 minutes).

    Design notes (per project rules):
    - No developer-machine paths are hard-coded. The repository root is derived
      from this script's own location, and the Python interpreter is resolved at
      install time (project .venv first, then the `py` launcher).
    - The monitor state directory defaults to %LOCALAPPDATA%\NativeBridgeGuard.
    - Re-running the script is idempotent: if the task already exists it is
      recreated (with a notice), so it is safe to run after updates.
    - This script does NOT request elevation silently. Creating a per-user
      scheduled task does not require administrator rights; if it fails for
      permission reasons the error is surfaced for the user to handle.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_monitor_task.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Resolve locations without hard-coding machine-specific paths ----------
$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot '..')
$TaskName   = 'NativeBridgeGuard Monitor'
$VenvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'

# Resolve a concrete, absolute Python executable. Prefer the project .venv; if it
# is absent, resolve the `py` launcher's real path. If neither exists, fail
# clearly rather than scheduling a task that cannot run. The scheduled task must
# store an absolute executable path (no bare 'py' that could resolve elsewhere).
if (Test-Path $VenvPython) {
    $Python = (Resolve-Path $VenvPython).Path
} else {
    try {
        $pyCmd = Get-Command py -ErrorAction Stop
        $Python = $pyCmd.Source
    } catch {
        Write-Host "ERROR: No Python interpreter found." -ForegroundColor Red
        Write-Host "Expected the project virtual environment at: $VenvPython" -ForegroundColor Yellow
        Write-Host "or the 'py' launcher on PATH. Install one, then re-run this script." -ForegroundColor Yellow
        exit 1
    }
}

$StateDir   = Join-Path $env:LOCALAPPDATA 'NativeBridgeGuard'

# Quote the state dir so paths with spaces survive.
$ActionArgs = "-m nativebridgeguard monitor --state-dir `"$StateDir`""

# --- Idempotent (re)creation -------------------------------------------------
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Task '$TaskName' already exists - recreating." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Run once now, then repeat every 15 minutes.
$Action   = New-ScheduledTaskAction -Execute $Python -Argument $ActionArgs -WorkingDirectory $RepoRoot
# BUGFIX: -RepetitionDuration ([TimeSpan]::MaxValue) serialises to an XML
# duration (P99999999DT23H59M59S) that Windows Task Scheduler rejects with
# "The task XML contains a value which is incorrectly formatted or out of
# range", so registration silently failed. Use a bounded-but-practical
# repetition window instead (10 years), which Task Scheduler accepts.
$RepetitionDuration = New-TimeSpan -Days 3650
$Trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) `
               -RepetitionInterval  (New-TimeSpan -Minutes 15) `
               -RepetitionDuration $RepetitionDuration
$Settings = New-ScheduledTaskSettingsSet `
               -AllowStartIfOnBatteries `
               -DontStopIfGoingOnBatteries `
               -StartWhenAvailable

# Register explicitly and surface failures. Register-ScheduledTask can emit a
# non-terminating error, which previously let the script print "Installed"
# even though no task was created.
try {
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
        -Settings $Settings `
        -Description "NativeBridgeGuard stateful trust-drift monitor. Runs one cycle per invocation; Task Scheduler repeats it." `
        -ErrorAction Stop | Out-Null
} catch {
    Write-Host "ERROR: failed to register scheduled task '$TaskName'." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Confirm registration actually persisted before claiming success.
$verify = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $verify) {
    Write-Host "ERROR: '$TaskName' not found after registration attempt." -ForegroundColor Red
    exit 1
}

Write-Host "Installed scheduled task '$TaskName'." -ForegroundColor Green
Write-Host "  Python  : $Python"
Write-Host "  Repo    : $RepoRoot"
Write-Host "  State   : $StateDir  (snapshot.json, events.ndjson, alert.md, meta.json)"
Write-Host "  Cadence : every 15 minutes"
Write-Host ""
Write-Host "Verify it runs:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Get-ScheduledTaskInfo -TaskName '$TaskName'"
