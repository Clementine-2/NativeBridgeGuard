<#
.SYNOPSIS
    Scenario C (apply): Native host binary replacement via a real launcher.

.DESCRIPTION
    Demonstrates detection of a replaced native host binary. It reuses the
    project's real launcher mechanism (.bat -> python host) so a genuine browser
    can actually launch the lab host:

      - The *shared* host program (lab_host_c.py) is copied once and never
        changes between states; its role/marker come from environment variables.
      - The *launcher* (lab_host_c.bat) is what the manifest points at AND what
        real Chromium executes. Its ONLY difference between baseline and replaced
        states is the NBG_LAB_MARKER env value ("A" vs "B"), so its bytes (and
        therefore its SHA-256) differ while ping/pong semantics are identical.

    Because Chromium launches the manifest `path` directly, the manifest must
    point at the .bat, not the .py. The scanner hashes that same path, so the
    SHA-256 change is observed exactly where the browser would execute it.

    To observe the drift:
      1. .\scenario_binary_replace_apply.ps1 -ExtensionId <id>       # launcher marker A, SHA-256 A
      2. nativebridgeguard monitor --state-dir C:\lab\nbg-state-c   # FIRST monitor: baseline_initialized
      3. .\scenario_binary_replace_apply.ps1 -Replaced -ExtensionId <id>   # launcher marker B, SHA-256 B (same path)
      4. nativebridgeguard monitor --state-dir C:\lab\nbg-state-c   # SECOND monitor: binary_identity_changed (before/after SHA)

    Runs on HKCU, so no administrator rights are required. No real third-party
    program is modified; only lab/runtime files are written.

.EXAMPLE
    powershell -File lab\scripts\scenario_binary_replace_apply.ps1 -ExtensionId <your-extension-id>
#>
[CmdletBinding()]
param(
    [string] $ExtensionId = 'REPLACE_WITH_EXTENSION_ID',
    [switch] $Replaced
)

. "$PSScriptRoot/common.ps1"

Write-Host "== Scenario C: Native Host Binary Replacement (apply) =="
New-LabRuntimeDir

# Resolve a concrete Python executable so the launcher does not depend on the
# browser process PATH having 'python'.
$py = Resolve-LabPython

$ext    = Format-LabOrigin $ExtensionId
$marker = if ($Replaced) { 'B' } else { 'A' }
$hostPy = Join-Path $Runtime 'lab_host_c.py'
$hostBat = Join-Path $Runtime 'lab_host_c.bat'

# Shared host program: marker/role are injected by the launcher via env, so this
# file is identical in both states and is never the thing that changes.
if (-not (Test-Path $hostPy)) {
    Copy-Item -Path $CanonicalHost -Destination $hostPy -Force
    Write-Host "Copied shared lab host program -> $hostPy"
}

# Launcher is both what Chromium executes and what the manifest points at.
# The only state-dependent byte is the MARKER env value, so its SHA-256 differs
# between baseline (A) and replaced (B) at the exact path the browser uses.
$bat = @"
@echo off
set NBG_LAB_ROLE=lab-c
set NBG_LAB_MARKER=$marker
"$py" "$hostPy" %*
"@
Set-Content -Path $hostBat -Value $bat -Encoding ASCII
Write-Host "Wrote launcher: $hostBat (marker=$marker)"

$man = Join-Path $Runtime 'manifest_binary.json'
Write-LabManifest -Path $man -HostBinary $hostBat -AllowedOrigins @($ext)
Register-LabHost HKCU $man

Write-Host ""
if ($Replaced) {
    Write-Host "Applied REPLACED state (marker B). The scanner should report 'binary_identity_changed' with before/after SHA256 at the same path."
} else {
    Write-Host "Applied BASELINE state (marker A). Run again with -Replaced to swap the launcher's marker bytes and observe binary_identity_changed."
}
Write-Host "Run 'scenario_binary_replace_cleanup.ps1' to remove the lab host."
