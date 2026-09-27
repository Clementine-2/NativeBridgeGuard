<#
.SYNOPSIS
    Prepare on-disk NativeBridgeGuard lab artifacts.

.DESCRIPTION
    Copies the harmless lab host program and creates the launcher .bat files
    under lab/runtime (git-ignored). No registry keys are written and no
    administrator rights are required. Per-scenario registry registration is
    performed by the scenario_*_apply scripts.

    Pass -ExtensionId to the scenario scripts later so the lab host authorizes
    the lab extension you loaded in Chrome/Edge.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/common.ps1"

Write-Host "== NativeBridgeGuard Lab Setup =="
Write-Host "Preparing harmless on-disk lab artifacts. No registry written; no admin required."
Ensure-LabHostProgram
Write-Host ""
Write-Host "Setup complete."
Write-Host "Run a scenario, e.g.:  powershell -File lab\scripts\scenario_origin_expand_apply.ps1 -ExtensionId <your-extension-id>"
Write-Host "Then:                  nativebridgeguard monitor --state-dir <dir>"
