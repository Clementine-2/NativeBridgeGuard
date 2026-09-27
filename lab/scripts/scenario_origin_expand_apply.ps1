<#
.SYNOPSIS
    Scenario B (apply): Authorization surface expansion.

.DESCRIPTION
    Demonstrates native-host authorization expansion. Registers a user-level
    (HKCU) lab host whose manifest authorizes one extension in baseline mode and
    an additional extension in expanded mode.

    To observe the drift:
      1. .\scenario_origin_expand_apply.ps1 -Baseline -ExtensionId <idA> -AddExtensionId <idB>   # host authorizes Extension A only
      2. nativebridgeguard monitor --state-dir C:\lab\nbg-state-b   # FIRST monitor: baseline_initialized
      3. .\scenario_origin_expand_apply.ps1 -ExtensionId <idA> -AddExtensionId <idB>   # now also authorizes Extension B
      4. nativebridgeguard monitor --state-dir C:\lab\nbg-state-b   # SECOND monitor: trust_surface_expanded (added_extension_ids = B)

    Runs on HKCU, so no administrator rights are required.

.EXAMPLE
    powershell -File lab\scripts\scenario_origin_expand_apply.ps1 -ExtensionId <idA> -AddExtensionId <idB>
#>
[CmdletBinding()]
param(
    [string] $ExtensionId     = 'REPLACE_WITH_EXTENSION_ID',
    [string] $AddExtensionId  = 'REPLACE_WITH_EXTENSION_ID_B',
    [switch] $Baseline
)

. "$PSScriptRoot/common.ps1"

Write-Host "== Scenario B: Authorization Surface Expansion (apply) =="
Ensure-LabHostProgram

$extA = Format-LabOrigin $ExtensionId
$extB = Format-LabOrigin $AddExtensionId
$hostB = Join-Path $Runtime 'host_b.bat'
$man   = Join-Path $Runtime 'manifest_origin.json'

if ($Baseline) {
    Write-Host "Baseline mode: lab host authorizes Extension A only."
    Write-LabManifest -Path $man -HostBinary $hostB -AllowedOrigins @($extA)
} else {
    Write-Host "Expanded mode: lab host authorizes Extension A + Extension B."
    Write-LabManifest -Path $man -HostBinary $hostB -AllowedOrigins @($extA, $extB)
}

Register-LabHost HKCU $man

Write-Host ""
Write-Host "Applied. Re-run the monitor to see 'trust_surface_expanded' (added_extension_ids lists Extension B)."
Write-Host "Run 'scenario_origin_expand_cleanup.ps1' to remove the lab host."
