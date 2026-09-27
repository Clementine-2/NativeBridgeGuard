<#
.SYNOPSIS
    Scenario B (cleanup): remove the authorization-surface lab host.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/common.ps1"

Write-Host "== Scenario B: Authorization Surface Expansion (cleanup) =="
Write-Host "Removing the lab host registered under HKCU."
Unregister-LabHost HKCU
Write-Host "Cleanup finished."
