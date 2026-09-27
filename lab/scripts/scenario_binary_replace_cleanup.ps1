<#
.SYNOPSIS
    Scenario C (cleanup): remove the binary-replacement lab host.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/common.ps1"

Write-Host "== Scenario C: Native Host Binary Replacement (cleanup) =="
Write-Host "Removing the lab host registered under HKCU."
Unregister-LabHost HKCU
Write-Host "Cleanup finished (lab_host_c.py remains in runtime until cleanup_lab.ps1 removes it)."
