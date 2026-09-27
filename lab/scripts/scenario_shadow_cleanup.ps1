<#
.SYNOPSIS
    Scenario A (cleanup): remove the shadowing lab hosts.

.DESCRIPTION
    Removes the user-level (HKCU) lab host B and the machine-level (HKLM) lab
    host A created by scenario_shadow_apply.ps1, restoring the pre-scenario
    state. Removing HKLM requires administrator rights; the script exits with a
    clear prompt if not elevated.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/common.ps1"

Write-Host "== Scenario A: User-Level Trust Shadowing (cleanup) =="
Write-Host "Removing lab host B (HKCU) and lab host A (HKLM)."
Assert-LabAdmin
Unregister-LabHost HKCU
Unregister-LabHost HKLM
Write-Host "Cleanup finished. Both Lab registrations removed (HKCU host B and HKLM host A); no effective lab host remains."
