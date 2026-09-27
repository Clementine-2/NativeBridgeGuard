<#
.SYNOPSIS
    Scenario A (apply): User-level trust shadowing, two-phase.

.DESCRIPTION
    Demonstrates effective-registry resolution and trust drift in two distinct
    phases so a real HKLM -> HKCU transition can be observed and measured:

      Phase 1 (-Baseline, requires elevation):
        Establishes the MACHINE-level (HKLM) lab host A only, and removes any
        pre-existing user-level (HKCU) shadow so HKLM is authoritative.
        Effective host = HKLM (machine, host A, role=machine).

      Phase 2 (default, HKCU only, no admin needed):
        Requires the HKLM baseline to already exist (errors otherwise), then
        registers the USER-level (HKCU) lab host B which shadows it. It never
        touches HKLM, so the machine baseline is preserved.
        Because the resolver prefers HKCU over HKLM for the same host name, the
        effective host becomes the user-level host B (role=user).

    NativeBridgeGuard should report NBG008 in phase 2, and the monitor should
    emit an 'effective_registration_changed' drift event comparing phase 1 to
    phase 2.

    Writing HKLM requires administrator rights; the baseline phase exits with a
    clear prompt if not elevated (no silent elevation, no bypass).

.EXAMPLE
    # Phase 1 (elevated): machine baseline only
    powershell -File lab\scripts\scenario_shadow_apply.ps1 -Baseline -ExtensionId <id>
    # Phase 2 (normal): user shadow
    powershell -File lab\scripts\scenario_shadow_apply.ps1 -ExtensionId <id>
#>
[CmdletBinding(DefaultParameterSetName='Shadow')]
param(
    [string] $ExtensionId = 'REPLACE_WITH_EXTENSION_ID',
    [switch] $Baseline
)

. "$PSScriptRoot/common.ps1"

$ext   = Format-LabOrigin $ExtensionId
$manA  = Join-Path $Runtime 'manifest_a.json'
$manB  = Join-Path $Runtime 'manifest_b.json'
$hostA = Join-Path $Runtime 'host_a.bat'
$hostB = Join-Path $Runtime 'host_b.bat'

if ($Baseline) {
    Write-Host "== Scenario A (Phase 1 / Baseline): machine-level (HKLM) lab host A =="
    Assert-LabAdmin
    Ensure-LabHostProgram

    Write-LabManifest -Path $manA -HostBinary $hostA -AllowedOrigins @($ext)

    # Guarantee HKLM is authoritative: drop any pre-existing user shadow first.
    if (Test-LabHostRegistered HKCU) {
        Unregister-LabHost HKCU
        Write-Host "Removed pre-existing HKCU shadow so HKLM baseline is authoritative."
    }

    Register-LabHost HKLM $manA

    Write-Host ""
    Write-Host "Baseline applied. Effective host is HKLM (machine, host A, role=machine)."
    Write-Host "NativeBridgeGuard monitor baseline scan -> no drift expected."
    Write-Host "Next: run AGAIN WITHOUT -Baseline (no elevation needed) to apply the user shadow (role=user)."
} else {
    Write-Host "== Scenario A (Phase 2 / Shadow): user-level (HKCU) lab host B shadows HKLM host A =="
    # Shadow phase writes only HKCU, so elevation is not required. But it must
    # build on a real machine baseline; refuse to shadow a host that does not
    # exist at HKLM.
    $hklmMan = Get-LabHostManifestPath HKLM
    if (-not $hklmMan) {
        Write-Host "ERROR: HKLM baseline not found. Run this script with -Baseline first (elevated)." -ForegroundColor Red
        Write-Host "No changes were made." -ForegroundColor Yellow
        exit 1
    }

    Ensure-LabHostProgram
    Write-LabManifest -Path $manB -HostBinary $hostB -AllowedOrigins @($ext)

    # HKLM is left untouched -> the machine baseline is preserved.
    Register-LabHost HKCU $manB

    Write-Host ""
    Write-Host "Shadow applied. HKCU now shadows HKLM for the same host name, so the effective host is HKCU (user, host B, role=user). HKLM baseline preserved."
    Write-Host "NativeBridgeGuard should report NBG008; the monitor should emit 'effective_registration_changed'."
    Write-Host "Run 'scenario_shadow_cleanup.ps1' (elevated) to restore both."
}
