<#
.SYNOPSIS
    Remove all NativeBridgeGuard lab artifacts.

.DESCRIPTION
    Removes the lab registry keys (HKCU and, if removable, HKLM) and the
    git-ignored lab/runtime directory, restoring the machine to its pre-lab
    state. HKCU removal needs no admin; HKLM removal needs administrator rights
    and will surface a clear message if denied (no silent elevation).
#>
[CmdletBinding()]
param()

. "$PSScriptRoot/common.ps1"

Write-Host "== NativeBridgeGuard Lab Cleanup =="
Write-Host "Removing lab registry keys (HKCU + HKLM) and the runtime directory."

Unregister-LabHost HKCU

try {
    Unregister-LabHost HKLM
} catch {
    Write-Host "Could not remove the HKLM lab key (access denied). Re-run this script ELEVATED to remove it." -ForegroundColor Yellow
}

Remove-LabRuntimeDir

Write-Host "Cleanup finished."
