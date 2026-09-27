<#
.SYNOPSIS
    Remove the NativeBridgeGuard Monitor scheduled task.

.DESCRIPTION
    Deletes ONLY the 'NativeBridgeGuard Monitor' scheduled task created by
    install_monitor_task.ps1. It does NOT touch any other scheduled tasks and
    does NOT delete the monitor state directory (%LOCALAPPDATA%\NativeBridgeGuard),
    so historical events.ndjson / alert.md are preserved for review.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\uninstall_monitor_task.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$TaskName = 'NativeBridgeGuard Monitor'

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Task '$TaskName' is not installed. Nothing to do." -ForegroundColor Yellow
    exit 0
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
Write-Host "Note: state files in $env:LOCALAPPDATA\NativeBridgeGuard were NOT deleted."
