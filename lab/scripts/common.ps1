<#
.SYNOPSIS
    Shared helpers for the NativeBridgeGuard adversarial lab.

.DESCRIPTION
    Internal module dot-sourced by the scenario/setup/cleanup scripts. It keeps
    every lab artifact under the single host name 'com.nativebridgeguard.lab'
    and under a git-ignored lab/runtime directory, so the lab never touches a
    real third-party Native Messaging host.

    Safety constraints enforced here:
    - No registry write outside HKCU/HKLM ...\NativeMessagingHosts\com.nativebridgeguard.lab
    - No silent elevation: Assert-Admin exits with a clear message if HKLM work
      is attempted without administrator rights.
    - Every script prints exactly what it is about to do and what it did.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$LabRoot      = Resolve-Path (Join-Path $PSScriptRoot '..')
$Runtime      = Join-Path $LabRoot 'runtime'
$HostName     = 'com.nativebridgeguard.lab'
$ChromeRoot   = 'Software\Google\Chrome\NativeMessagingHosts'
$CanonicalHost = Join-Path $LabRoot 'native_host\native_host_lab.py'

function Get-LabIsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-LabAdmin {
    if (-not (Get-LabIsAdmin)) {
        Write-Host "This operation writes to HKLM and requires administrator rights." -ForegroundColor Red
        Write-Host "Re-run this script from an ELEVATED PowerShell (Run as Administrator). No changes were made." -ForegroundColor Yellow
        exit 1
    }
}

function New-LabRuntimeDir {
    if (-not (Test-Path $Runtime)) {
        New-Item -ItemType Directory -Path $Runtime | Out-Null
        Write-Host "Created runtime dir: $Runtime"
    }
}

function Ensure-LabHostProgram {
    New-LabRuntimeDir
    $dst = Join-Path $Runtime 'host_lab.py'
    if (-not (Test-Path $dst)) {
        Copy-Item -Path $CanonicalHost -Destination $dst -Force
        Write-Host "Copied lab host program -> $dst"
    }
    # Resolve a concrete Python executable so the launchers do not rely on the
    # browser process PATH having 'python'. The path is quoted to survive spaces.
    $py = Resolve-LabPython
    # Launchers set the role/marker env vars the host reads.
    $a = Join-Path $Runtime 'host_a.bat'
    $b = Join-Path $Runtime 'host_b.bat'
    if (-not (Test-Path $a)) {
        @"
@echo off
set NBG_LAB_ROLE=machine
set NBG_LAB_MARKER=A
"$py" "$dst" %*
"@ | Set-Content -Path $a -Encoding ASCII
        Write-Host "Created launcher: $a (role=machine, marker=A)"
    }
    if (-not (Test-Path $b)) {
        @"
@echo off
set NBG_LAB_ROLE=user
set NBG_LAB_MARKER=B
"$py" "$dst" %*
"@ | Set-Content -Path $b -Encoding ASCII
        Write-Host "Created launcher: $b (role=user, marker=B)"
    }
}

function Write-LabManifest {
    param(
        [Parameter(Mandatory)] [string]   $Path,
        [Parameter(Mandatory)] [string]   $HostBinary,
        [Parameter(Mandatory)] [string[]] $AllowedOrigins
    )
    $obj = [ordered]@{
        name           = $HostName
        description    = "NativeBridgeGuard harmless lab host"
        path           = $HostBinary
        type           = "stdio"
        allowed_origins = $AllowedOrigins
    }
    $json = $obj | ConvertTo-Json -Compress
    # UTF-8 WITHOUT BOM. Set-Content -Encoding UTF8 on Windows PowerShell 5.1
    # emits a BOM, which breaks the Python (utf-8 / json.loads) manifest reader.
    # WriteAllText with UTF8Encoding($false) is stable across PS 5.1 and PS 7.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
    Write-Host "Wrote manifest: $Path"
    Write-Host "  path=$HostBinary"
    Write-Host "  allowed_origins=$($AllowedOrigins -join ', ')"
}

function Register-LabHost {
    param(
        [Parameter(Mandatory)] [ValidateSet('HKCU','HKLM')] [string] $Scope,
        [Parameter(Mandatory)] [string] $ManifestPath
    )
    if ($Scope -eq 'HKLM') { Assert-LabAdmin }
    $hive = if ($Scope -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
    $key  = "$hive\$ChromeRoot\$HostName"
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force | Out-Null
        Write-Host "Created registry key: $key"
    }
    # Set-Item on a registry key writes the key's true default value (the
    # '(default)' entry), matching Chrome Native Messaging semantics directly.
    Set-Item -Path $key -Value $ManifestPath
    Write-Host "Registered lab host [$Scope] -> $ManifestPath"
}

function Unregister-LabHost {
    param(
        [Parameter(Mandatory)] [ValidateSet('HKCU','HKLM')] [string] $Scope
    )
    $hive = if ($Scope -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
    $key  = "$hive\$ChromeRoot\$HostName"
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force
        Write-Host "Removed registry key: $key"
    } else {
        Write-Host "Registry key not present (already clean): $key"
    }
}

function Get-LabHostManifestPath {
    param(
        [Parameter(Mandatory)] [ValidateSet('HKCU','HKLM')] [string] $Scope
    )
    $hive = if ($Scope -eq 'HKLM') { 'HKLM:' } else { 'HKCU:' }
    $key  = "$hive\$ChromeRoot\$HostName"
    if (-not (Test-Path $key)) { return $null }
    $prop = Get-ItemProperty -Path $key -Name '(default)' -ErrorAction SilentlyContinue
    if ($null -eq $prop) { return $null }
    return $prop.'(default)'
}

function Test-LabHostRegistered {
    param(
        [Parameter(Mandatory)] [ValidateSet('HKCU','HKLM')] [string] $Scope
    )
    return ($null -ne (Get-LabHostManifestPath $Scope))
}

function Remove-LabRuntimeDir {
    if (Test-Path $Runtime) {
        Remove-Item -Path $Runtime -Recurse -Force
        Write-Host "Removed runtime dir: $Runtime"
    } else {
        Write-Host "Runtime dir not present (already clean): $Runtime"
    }
}

function Format-LabOrigin {
    param([string] $ExtensionId)
    if ($ExtensionId -notmatch '^chrome-extension://') {
        $ExtensionId = "chrome-extension://$ExtensionId/"
    } elseif (-not $ExtensionId.EndsWith('/')) {
        $ExtensionId = "$ExtensionId/"
    }
    return $ExtensionId
}

function Resolve-LabPython {
    # Resolve a concrete, absolute Python executable so the lab .bat launchers do
    # not depend on the (possibly absent) 'python' on the Chromium host process
    # PATH. Order: project .venv -> 'py' launcher -> 'python' on PATH. Any of
    # these may be absent; if all are missing, fail clearly.
    $venv = Join-Path $LabRoot '.venv\Scripts\python.exe'
    if (Test-Path $venv) {
        return (Resolve-Path $venv).Path
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return $py.Source }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return $python.Source }
    Write-Host "ERROR: No Python interpreter found to drive the lab host." -ForegroundColor Red
    Write-Host "Expected <repo>\.venv\Scripts\python.exe, the 'py' launcher, or 'python' on PATH." -ForegroundColor Yellow
    Write-Host "Install one and re-run the scenario script." -ForegroundColor Yellow
    exit 1
}
