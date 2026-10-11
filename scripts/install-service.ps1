#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs hawk-service.exe as a Windows service running as LocalSystem.

.DESCRIPTION
    A Windows service runs in Session 0 as NT AUTHORITY\SYSTEM by default;
    that is exactly the privilege level hawk-service needs in order to call
    WTSQueryUserToken and CreateProcessAsUser to launch hawk-capture into the
    interactive user's session. This script registers the service, sets it to
    start at boot, and starts it now.

    Run it from an elevated PowerShell prompt. hawk-capture.exe must sit next
    to hawk-service.exe (the service looks for it in its own directory).

.PARAMETER BinPath
    Path to hawk-service.exe. Defaults to ..\bin\hawk-service.exe relative to
    this script.

.PARAMETER EnrollCode
    One-time enrollment code from the dashboard (Machines > Add machine),
    e.g. 7K3QD-WX2MP-4HZ8R-QN1CV-B6T2J. Needed the first time, or to re-enroll
    a machine that was removed. The code itself never leaves this machine:
    the relay gets its hash, and the code is what lets this machine check its
    owner's key. The service uses it once, then deletes it. Omit it when reinstalling an already enrolled machine.

.PARAMETER RelayPin
    The relay's TLS key pin, shown in the dashboard next to the enrollment
    code (and in the relay's log at startup). The service then refuses any
    relay whose certificate doesn't carry that key, even one the machine
    would otherwise trust. Pass several (comma-separated) to also accept a
    backup key ahead of a rotation. Omit it to keep the pins already set.
#>
[CmdletBinding()]
param(
    [string]$BinPath,
    [string]$EnrollCode,
    [string[]]$RelayPin
)

$ErrorActionPreference = "Stop"
$ServiceName = "HawkService"

# Worked out here rather than as the parameter's default: Windows
# PowerShell 5.1 can leave $PSScriptRoot empty while binding parameters.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $BinPath) { $BinPath = Join-Path $ScriptDir "..\bin\hawk-service.exe" }
$BinPath = (Resolve-Path $BinPath).Path
if (-not (Test-Path $BinPath)) {
    throw "hawk-service.exe not found at '$BinPath': build the project first."
}
$CapturePath = Join-Path (Split-Path $BinPath) "hawk-capture.exe"
if (-not (Test-Path $CapturePath)) {
    Write-Warning "hawk-capture.exe not found next to the service at '$CapturePath'. Capture will fail to launch until it is there."
}

# Validate everything before touching the installed service, so a typo
# never leaves it removed or stopped.
$pins = @()
if ($RelayPin) {
    $pins = @($RelayPin | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($pin in $pins) {
        # base64 of a 32-byte SHA-256: 44 characters ending in '='.
        if ($pin -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "'$pin' doesn't look like a relay pin" }
    }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' already exists; stopping and removing it first."
    & (Join-Path $ScriptDir "uninstall-service.ps1")
}

# sc.exe is picky: the space after each `name=` is part of the syntax.
# obj= LocalSystem is the default for a service, but we set it explicitly so
# the privilege level this project depends on is visible and not an accident.
Write-Host "Creating service '$ServiceName' -> $BinPath"
sc.exe create $ServiceName binPath= "`"$BinPath`"" start= auto obj= LocalSystem DisplayName= "Hawk Remote Service" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }

sc.exe description $ServiceName "Hawk remote desktop background service." | Out-Null

$DataDir = Join-Path $env:ProgramData "HawkService"
New-Item -ItemType Directory -Force $DataDir | Out-Null

if ($pins.Count -gt 0) {
    Set-Content -Path (Join-Path $DataDir "relay-pins.txt") -Value $pins -Encoding ascii
    Write-Host "Relay key pinned ($($pins.Count) pin(s))."
}

if ($EnrollCode) {
    Set-Content -Path (Join-Path $DataDir "enroll-code.txt") -Value $EnrollCode.Trim() -NoNewline -Encoding ascii
    Write-Host "Enrollment code saved; the service will enroll this machine on its next connect."
}

Write-Host "Starting service '$ServiceName'"
sc.exe start $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed with exit code $LASTEXITCODE" }

Write-Host "Done. Logs: C:\ProgramData\HawkService\hawk-service.log"
Write-Host "Check status with:  sc.exe query $ServiceName"
