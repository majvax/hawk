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
    e.g. 7K3QD-WX2MP. Needed the first time, or to re-enroll a machine that
    was removed. The service uses it once to get this machine's credential,
    then deletes it. Omit it when reinstalling an already enrolled machine.
#>
[CmdletBinding()]
param(
    [string]$BinPath = (Join-Path $PSScriptRoot "..\bin\hawk-service.exe"),
    [string]$EnrollCode
)

$ErrorActionPreference = "Stop"
$ServiceName = "HawkService"

$BinPath = (Resolve-Path $BinPath).Path
if (-not (Test-Path $BinPath)) {
    throw "hawk-service.exe not found at '$BinPath' — build the project first."
}
$CapturePath = Join-Path (Split-Path $BinPath) "hawk-capture.exe"
if (-not (Test-Path $CapturePath)) {
    Write-Warning "hawk-capture.exe not found next to the service at '$CapturePath'. Capture will fail to launch until it is there."
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' already exists; stopping and removing it first."
    & "$PSScriptRoot\uninstall-service.ps1"
}

# sc.exe is picky: the space after each `name=` is part of the syntax.
# obj= LocalSystem is the default for a service, but we set it explicitly so
# the privilege level this project depends on is visible and not an accident.
Write-Host "Creating service '$ServiceName' -> $BinPath"
sc.exe create $ServiceName binPath= "`"$BinPath`"" start= auto obj= LocalSystem DisplayName= "Hawk Remote Service" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }

sc.exe description $ServiceName "Hawk remote desktop background service." | Out-Null

if ($EnrollCode) {
    $DataDir = Join-Path $env:ProgramData "HawkService"
    New-Item -ItemType Directory -Force $DataDir | Out-Null
    Set-Content -Path (Join-Path $DataDir "enroll-code.txt") -Value $EnrollCode.Trim() -NoNewline -Encoding ascii
    Write-Host "Enrollment code saved; the service will enroll this machine on its next connect."
}

Write-Host "Starting service '$ServiceName'"
sc.exe start $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed with exit code $LASTEXITCODE" }

Write-Host "Done. Logs: C:\ProgramData\HawkService\hawk-service.log"
Write-Host "Check status with:  sc.exe query $ServiceName"
