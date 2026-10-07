#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the HawkService Windows service.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ServiceName = "HawkService"

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Host "Service '$ServiceName' is not installed; nothing to do."
    return
}

Write-Host "Stopping service '$ServiceName'"
sc.exe stop $ServiceName | Out-Null  # fine if it was already stopped

# The SCM marks a service for deletion but only frees the name once every
# handle to it is closed, so poll briefly rather than assuming it is gone.
Write-Host "Deleting service '$ServiceName'"
sc.exe delete $ServiceName | Out-Null

for ($i = 0; $i -lt 10; $i++) {
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "Done."
        return
    }
    Start-Sleep -Milliseconds 300
}
Write-Warning "Service still present after delete; a process may still hold a handle to it (close services.msc, stop hawk-capture.exe)."
