#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Runs an executable once as NT AUTHORITY\SYSTEM via a throwaway scheduled task.

.DESCRIPTION
    Useful for reproducing what hawk-service sees at runtime without installing
    it as a service — e.g. launching hawk-service.exe under SYSTEM to inspect
    its log, or testing CreateProcessAsUser behaviour from a SYSTEM context.

    Note: hawk-service.exe itself expects to be started by the Service Control
    Manager (it calls StartServiceCtrlDispatcher), so for the real service use
    install-service.ps1. This helper is for ad-hoc SYSTEM-context debugging.

.PARAMETER Exe
    Path to the executable to run.

.PARAMETER Arguments
    Arguments string passed to the executable.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$Arguments = ""
)

$ErrorActionPreference = "Stop"
$Exe = (Resolve-Path $Exe).Path
$TaskName = "HawkRunAsSystem_$([guid]::NewGuid().ToString('N'))"

try {
    $action = New-ScheduledTaskAction -Execute $Exe -Argument $Arguments -WorkingDirectory (Split-Path $Exe)
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal | Out-Null

    Write-Host "Running '$Exe $Arguments' as SYSTEM..."
    Start-ScheduledTask -TaskName $TaskName

    # Wait for it to leave the "running" state, so one-shot tools finish.
    do {
        Start-Sleep -Milliseconds 400
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
    } while ($info.LastTaskResult -eq 267009)  # SCHED_S_TASK_RUNNING

    Write-Host "Exit code: $($info.LastTaskResult)"
}
finally {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
