param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$Service
)
$ErrorActionPreference='Stop'
$name='SkewerHostPause-'+[Guid]::NewGuid().ToString('N')
$result=Join-Path $env:TEMP ($name+'.json')
$script=Join-Path $PSScriptRoot 'host-pause-gui.ps1'
$arguments="-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Directory `"$Directory`" -Service `"$Service`" -ResultFile `"$result`""
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
try {
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $name
    $until=(Get-Date).AddSeconds(100)
    do {
        if ((Test-Path -LiteralPath $result) -and (Get-ScheduledTask -TaskName $name).State -ne 'Running') {
            $state=Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
            if (!$state.passed) { throw $state.detail }
            Write-Output "PASS: $($state.detail)"
            return
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $until)
    throw 'Interactive host pause test timed out'
} finally {
    Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
