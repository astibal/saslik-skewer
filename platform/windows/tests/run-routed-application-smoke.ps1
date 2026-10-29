param(
    [string]$Directory='C:\SkewerDev\skewer-windows-app',
    [string]$FixtureDirectory=$Directory
)
$ErrorActionPreference='Stop'
$name='SkewerRoutedApplicationSmoke'
$script=Join-Path $FixtureDirectory 'routed-application-smoke.ps1'
$arguments="-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Directory `"$Directory`""
$log=Join-Path $env:USERPROFILE 'skewer-routed-application-smoke.log'
Remove-Item $log -ErrorAction SilentlyContinue
$action=New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument $arguments
$principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
try {
    Start-ScheduledTask -TaskName $name
    $deadline=(Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $log) {
            $text=Get-Content $log -Raw
            if ($text -match 'Exit: [01]') {
                Write-Output $text
                if ($text -match 'Exit: 1') { exit 1 }
                exit 0
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'Routed GUI smoke test timed out'
} finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
