$ErrorActionPreference='Stop'
$name='SkewerApplicationSmoke'
$script='C:\SkewerDev\skewer-windows-app\application_smoke.ps1'
$log=Join-Path $env:USERPROFILE 'skewer-application-smoke.log'
Remove-Item $log -ErrorAction SilentlyContinue
$action=New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
try {
    Start-ScheduledTask -TaskName $name
    $deadline=(Get-Date).AddSeconds(70)
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
    throw 'Application GUI smoke test timed out'
} finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
