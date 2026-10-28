param([string]$Endpoint='skewer://172.30.1.73:8766/pair')
$ErrorActionPreference='Stop'
$name='SkewerCaTrustSmoke'
$script='C:\SkewerDev\skewer-windows-app\ca-trust-smoke.ps1'
$log=Join-Path $env:USERPROFILE 'skewer-ca-trust-smoke.log'
Remove-Item $log -ErrorAction SilentlyContinue
$registry='HKCU:\Software\Saslik\Skewer\windows'
$old=(Get-ItemProperty $registry -Name saslikEndpoint -ErrorAction SilentlyContinue).saslikEndpoint
New-Item $registry -Force | Out-Null
Set-ItemProperty $registry -Name saslikEndpoint -Value $Endpoint
Stop-Process -Name skewer -Force -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName SkewerDevelopmentDesktop -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName SkewerDevelopmentDesktop
Start-Sleep -Seconds 2
$action=New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
try {
    Start-ScheduledTask -TaskName $name
    $deadline=(Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $log) {
            $text=Get-Content $log -Raw
            if ($text -match 'Exit: [01]') {
                Write-Output $text
                if ($text -match 'Exit: 1') { exit 1 }
                exit 0
            }
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'CA Trust smoke test timed out'
} finally {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    if ($null -eq $old) { Remove-ItemProperty $registry -Name saslikEndpoint -ErrorAction SilentlyContinue }
    else { Set-ItemProperty $registry -Name saslikEndpoint -Value $old }
}
